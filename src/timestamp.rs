//! Verifies the timestamp on a CAB file and the certificate of the timestamp signer

use authenticode::AuthenticodeSignature;

use cms::{attr::SigningTime, content_info::ContentInfo, signed_data::SignerIdentifier};
use const_oid::ObjectIdentifier;
use x509_cert::{
    attr::Attributes,
    der::{Decode, Encode},
    ext::pkix::{name::GeneralName, ExtendedKeyUsage},
    Certificate,
};

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::signer::{check_message_digest, skid_match};
use crate::{
    asn1::{IssuerSerial, SignedData2, SigningCertificateV2, TstInfo2},
    roots::get_msft_roots,
    CabVerifyParts, Error, Result,
};
use certval::{
    CertFile, CertSource, CertVector, CertificationPathResults, CertificationPathSettings,
    PDVCertificate, PkiEnvironment, TimeOfInterest,
};
use const_oid::db::rfc3161::ID_CT_TST_INFO;
use const_oid::db::rfc5280::{ID_CE_EXT_KEY_USAGE, ID_KP_TIME_STAMPING};
use const_oid::db::rfc5911::{
    ID_AA_SIGNING_CERTIFICATE_V_2, ID_CONTENT_TYPE, ID_SIGNED_DATA, ID_SIGNING_TIME,
};
use const_oid::db::rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512};
use der::{asn1::BitString, Tag, Tagged};
use log::{error, warn};
use x509_tsp::TspVersion;

/// Allowance for clock skew between the timestamping authority and the verifying host when
/// affirming that a timestamp does not claim a time in the future.
const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// A signingTime signed attribute differing from genTime by more than this is logged. RFC 3161 does
/// not require the attribute and its absence is not an error, so this is advisory only: a genuine TSA
/// sets the two within moments of each other, whereas a signing oracle stamps the current time into
/// signingTime while genTime is attacker-chosen.
const SIGNING_TIME_SKEW_WARN_SECS: i64 = 86400;

pub const TIMESTAMP_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");

impl CabVerifyParts {
    /// Verify the timestamp in the SignedData message from the CAB file and validate the signer's certificate.
    /// Timestamp verification does not consider the attribute certificates that may be present. It
    /// verifies the signature on the timestamp, affirms the digest included in the timestamp matches
    /// the expected value, and validates the timestamp signer's certificate at the genTime asserted
    /// in the timestamp (timestamping certificates are short-lived, so validating at the current
    /// time would cause verification to fail soon after a CAB file is published).
    ///
    /// Returns the genTime from the timestamp for use as the time of interest when validating the
    /// CAB signer's certificate.
    pub(crate) async fn verify_timestamp(
        &self,
        authenticode: &AuthenticodeSignature,
        signature: &[u8],
        pe: &mut PkiEnvironment,
        cps: &CertificationPathSettings,
    ) -> Result<TimeOfInterest> {
        let signer_info = authenticode.signer_info();
        let unsigned_attrs = match &signer_info.unsigned_attrs {
            Some(unsigned_attrs) => unsigned_attrs,
            None => {
                error!("The SignedData object did not include UnsignedAttributes");
                return Err(Error::MissingValue);
            }
        };

        let timestamp_attr = unsigned_attrs.iter().find(|a| a.oid == TIMESTAMP_OID);
        let timestamp = match timestamp_attr {
            Some(attr) => {
                if let Some(val) = attr.values.get(0) {
                    val.to_der()?
                } else {
                    error!("Timestamp attribute had no values");
                    return Err(Error::MissingValue);
                }
            }
            None => {
                error!("Timestamp attribute not found");
                return Err(Error::MissingValue);
            }
        };

        let ci = ContentInfo::from_der(&timestamp)?;
        if ci.content_type != ID_SIGNED_DATA {
            error!("Content type was not ID_SIGNED_DATA");
            return Err(Error::UnexpectedValue);
        }
        let sd_bytes = ci.content.to_der()?;
        let sd = SignedData2::from_der(&sd_bytes)?;
        if sd.encap_content_info.econtent_type != ID_CT_TST_INFO {
            error!("The timestamp eContentType was not id-ct-TSTInfo");
            return Err(Error::UnexpectedValue);
        }
        let ec = match sd.encap_content_info.econtent {
            Some(ec) => ec,
            None => {
                error!("SignedData did not feature encapsulated content.");
                return Err(Error::MissingValue);
            }
        };

        if signer_info.digest_alg.oid != ID_SHA_256 {
            error!("SHA256 is the only digest algorithm supported at present");
            return Err(Error::NotSupported);
        }

        let encap_content = ec.value().to_vec();
        let encap_digest = Sha256::digest(&encap_content);

        let timestamp_token = TstInfo2::from_der(&encap_content)?;

        if timestamp_token.version != TspVersion::V1 {
            error!("The TSTInfo version was not 1");
            return Err(Error::UnexpectedValue);
        }

        // todo - support other digest algorithms
        if timestamp_token.message_imprint.hash_algorithm.oid != ID_SHA_256 {
            error!("SHA256 is the only messageImprint hash algorithm supported at present");
            return Err(Error::NotSupported);
        }
        let sig_hash = Sha256::digest(signature);
        if timestamp_token.message_imprint.hashed_message.as_bytes() != sig_hash.as_slice() {
            error!("The timestamp digest did not match the calculated digest of the signer's signature");
            return Err(Error::DigestMismatch);
        }

        let gen_time = parse_gen_time(&timestamp_token.gen_time)?;

        // A genuine timestamp is always in the past. Reject tokens claiming a future time so a
        // forger cannot post-date a signature. If the system clock cannot be read this fails
        // closed (now_secs of 0 causes any genTime to be rejected).
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if gen_time.as_unix_secs() > now_secs + MAX_CLOCK_SKEW_SECS {
            error!(
                "The genTime in the timestamp ({gen_time}) is in the future; refusing to use it"
            );
            return Err(Error::TimestampInFuture);
        }

        let signer_info = match sd.signer_infos.0.get(0) {
            Some(si) => si,
            None => {
                error!("The SignedData object did not include any SignerInfos");
                return Err(Error::MissingValue);
            }
        };
        let signed_attrs = match &signer_info.signed_attrs {
            Some(sa) => sa,
            None => {
                error!("The SignedData object did not include SignedAttributes");
                return Err(Error::MissingValue);
            }
        };

        if signer_info.digest_alg.oid != ID_SHA_256 {
            error!("SHA256 is the only TSA digest algorithm supported at present");
            return Err(Error::NotSupported);
        }

        check_message_digest(encap_digest.as_slice(), signed_attrs)?;
        check_content_type(signed_attrs)?;
        warn_on_signing_time_skew(signed_attrs, &gen_time);

        let enc_signed_attrs = signed_attrs.to_der()?;
        let signature = signer_info.signature.as_bytes();

        let pile = match sd.certificates {
            Some(pile) => pile,
            None => {
                error!("The SignedData object did not include certificates");
                return Err(Error::MissingValue);
            }
        };

        // this is necessary because the TrustedTmp.cab file includes v1 attribute certificates which
        // are marked as obsolete by the CMS RFC and are not supported by the cms crate;
        let mut certs = vec![];
        for item in pile.0.iter() {
            match item.to_der() {
                Ok(d) => {
                    if let Ok(c) = Certificate::from_der(&d) {
                        certs.push(c);
                    }
                }
                Err(_e) => {}
            }
        }

        let signer_cert = match get_signer_cert_vec(&signer_info.sid, &certs) {
            Some(signer_cert) => signer_cert,
            None => {
                error!("Failed to find signer's certificate in SignedData");
                return Err(Error::SignerCertNotFound);
            }
        };

        pe.verify_signature_message(
            pe,
            &enc_signed_attrs,
            &BitString::from_bytes(signature)?,
            &signer_info.signature_algorithm,
            signer_cert.tbs_certificate().subject_public_key_info(),
        )?;

        check_timestamping_eku(&signer_cert)?;
        check_signing_certificate(signed_attrs, &signer_cert)?;

        // Validate the timestamp signer's certificate at the time the timestamp was produced,
        // requiring the id-kp-timeStamping EKU on the signer's certificate. Enabling
        // PS_EXTENDED_KEY_USAGE_PATH also enforces the EKU intersection across the whole path,
        // so an intermediate that omits timeStamping narrows the usage as RFC 5280 intends.
        let mut cps = cps.clone();
        cps.set_time_of_interest(gen_time);
        cps.set_extended_key_usage(vec![ID_KP_TIME_STAMPING.to_string()]);
        cps.set_extended_key_usage_path(true);

        let msft_roots = get_msft_roots()?;
        pe.add_trust_anchor_source(Box::new(msft_roots));

        let mut cert_source = CertSource::default();
        for cert in certs {
            if cert != signer_cert {
                let name = cert.tbs_certificate().subject().to_string();
                let cf = CertFile {
                    filename: name,
                    bytes: cert.to_der()?,
                };
                cert_source.push(cf);
            }
        }
        if let Err(e) = cert_source.initialize(&cps) {
            error!("Failed to initialize cert source: {}", e);
            return Err(Error::Certval(e));
        }
        cert_source.find_all_partial_paths(pe, &cps);

        pe.add_certificate_source(Box::new(cert_source));

        let signer_cert_pdv = PDVCertificate::try_from(signer_cert.to_der()?.as_slice())?;

        let mut paths = vec![];
        pe.get_paths_for_target(&signer_cert_pdv, &mut paths, 0, cps.get_time_of_interest())?;

        for path in paths {
            let mut cpr = CertificationPathResults::new();
            if pe.validate_path(pe, &cps, &path, &mut cpr).is_ok() {
                return Ok(gen_time);
            }
        }

        Err(Error::SignerCertNotValidated)
    }
}

/// Parse the genTime from a TSTInfo into a `TimeOfInterest`. The field is decoded as an `Any`
/// because observed timestamps include fractional seconds, which strict GeneralizedTime decoding
/// rejects (see `TstInfo2`). Fractional seconds are truncated.
fn parse_gen_time(gen_time: &der::Any) -> Result<TimeOfInterest> {
    if gen_time.tag() != Tag::GeneralizedTime {
        error!("genTime was not encoded as a GeneralizedTime");
        return Err(Error::UnexpectedValue);
    }
    let s = core::str::from_utf8(gen_time.value()).map_err(|_| Error::ParseError)?;
    let t = s.strip_suffix('Z').ok_or_else(|| {
        error!("genTime value {s} did not end in Z");
        Error::ParseError
    })?;
    let t = t.split('.').next().unwrap_or_default();
    if t.len() != 14 || !t.bytes().all(|b| b.is_ascii_digit()) {
        error!("genTime value {s} was not in YYYYMMDDHHMMSS[.fff]Z format");
        return Err(Error::ParseError);
    }
    let num = |r: core::ops::Range<usize>| t[r].parse::<u16>().map_err(|_| Error::ParseError);
    let dt = der::DateTime::new(
        num(0..4)?,
        num(4..6)? as u8,
        num(6..8)? as u8,
        num(8..10)? as u8,
        num(10..12)? as u8,
        num(12..14)? as u8,
    )?;
    Ok(TimeOfInterest(dt))
}

/// Searches for a given certificate in a vector of certificates extracted from a timestamp, i.e.,
/// the list minus any attribute certificates.
fn get_signer_cert_vec(sid: &SignerIdentifier, certs: &[Certificate]) -> Option<Certificate> {
    for cert in certs {
        match sid {
            SignerIdentifier::SubjectKeyIdentifier(skid) => {
                if skid_match(skid.0.as_bytes(), cert) {
                    return Some(cert.clone());
                }
            }
            SignerIdentifier::IssuerAndSerialNumber(iasn) => {
                if cert.tbs_certificate().serial_number() == &iasn.serial_number
                    && cert.tbs_certificate().issuer() == &iasn.issuer
                {
                    return Some(cert.clone());
                }
            }
        }
    }
    None
}

/// Affirms the signed `contentType` attribute is present and names id-ct-TSTInfo. RFC 5652 §11.1
/// requires this attribute to match the eContentType; a token whose signed contentType is `id-data`,
/// or missing, indicates the signature was produced over something other than a TSTInfo.
fn check_content_type(signed_attrs: &Attributes) -> Result<()> {
    let attr = signed_attrs
        .iter()
        .find(|a| a.oid == ID_CONTENT_TYPE)
        .ok_or_else(|| {
            error!("The timestamp had no contentType signed attribute");
            Error::MissingValue
        })?;
    let val = attr.values.get(0).ok_or_else(|| {
        error!("The contentType attribute had no values");
        Error::MissingValue
    })?;
    let oid = ObjectIdentifier::from_der(&val.to_der()?)?;
    if oid != ID_CT_TST_INFO {
        error!("The signed contentType attribute was not id-ct-TSTInfo");
        return Err(Error::UnexpectedValue);
    }
    Ok(())
}

/// Logs when a present signingTime signed attribute diverges from genTime by more than
/// [`SIGNING_TIME_SKEW_WARN_SECS`]. The attribute is optional under RFC 3161, so its absence or a
/// decode failure is ignored; this never affects the verification result.
fn warn_on_signing_time_skew(signed_attrs: &Attributes, gen_time: &TimeOfInterest) {
    let Some(attr) = signed_attrs.iter().find(|a| a.oid == ID_SIGNING_TIME) else {
        return;
    };
    let Some(val) = attr.values.get(0) else {
        return;
    };
    let Ok(der) = val.to_der() else {
        return;
    };
    let Ok(signing_time) = SigningTime::from_der(&der) else {
        return;
    };
    let signing_secs = signing_time.to_unix_duration().as_secs() as i64;
    let gen_secs = gen_time.as_unix_secs() as i64;
    let diff = (signing_secs - gen_secs).abs();
    if diff > SIGNING_TIME_SKEW_WARN_SECS {
        warn!(
            "signingTime and genTime differ by {diff} seconds; a genuine TSA sets them together, so \
             a large gap can indicate a timestamp produced through a signing oracle"
        );
    }
}

/// Affirms the signer certificate carries exactly one extended key usage, id-kp-timeStamping.
///
/// RFC 3161 §2.3 additionally requires the extension to be critical, but Microsoft's own
/// timestamping certificates (e.g. the 2021 TrustedTpm.cab material) mark it non-critical, so
/// criticality is not enforced: the sole-purpose EKU is the property that matters, and requiring
/// critical would refuse the genuine certificates this crate exists to verify.
fn check_timestamping_eku(signer_cert: &Certificate) -> Result<()> {
    let exts = signer_cert.tbs_certificate().extensions().ok_or_else(|| {
        error!("The TSA signer certificate had no extensions");
        Error::MissingValue
    })?;
    let eku_ext = exts
        .iter()
        .find(|e| e.extn_id == ID_CE_EXT_KEY_USAGE)
        .ok_or_else(|| {
            error!("The TSA signer certificate had no extended key usage extension");
            Error::MissingValue
        })?;
    let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())?;
    if eku.0.len() != 1 || eku.0[0] != ID_KP_TIME_STAMPING {
        error!("The TSA signer certificate extended key usage was not solely id-kp-timeStamping");
        return Err(Error::UnexpectedValue);
    }
    Ok(())
}

/// Affirms a SigningCertificateV2 signed attribute is present and that its first certificate hash
/// matches the signer certificate, binding the TSA certificate into the signed content as RFC 3161
/// §2.4.1 requires. The Microsoft TrustedTpm.cab timestamps carry SigningCertificateV2; the
/// superseded RFC 2634 SigningCertificate (v1, SHA-1) is not accepted.
fn check_signing_certificate(signed_attrs: &Attributes, signer_cert: &Certificate) -> Result<()> {
    let cert_der = signer_cert.to_der()?;

    if let Some(attr) = signed_attrs
        .iter()
        .find(|a| a.oid == ID_AA_SIGNING_CERTIFICATE_V_2)
    {
        let val = attr.values.get(0).ok_or_else(|| {
            error!("The signingCertificateV2 attribute had no values");
            Error::MissingValue
        })?;
        let sc = SigningCertificateV2::from_der(&val.to_der()?)?;
        let first = sc.certs.first().ok_or_else(|| {
            error!("The signingCertificateV2 attribute listed no certificates");
            Error::MissingValue
        })?;
        let oid = first
            .hash_algorithm
            .as_ref()
            .map(|a| a.oid)
            .unwrap_or(ID_SHA_256);
        let expected = hash_cert(oid, &cert_der)?;
        if first.cert_hash.as_bytes() != expected.as_slice() {
            error!("The signingCertificateV2 certHash did not match the signer certificate");
            return Err(Error::DigestMismatch);
        }
        return check_issuer_serial(first.issuer_serial.as_ref(), signer_cert);
    }

    error!("The timestamp had no signingCertificateV2 attribute");
    Err(Error::MissingValue)
}

/// Compares an optional ESSCertID issuerSerial against the signer certificate. When present, both
/// the serial number and an issuer directoryName must match.
fn check_issuer_serial(
    issuer_serial: Option<&IssuerSerial>,
    signer_cert: &Certificate,
) -> Result<()> {
    let Some(issuer_serial) = issuer_serial else {
        return Ok(());
    };
    if issuer_serial.serial_number != *signer_cert.tbs_certificate().serial_number() {
        error!("The ESSCertID issuerSerial serial number did not match the signer certificate");
        return Err(Error::UnexpectedValue);
    }
    let issuer = signer_cert.tbs_certificate().issuer();
    let issuer_matches = issuer_serial
        .issuer
        .iter()
        .any(|gn| matches!(gn, GeneralName::DirectoryName(name) if name == issuer));
    if !issuer_matches {
        error!("The ESSCertID issuerSerial issuer did not match the signer certificate");
        return Err(Error::UnexpectedValue);
    }
    Ok(())
}

/// Computes the hash of a certificate under the named ESSCertIDv2 algorithm for comparison against
/// the attribute's certHash. SHA-256 is the default, SHA-384 and SHA-512 are the other commonly
/// specified choices.
fn hash_cert(oid: ObjectIdentifier, cert_der: &[u8]) -> Result<Vec<u8>> {
    if oid == ID_SHA_256 {
        Ok(Sha256::digest(cert_der).to_vec())
    } else if oid == ID_SHA_384 {
        Ok(Sha384::digest(cert_der).to_vec())
    } else if oid == ID_SHA_512 {
        Ok(Sha512::digest(cert_der).to_vec())
    } else {
        error!("Unsupported certHash algorithm {oid} in a signingCertificateV2 attribute");
        Err(Error::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use der::Any;

    fn gen_time_any(s: &str) -> Any {
        Any::new(Tag::GeneralizedTime, s.as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn parse_gen_time_with_fractional_seconds() {
        // As observed in TrustedTpm.cab timestamps (mis-encoded per DER, hence the Any handling)
        let toi = parse_gen_time(&gen_time_any("20240614203756.847Z")).unwrap();
        assert_eq!(1718397476, toi.as_unix_secs());
    }

    #[test]
    fn parse_gen_time_without_fractional_seconds() {
        let toi = parse_gen_time(&gen_time_any("20240614203756Z")).unwrap();
        assert_eq!(1718397476, toi.as_unix_secs());
    }

    #[test]
    fn parse_gen_time_rejects_bad_values() {
        assert!(parse_gen_time(&gen_time_any("20240614203756")).is_err()); // no Z
        assert!(parse_gen_time(&gen_time_any("2024061420375Z")).is_err()); // too short
        assert!(parse_gen_time(&gen_time_any("2024061420375xZ")).is_err()); // non-digit
        assert!(parse_gen_time(&gen_time_any("20241314203756Z")).is_err()); // month 13
        let utc = Any::new(Tag::UtcTime, b"240614203756Z".to_vec()).unwrap();
        assert!(parse_gen_time(&utc).is_err()); // wrong tag
    }
}
