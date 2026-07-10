//! Verifies the timestamp on a CAB file and the certificate of the timestamp signer

use authenticode::AuthenticodeSignature;

use cms::{content_info::ContentInfo, signed_data::SignerIdentifier};
use const_oid::{db::rfc5911::ID_SIGNED_DATA, ObjectIdentifier};
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

use sha2::{Digest, Sha256};

use crate::signer::{check_message_digest, skid_match};
use crate::{
    asn1::{SignedData2, TstInfo2},
    roots::get_msft_roots,
    CabVerifyParts, Error, Result,
};
use certval::{
    CertFile, CertSource, CertVector, CertificationPathResults, CertificationPathSettings,
    PDVCertificate, PkiEnvironment, TimeOfInterest,
};
use const_oid::db::rfc5280::ID_KP_TIME_STAMPING;
use const_oid::db::rfc5912::ID_SHA_256;
use der::{Tag, Tagged};
use log::error;

/// Allowance for clock skew between the timestamping authority and the verifying host when
/// affirming that a timestamp does not claim a time in the future.
const MAX_CLOCK_SKEW_SECS: u64 = 300;

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

        // todo - support other digest algorithms
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

        check_message_digest(encap_digest.as_slice(), signed_attrs)?;

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
            signature,
            &signer_info.signature_algorithm,
            signer_cert.tbs_certificate().subject_public_key_info(),
        )?;

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

        for mut path in paths {
            let mut cpr = CertificationPathResults::new();
            if pe.validate_path(pe, &cps, &mut path, &mut cpr).is_ok() {
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

#[cfg(test)]
mod tests {
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
