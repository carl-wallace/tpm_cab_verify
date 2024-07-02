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
    PDVCertificate, PkiEnvironment,
};
use const_oid::db::rfc5912::ID_SHA_256;
use log::error;

impl CabVerifyParts {
    /// Verify the timestamp in the SignedData message from the CAB file and validate the signer's certificate.
    /// Timestamp verification does not consider the attribute certificates that may be present and
    /// does not evaluate the time value from the timestamp against any reference point. It simply
    /// verifies the signature on the timestamp, validates the signer's certificate and affirms the digest
    /// included in the timestamp matches the expected value.
    pub(crate) async fn verify_timestamp(
        &self,
        authenticode: &AuthenticodeSignature,
        signature: &[u8],
        pe: &mut PkiEnvironment,
        cps: &CertificationPathSettings,
    ) -> Result<()> {
        let signer_info = authenticode.signer_info();
        let unsigned_attrs = match &signer_info.unsigned_attrs {
            Some(unsigned_attrs) => unsigned_attrs,
            None => {
                error!("The SignedData object did not include UnsignedAttributes");
                return Err(Error::MissingValue);
            }
        };

        let timestamp_oid = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");

        let timestamp_attr = unsigned_attrs.iter().find(|a| a.oid == timestamp_oid);
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
            &signer_cert.tbs_certificate.subject_public_key_info,
        )?;

        let msft_roots = get_msft_roots()?;
        pe.add_trust_anchor_source(Box::new(msft_roots));

        let mut cert_source = CertSource::default();
        for cert in certs {
            if cert != signer_cert {
                let name = cert.tbs_certificate.subject.to_string();
                let cf = CertFile {
                    filename: name,
                    bytes: cert.to_der()?,
                };
                cert_source.push(cf);
            }
        }
        let _ = cert_source.initialize(cps);
        cert_source.find_all_partial_paths(pe, cps);

        pe.add_certificate_source(Box::new(cert_source));

        let signer_cert_pdv = PDVCertificate::try_from(signer_cert.to_der()?.as_slice())?;

        let mut paths = vec![];
        pe.get_paths_for_target(&signer_cert_pdv, &mut paths, 0, cps.get_time_of_interest())?;

        for mut path in paths {
            let mut cpr = CertificationPathResults::new();
            if pe.validate_path(pe, cps, &mut path, &mut cpr).is_ok() {
                return Ok(());
            }
        }

        Err(Error::SignerCertNotValidated)
    }
}

/// Searches for a given certificate in a vector of certificates extracted from a timestamp, i.e.,
/// the list minus any attribute certificates.
fn get_signer_cert_vec(sid: &SignerIdentifier, certs: &Vec<Certificate>) -> Option<Certificate> {
    for cert in certs {
        match sid {
            SignerIdentifier::SubjectKeyIdentifier(skid) => {
                if skid_match(skid.0.as_bytes(), cert) {
                    return Some(cert.clone());
                }
            }
            SignerIdentifier::IssuerAndSerialNumber(iasn) => {
                if cert.tbs_certificate.serial_number == iasn.serial_number
                    && cert.tbs_certificate.issuer == iasn.issuer
                {
                    return Some(cert.clone());
                }
            }
        }
    }
    None
}
