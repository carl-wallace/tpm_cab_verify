//! Verifies the signature on a CAB file and the certificate of the CAB file signer

use authenticode::AuthenticodeSignature;

use cms::attr::MessageDigest;
use const_oid::db::{
    rfc5911::ID_MESSAGE_DIGEST,
    rfc5912::{ID_SHA_256, SHA_256_WITH_RSA_ENCRYPTION},
};
use x509_cert::{
    der::{Decode, Encode},
    spki::AlgorithmIdentifierOwned,
    Certificate,
};

use sha2::{Digest, Sha256};

use crate::{roots::get_msft_roots, CabVerifyParts, Error, Result};
use certval::{
    CertFile, CertSource, CertVector, CertificationPathResults, CertificationPathSettings,
    PDVCertificate, PkiEnvironment,
};
use cms::signed_data::SignerIdentifier;
use const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER;
use const_oid::db::rfc5912::RSA_ENCRYPTION;
use log::error;
use x509_cert::attr::Attributes;

impl CabVerifyParts {
    /// Verify the signature in the SignedData message from the CAB file and validate the signer's certificate
    pub(crate) fn verify_signer(
        &self,
        authenticode: &AuthenticodeSignature,
        pe: &mut PkiEnvironment,
        cps: &CertificationPathSettings,
    ) -> Result<Vec<u8>> {
        let signer_info = authenticode.signer_info();

        // Hash the encapsulated content. There's not much in the way of documentation to inform this.
        // and it leans on very old PKCS #7 definitions (not CMS). The value in the message digest
        // attribute of the observed TrustedTpm.cab files is calculated over the inner SEQUENCE of the
        // encapsulated content.
        let encapsulated_content = match authenticode.encapsulated_content() {
            Some(encap_content) => encap_content,
            None => {
                error!("SignedData did not feature encapsulated content.");
                return Err(Error::ParseError);
            }
        };

        if signer_info.digest_alg.oid != ID_SHA_256 {
            error!("SHA256 is the only digest algorithm supported at present");
            return Err(Error::NotSupported);
        }

        // todo - support other digest algorithms
        let digest_indirect = Sha256::digest(encapsulated_content);
        let signed_attrs = match &signer_info.signed_attrs {
            Some(signed_attrs) => signed_attrs,
            None => {
                error!("The SignedData object did not include SignedAttributes");
                return Err(Error::MissingValue);
            }
        };

        check_message_digest(digest_indirect.as_slice(), signed_attrs)?;

        let mut certs = authenticode.certificates();
        let signer_cert = match get_signer_cert(&signer_info.sid, &mut certs) {
            Some(signer_cert) => signer_cert,
            None => {
                error!("Failed to find signer's certificate in SignedData");
                return Err(Error::SignerCertNotFound);
            }
        };
        let enc_signed_attrs = signed_attrs.to_der()?;

        let signature = authenticode.signature();

        // At least some of the TrustedTpm.cab files use RSA_ENCRYPTION as a signature algorithm, Fix
        // that before attempting verification.
        let sig_alg = if RSA_ENCRYPTION == signer_info.signature_algorithm.oid {
            // todo - support other digest algorithms
            if signer_info.digest_alg.oid == ID_SHA_256 {
                AlgorithmIdentifierOwned {
                    oid: SHA_256_WITH_RSA_ENCRYPTION,
                    parameters: signer_info.signature_algorithm.parameters.clone(),
                }
            } else {
                return Err(Error::NotSupported);
            }
        } else {
            signer_info.signature_algorithm.clone()
        };

        pe.verify_signature_message(
            pe,
            &enc_signed_attrs,
            signature,
            &sig_alg,
            &signer_cert.tbs_certificate.subject_public_key_info,
        )?;

        let msft_roots = get_msft_roots()?;
        pe.add_trust_anchor_source(Box::new(msft_roots));

        let mut cert_source = CertSource::default();
        for cert in certs {
            if cert != signer_cert {
                let cf = CertFile {
                    filename: "".to_string(),
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
                return Ok(signer_info.signature.clone().into_bytes());
            }
        }
        Err(Error::SignerCertNotValidated)
    }
}

/// Compare a SKID value with the value from the SKID extention in the certificate, if any
pub(crate) fn skid_match(skid: &[u8], cert: &Certificate) -> bool {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        if let Some(skid_ext) = exts
            .iter()
            .find(|a| a.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)
        {
            return skid == skid_ext.extn_value.as_bytes();
        }
    }
    false
}

/// Compares a given digest value with the value extracted from an ID_MESSAGE_DIGEST instance in the
/// set of attributes, if any.
pub(crate) fn check_message_digest(expected: &[u8], signed_attrs: &Attributes) -> Result<()> {
    let md_attr = signed_attrs.iter().find(|a| a.oid == ID_MESSAGE_DIGEST);
    match md_attr {
        Some(attr) => {
            if let Some(val) = attr.values.get(0) {
                let md_attr = MessageDigest::from_der(&val.to_der()?)?;
                if md_attr.as_bytes() != expected {
                    Err(Error::DigestMismatch)
                } else {
                    Ok(())
                }
            } else {
                error!("MessageDigest attribute had no values");
                Err(Error::MissingValue)
            }
        }
        None => {
            error!("MessageDigest attribute not found");
            Err(Error::MissingValue)
        }
    }
}

/// Searches for a given certificate in a list returned from an authenticode signature object.
fn get_signer_cert<'a>(
    sid: &SignerIdentifier,
    certs: &mut impl Iterator<Item = &'a Certificate>,
) -> Option<&'a Certificate> {
    for cert in certs {
        match sid {
            SignerIdentifier::SubjectKeyIdentifier(skid) => {
                if skid_match(skid.0.as_bytes(), cert) {
                    return Some(cert);
                }
            }
            SignerIdentifier::IssuerAndSerialNumber(iasn) => {
                if cert.tbs_certificate.serial_number == iasn.serial_number
                    && cert.tbs_certificate.issuer == iasn.issuer
                {
                    return Some(cert);
                }
            }
        }
    }
    None
}
