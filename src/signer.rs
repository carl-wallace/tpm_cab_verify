use authenticode::AuthenticodeSignature;

use cms::{
    attr::MessageDigest
};
use const_oid::{
    db::{
        rfc5911::ID_MESSAGE_DIGEST, rfc5912::{
            SHA_256_WITH_RSA_ENCRYPTION, ID_SHA_256
        }
    },
};
use x509_cert::{Certificate, der::{
    Decode, Encode,
}, spki::AlgorithmIdentifierOwned};

use sha2::{Digest, Sha256};

use certval::Error::ParseError;
use certval::{
    CertFile, CertSource, CertVector, CertificationPathResults,
    CertificationPathSettings, Error, PDVCertificate, PkiEnvironment,
};
use cms::signed_data::SignerIdentifier;
use const_oid::db::rfc5912::RSA_ENCRYPTION;
use crate::CabVerifyParts;
use crate::roots::get_msft_roots;

impl CabVerifyParts {
    pub(crate) fn verify_signer(&self, authenticode: &AuthenticodeSignature, cps: &CertificationPathSettings) -> certval::Result<Vec<u8>> {
        let signer_info = authenticode.signer_info();

        // Hash the encapsulated content. There's not much in the way of documentation to inform this.
        // and it leans on very old PKCS #7 definitions (not CMS). The value in the message digest
        // attribute of the observed TrustedTpm.cab files is calculated over the inner SEQUENCE of the
        // encapsulated content.
        let encapsulated_content = authenticode.encapsulated_content().unwrap();

        if signer_info.digest_alg.oid != ID_SHA_256 {
            return Err(Error::ParseError);
        }

        // todo - support other digest algorithms
        let digest_indirect = Sha256::digest(encapsulated_content);
        let signed_attrs = match &signer_info.signed_attrs {
            Some(signed_attrs) => signed_attrs,
            None => {
                return Err(Error::ParseError);
            }
        };

        let md_attr = signed_attrs.iter().find(|a| a.oid == ID_MESSAGE_DIGEST);
        match md_attr {
            Some(attr) => {
                if let Some(val) = attr.values.get(0) {
                    let md_attr = MessageDigest::from_der(&val.to_der()?)?;
                    if md_attr.as_bytes() != digest_indirect.as_slice() {
                        return Err(Error::ParseError);
                    }
                } else {
                    return Err(Error::ParseError);
                }
            }
            None => return Err(Error::ParseError),
        };

        let mut certs = authenticode.certificates();
        let signer_cert = get_signer_cert(&signer_info.sid, &mut certs);
        let enc_signed_attrs = signed_attrs.to_der()?;

        let signature = authenticode.signature();

        // At least some of the TrustedTpm.cab files use RSA_ENCRYPTION as a signature algorithm, Fix
        // that before attempting verification.
        let sig_alg = if RSA_ENCRYPTION == signer_info.signature_algorithm.oid {
                if signer_info.digest_alg.oid == ID_SHA_256 {
                    AlgorithmIdentifierOwned {
                        oid: SHA_256_WITH_RSA_ENCRYPTION,
                        parameters: signer_info.signature_algorithm.parameters.clone(),
                    }
                } else {
                    // todo support more algs
                    return Err(Error::ParseError);
                }
            }
            else {
                signer_info.signature_algorithm.clone()
            };

        let mut pe = PkiEnvironment::new();
        pe.populate_5280_pki_environment();
        pe.verify_signature_message(
            &pe,
            &enc_signed_attrs,
            signature,
            &sig_alg,
            &signer_cert.unwrap().tbs_certificate.subject_public_key_info,
        )?;

        let msft_roots = get_msft_roots()?;
        pe.add_trust_anchor_source(Box::new(msft_roots));

        let mut cert_source = CertSource::default();
        for cert in certs {
            if cert != signer_cert.unwrap() {
                let cf = CertFile {
                    filename: "".to_string(),
                    bytes: cert.to_der()?,
                };
                cert_source.push(cf);
            }
        }
        let _ = cert_source.initialize(&cps);
        cert_source.find_all_partial_paths(&pe, &cps);

        pe.add_certificate_source(Box::new(cert_source));

        let signer_cert_pdv = match signer_cert {
            Some(cert) => PDVCertificate::try_from(cert.to_der()?.as_slice())?,
            None => return Err(ParseError),
        };

        let mut paths = vec![];
        pe.get_paths_for_target(
            &pe,
            &signer_cert_pdv,
            &mut paths,
            0,
            cps.get_time_of_interest(),
        )?;

        for mut path in paths {
            let mut cpr = CertificationPathResults::new();
            if pe.validate_path(&pe, &cps, &mut path, &mut cpr).is_ok() {
                return Ok(signer_info.signature.clone().into_bytes());
            }
        }
        Err(Error::ParseError)
    }
}

fn get_signer_cert<'a>(
    sid: &SignerIdentifier,
    certs: &mut impl Iterator<Item = &'a Certificate>,
) -> Option<&'a Certificate> {
    for cert in certs {
        match sid {
            SignerIdentifier::SubjectKeyIdentifier(_skid) => {
                todo!()
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