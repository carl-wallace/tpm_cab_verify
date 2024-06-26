use authenticode::AuthenticodeSignature;

use cms::{
    attr::MessageDigest, content_info::ContentInfo, signed_data::SignerIdentifier
};
use const_oid::{
    db::{
        rfc5911::{
            ID_SIGNED_DATA, ID_MESSAGE_DIGEST
        },
    }, ObjectIdentifier
};
use x509_cert::{
    der::{
        Decode, Encode
    },
    Certificate
};

use sha2::{Digest, Sha256};

use certval::{
    CertFile, CertSource, CertVector, CertificationPathResults,
    CertificationPathSettings, Error, PDVCertificate, PkiEnvironment,
};
use crate::{CabVerifyParts, asn1::{SignedData2, TstInfo2}};
use crate::roots::get_msft_roots;

impl CabVerifyParts {
    pub(crate) async fn verify_timestamp(
        &self,
        authenticode: &AuthenticodeSignature,
        signature: &[u8],
        cps: &CertificationPathSettings
    ) -> certval::Result<()> {
        let signer_info = authenticode.signer_info();
        let unsigned_attrs = match &signer_info.unsigned_attrs {
            Some(unsigned_attrs) => unsigned_attrs,
            None => return Err(Error::ParseError),
        };

        let timestamp_oid = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");

        let timestamp_attr = unsigned_attrs.iter().find(|a| a.oid == timestamp_oid);
        let timestamp = match timestamp_attr {
            Some(attr) => {
                if let Some(val) = attr.values.get(0) {
                    val.to_der()?
                } else {
                    return Err(Error::ParseError);
                }
            }
            None => return Err(Error::ParseError),
        };

        let ci = ContentInfo::from_der(&timestamp)?;
        if ci.content_type != ID_SIGNED_DATA {
            return Err(Error::ParseError);
        }
        let sd_bytes = ci.content.to_der()?;
        let sd = SignedData2::from_der(&sd_bytes)?;
        let ec = match sd.encap_content_info.econtent {
            Some(ec) => ec,
            None => return Err(Error::ParseError),
        };
        let encap_content = ec.value().to_vec();
        let encap_digest = Sha256::digest(&encap_content);

        let timestamp_token = TstInfo2::from_der(&encap_content)?;
        //todo more algs
        let sig_hash = Sha256::digest(signature);
        if timestamp_token.message_imprint.hashed_message.as_bytes() != sig_hash.as_slice() {
            return Err(Error::ParseError);
        }

        let signer_info = match sd.signer_infos.0.get(0) {
            Some(si) => si,
            None => return Err(Error::ParseError),
        };
        let signed_attrs = match &signer_info.signed_attrs {
            Some(sa) => sa,
            None => return Err(Error::ParseError),
        };
        let md_attr = signed_attrs.iter().find(|a| a.oid == ID_MESSAGE_DIGEST);
        match md_attr {
            Some(attr) => {
                if let Some(val) = attr.values.get(0) {
                    let md_attr = MessageDigest::from_der(&val.to_der()?)?;
                    if md_attr.as_bytes() != encap_digest.as_slice() {
                        return Err(Error::ParseError);
                    }
                } else {
                    return Err(Error::ParseError);
                }
            }
            None => return Err(Error::ParseError),
        };
        let enc_signed_attrs = signed_attrs.to_der()?;
        let signature = signer_info.signature.as_bytes();

        let pile = match sd.certificates {
            Some(pile) => pile,
            None => return Err(Error::ParseError),
        };

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

        let signer_cert_option = get_signer_cert_vec(&signer_info.sid, &certs);

        let signer_cert = match signer_cert_option {
            Some(signer_cert) => signer_cert,
            None => return Err(Error::ParseError),
        };

        let mut pe = PkiEnvironment::new();
        pe.populate_5280_pki_environment();
        pe.verify_signature_message(
            &pe,
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

        let signer_cert_pdv = PDVCertificate::try_from(signer_cert.to_der()?.as_slice())?;

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
                return Ok(());
            }
        }

        Ok(())
    }
}

fn get_signer_cert_vec(sid: &SignerIdentifier, certs: &Vec<Certificate>) -> Option<Certificate> {
    for cert in certs {
        match sid {
            SignerIdentifier::SubjectKeyIdentifier(_skid) => {
                todo!()
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