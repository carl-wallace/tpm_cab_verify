//! Alternative decoders for SignedData and TstInfo to work around quirks in the TrustedTpm.cab contents

use cms::{
    content_info::CmsVersion,
    signed_data::{DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignerInfos},
};
use der::{
    asn1::{Int, OctetString, SetOfVec},
    Any, Sequence,
};
use x509_cert::{
    ext::{
        pkix::{
            certpolicy::PolicyInformation,
            name::{GeneralName, GeneralNames},
        },
        Extensions,
    },
    impl_newtype,
    serial_number::SerialNumber,
    spki::AlgorithmIdentifierOwned,
};
use x509_tsp::{Accuracy, MessageImprint, TsaPolicyId, TspVersion};

/// Alternative SignedData decoder that tolerates v1 attribute certificates.
///
/// For some bizarre reason, the SignedData used for the timestamp includes v1 attribute certs (!!!),
/// which are marked as obsolete in CMS and are not supported in the cms crate.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub(crate) struct SignedData2 {
    pub version: CmsVersion,
    pub digest_algorithms: DigestAlgorithmIdentifiers,
    pub encap_content_info: EncapsulatedContentInfo,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<AnySet>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<AnySet>,
    pub signer_infos: SignerInfos,
}

/// Used in lieu of full support for all certificate and CRL types
#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct AnySet(pub SetOfVec<Any>);
impl_newtype!(AnySet, SetOfVec<Any>);

/// Timestamps on TrustedTpm.cab feature mis-encoded GeneralizedTime values, as shown in this dump
/// generated using dumpasn1:
///
/// ```text
///  4477    19:                               GeneralizedTime '20240614203756.847Z'
///            :                   Error: Time is encoded incorrectly.
///```
///
/// This structure treats the time field as an Any, which at least allows the message digest to be
/// compared.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct TstInfo2 {
    pub version: TspVersion,
    pub policy: TsaPolicyId,
    pub message_imprint: MessageImprint,
    pub serial_number: Int,
    pub gen_time: Any,
    #[asn1(optional = "true")]
    pub accuracy: Option<Accuracy>,
    #[asn1(default = "default_false")]
    pub ordering: bool,
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<GeneralName>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}

/// Provide false as default for boolean fields
pub(crate) fn default_false() -> bool {
    false
}

/// `IssuerSerial` from RFC 5035, binding a certificate hash to the issuer name and serial it was
/// issued under.
///
/// ```text
/// IssuerSerial ::= SEQUENCE {
///     issuer                   GeneralNames,
///     serialNumber             CertificateSerialNumber
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct IssuerSerial {
    pub issuer: GeneralNames,
    pub serial_number: SerialNumber,
}

/// `ESSCertIDv2` from RFC 5035. `hash_algorithm` defaults to SHA-256 when absent; `cert_hash` is the
/// hash of the referenced certificate under that algorithm.
///
/// ```text
/// ESSCertIDv2 ::= SEQUENCE {
///     hashAlgorithm            AlgorithmIdentifier
///                                  DEFAULT {algorithm id-sha256},
///     certHash                 Hash,
///     issuerSerial             IssuerSerial OPTIONAL
/// }
///
/// Hash ::= OCTET STRING
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct EssCertIdV2 {
    #[asn1(optional = "true")]
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    pub cert_hash: OctetString,
    #[asn1(optional = "true")]
    pub issuer_serial: Option<IssuerSerial>,
}

/// `SigningCertificateV2` from RFC 5035. The `policies` field is decoded but not inspected here.
///
/// ```text
/// SigningCertificateV2 ::= SEQUENCE {
///     certs                    SEQUENCE OF ESSCertIDv2,
///     policies                 SEQUENCE OF PolicyInformation OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct SigningCertificateV2 {
    pub certs: Vec<EssCertIdV2>,
    #[asn1(optional = "true")]
    pub policies: Option<Vec<PolicyInformation>>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use der::{Decode, Encode};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // A signingCertificateV2 value taken from a genuine Certum RFC 3161 token. hashAlgorithm is
    // omitted (the SHA-256 default) and issuerSerial is absent, exercising the leading OPTIONAL.
    const SIGNING_CERT_V2: &str =
        "302630243022042085be90e10ad2438d7cc928b6af48b09ab208177cecf8b0126c58d3910525c43c";

    #[test]
    fn signing_certificate_v2_default_hash_alg_decodes() {
        let der = unhex(SIGNING_CERT_V2);
        let sc = SigningCertificateV2::from_der(&der).unwrap();
        assert_eq!(sc.certs.len(), 1);
        let first = &sc.certs[0];
        assert!(first.hash_algorithm.is_none());
        assert!(first.issuer_serial.is_none());
        assert_eq!(first.cert_hash.as_bytes().len(), 32);
        assert_eq!(sc.to_der().unwrap(), der);
    }
}
