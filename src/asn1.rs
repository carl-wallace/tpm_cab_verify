//! Alternative decoders for SignedData and TstInfo to work around quirks in the TrustedTpm.cab contents

use cms::{
    content_info::CmsVersion, signed_data::{
        DigestAlgorithmIdentifiers, EncapsulatedContentInfo,
        SignerInfos,
    }
};
use der::{
    Any, asn1::{Int, SetOfVec}, Sequence
};
use x509_cert::{
    ext::{
        pkix::name::GeneralName, Extensions
    }, impl_newtype
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
    #[asn1(default = "default_false_example")]
    pub ordering: bool,
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<GeneralName>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}
pub fn default_false_example() -> bool {
    false
}