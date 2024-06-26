//! Provides a serde-based decoder capable in support of verifying the TrustedTpm.cab file. This is
//! not a general purpose CAB file verification utility.

pub(crate) mod cab;
pub(crate) mod timestamp;
pub(crate) mod signer;
pub(crate) mod asn1;
mod roots;

use authenticode::AuthenticodeSignature;
use certval::CertificationPathSettings;
use serde::{Deserialize, Serialize};

/// The structure shown below is defined [here](https://learn.microsoft.com/en-us/previous-versions//bb267310(v=vs.85)?redirectedfrom=MSDN#cfheader).
/// struct CFHEADER
/// {
///   u1  signature[4]  /* inet file signature */
///   u4  reserved1     /* reserved */
///   u4  cb_cabinet    /* size of this cabinet file in bytes */
///   u4  reserved2     /* reserved */
///   u4  coff_files    /* offset of the first CFFILE entry */
///   u4  reserved3     /* reserved */
///   u1  version_minor /* cabinet file format version, minor */
///   u1  version_major /* cabinet file format version, major */
///   u2  c_folders     /* number of CFFOLDER entries in this */
///                     /*    cabinet */
///   u2  c_files       /* number of CFFILE entries in this cabinet */
///   u2  flags         /* cabinet file option indicators */
///   u2  set_id        /* must be the same for all cabinets in a */
///                     /*    set */
///   u2  i_cabinet;    /* number of this cabinet file in a set */
///   u2  cb_cfheader;  /* (optional) size of per-cabinet reserved */
///                     /*    area */
///   u1  cb_cffolder;  /* (optional) size of per-folder reserved */
///                     /*    area */
///   u1  cb_cfdata;    /* (optional) size of per-datablock reserved */
///                     /*    area */
///   u1  ab_reserve[];     /* (optional) per-cabinet reserved area */
///   u1  szCabinetPrev[];  /* (optional) name of previous cabinet file */
///   u1  szDiskPrev[];     /* (optional) name of previous disk */
///   u1  szCabinetNext[];  /* (optional) name of next cabinet file */
///   u1  szDiskNext[];     /* (optional) name of next disk */
/// };
/// Based on limited observation, the szCabinetPrev, szDiskPrev, szCabinetNext, and szDiskNext are
/// assumed to always be absent and the cb_cfheader, cb_cffolder, and cb_cfdata fields are assumed to
/// always be present. The flags field will be inspected and if it is not consistent with this, i.e.,
/// if its value is not 4, then parsing will fail.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
struct CfHeader {
    pub signature: [u8; 4],
    pub reserved1: u32,
    pub cb_cabinet: u32,
    pub reserved2: u32,
    pub coff_files: u32,
    pub reserved3: u32,
    pub version_minor: u8,
    pub version_major: u8,
    pub c_folders: u16,
    pub c_files: u16,
    pub flags: u16,
    pub set_id: u16,
    pub i_cabinet: u16,
    pub cb_cfheader: u16,
    pub cb_cffolder: u8,
    pub cb_cfdata: u8,
    pub ignore1: u32,
    pub sig_offset: u32,
    pub sig_len: u32,
    pub ignore2: u32,
    pub ab_reserve: u32,
}

/// Provides information useful in verifying a CAB file, i.e., a digest of the relevant fields in a
/// signed CAB file and the extracted PKCS #7 message containing the signature that covers that digest.
///
/// The digest calculation is based entirely on review of the [cab_digest_calc](https://github.com/mtrojnar/osslsigncode/blob/master/cab.c#L202)
/// function in [osslsigncode](https://github.com/mtrojnar/osslsigncode). The implementation here was
/// further reduced based on observation of various TrustedTpm.cab file, i.e., there is never a next
/// or previous CAB file, there is always 1 folder, etc.
///
/// Verification of the CAB file signer and the timestamp signer are performed relative to a pair of
/// Microsoft root certification authorities that are baked into the crate.
pub struct CabVerifyParts {
    pub digest: Vec<u8>,
    pub signed_data: Vec<u8>,
}

impl CabVerifyParts {
    pub async fn verify(&self, cps: &CertificationPathSettings) -> certval::Result<()> {
        let authenticode = AuthenticodeSignature::from_bytes(&self.signed_data).unwrap();

        self.verify_cab_digest(&authenticode)?;
        let signature = self.verify_signer(&authenticode, cps)?;
        self.verify_timestamp(&authenticode, &signature, cps).await?;

        Ok(())
    }
}






