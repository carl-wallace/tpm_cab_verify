//! Parses a CAB file to obtain a digest of relevant components and the SignedData message that covers
//! the CAB file

use std::io::{Read, Seek, SeekFrom};

use authenticode::AuthenticodeSignature;
use log::error;

use cms::content_info::ContentInfo;
use x509_cert::der::{Decode, ErrorKind};

use sha2::{Digest, Sha256};

use crate::{CabVerifyParts, CfHeader, Error, Result};

impl CabVerifyParts {
    /// Calculate a message digest to compare to the SpcIndirectDataContent included in the SignedData
    /// message included in the CAB file.
    ///
    /// The digest calculation is based entirely on the digest calculation included in the
    /// [osslsigncode](https://github.com/mtrojnar/osslsigncode/) utility. This implementation varies
    /// slightly owing to limited usage context.
    pub fn new<R>(mut reader: R) -> Result<Self>
    where
        R: Read + Seek,
    {
        let mut header = vec![00u8; 60];
        if let Err(e) = reader.read_exact(&mut header) {
            error!("Failed to read CfHeader value: {e:?}");
            return Err(e.into());
        }

        let cf: CfHeader = match bincode::deserialize(&header) {
            Ok(cf) => cf,
            Err(e) => {
                error!("Failed to parse CfHeader: {e:?}");
                return Err(Error::ParseError);
            }
        };

        let mut hasher = Sha256::new();

        // see cab_digest_calc in osslsigncode re: which fields are skipped.
        hasher.update(cf.signature);
        hasher.update(cf.cb_cabinet.to_le_bytes());
        hasher.update(cf.reserved2.to_le_bytes());
        hasher.update(cf.coff_files.to_le_bytes());
        hasher.update(cf.reserved3.to_le_bytes());
        hasher.update(cf.version_minor.to_le_bytes());
        hasher.update(cf.version_major.to_le_bytes());
        hasher.update(cf.c_folders.to_le_bytes());
        hasher.update(cf.c_files.to_le_bytes());
        hasher.update(cf.flags.to_le_bytes());
        hasher.update(cf.set_id.to_le_bytes());
        hasher.update(cf.ab_reserve.to_le_bytes());

        assert_eq!(60, reader.stream_position().unwrap_or_default());

        let mut folder = vec![0u8; 8];
        if let Err(e) = reader.read_exact(&mut folder) {
            error!("Failed to read folder entry value at offset 60: {e:?}");
            return Err(e.into());
        }
        hasher.update(&folder);

        assert_eq!(
            cf.coff_files as u64,
            reader.stream_position().unwrap_or_default()
        );
        if let Err(e) = reader.seek(SeekFrom::Start(cf.coff_files as u64)) {
            error!(
                "Failed to seek to start of file data at offset{}: {e:?}",
                cf.coff_files
            );
            return Err(e.into());
        }

        let chunk_size = 1000;
        let mut chunk = vec![0u8; chunk_size as usize];
        let mut index = match reader.stream_position() {
            Ok(index) => index,
            Err(e) => {
                error!("Failed to read stream position while digested file data: {e:?}");
                return Err(e.into());
            }
        };
        while index < cf.sig_offset as u64 {
            let want = cf.sig_offset as u64 - index;
            if want < chunk_size {
                chunk.resize(want as usize, 0);
            }
            reader.read_exact(&mut chunk)?;
            hasher.update(&chunk);

            index = match reader.stream_position() {
                Ok(index) => index,
                Err(e) => {
                    error!("Failed to read stream position while digested file data: {e:?}");
                    return Err(e.into());
                }
            };
        }

        assert_eq!(
            cf.sig_offset as u64,
            reader.stream_position().unwrap_or_default()
        );
        if let Err(e) = reader.seek(SeekFrom::Start(cf.sig_offset as u64)) {
            error!(
                "Failed to seek to start of signature data at offset{}: {e:?}",
                cf.sig_offset
            );
            return Err(e.into());
        }

        let mut signed_data = vec![0u8; cf.sig_len as usize];
        if let Err(e) = reader.read_exact(&mut signed_data) {
            error!("Failed to read SignedData value: {e:?}");
            return Err(e.into());
        }

        // The signature length indicated in the CAB data includes trailing data sometimes. Detect that
        // here and fix it so the caller can act on the data without having to deal with this.
        if let Err(e) = ContentInfo::from_der(&signed_data) {
            match e.kind() {
                ErrorKind::TrailingData {
                    decoded,
                    remaining: _,
                } => match decoded.try_into() {
                    Ok(x) => {
                        signed_data.resize(x, 0);
                    }
                    Err(e) => {
                        error!("Failed to parse ContentInfo due to trailing data then failed to parse decoded size. Returning as-is. Error: {e:?}.")
                    }
                },
                _ => {
                    error!("Failed to parse ContentInfo. Returning as-is. Error: {e:?}.")
                }
            }
        };

        let output = hasher.finalize();
        Ok(CabVerifyParts {
            digest: output.to_vec(),
            signed_data,
        })
    }

    /// Compares the digest calculated over the CAB file contents with the value included in the
    /// SpcIndirectDataContent structure in the SignedData message.
    pub(crate) fn verify_cab_digest(&self, authenticode: &AuthenticodeSignature) -> Result<()> {
        let cab_digest = authenticode.digest();
        if self.digest != cab_digest {
            return Err(Error::DigestMismatch);
        }
        Ok(())
    }
}
