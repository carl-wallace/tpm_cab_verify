//! Prepares a trust anchor source containing current Microsoft trust anchors required to verify
//! TrustedTpm.cab files.

use crate::Result;
use certval::{CertFile, CertVector, TaSource};

/// Prepare and return a TaSource instance populated with Microsoft trust anchors required to validate
/// TrustedTpm.cab files. The included trust anchors are:
///
/// ```text
/// Common Name: Microsoft Root Certificate Authority 2011
/// Subject Key Identifier: 722D3A02319043B914054EE1EAA7C731D1238934
///
/// Common Name: Microsoft Root Certificate Authority 2010
/// Subject Key Identifier: D5F656CB8FE8A25C6268D13D94905BD7CE9A18C4
/// ```
pub(crate) fn get_msft_roots() -> Result<TaSource> {
    let mut msft_roots = TaSource::new();
    let msft_root_2011_bytes = include_bytes!("../MicrosoftRootCertificateAuthority2011.cer");
    let cf = CertFile {
        filename: "MicrosoftRootCertificateAuthority2011.cer".to_string(),
        bytes: msft_root_2011_bytes.to_vec(),
    };
    msft_roots.push(cf);

    let msft_root_2010_bytes = include_bytes!("../MicRooCerAut_2010-06-23.crt");
    let cf2 = CertFile {
        filename: "MicRooCerAut_2010-06-23.crt".to_string(),
        bytes: msft_root_2010_bytes.to_vec(),
    };
    msft_roots.push(cf2);
    msft_roots.initialize()?;
    Ok(msft_roots)
}
