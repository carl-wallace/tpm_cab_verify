use certval::{CertFile, CertVector, TaSource};

pub(crate) fn get_msft_roots() -> certval::Result<TaSource> {
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

    let msft_root_old_bytes = include_bytes!("../microsoftrootcert.crt");
    let cf3 = CertFile {
        filename: "microsoftrootcert.crt".to_string(),
        bytes: msft_root_old_bytes.to_vec(),
    };
    msft_roots.push(cf3);
    msft_roots.initialize()?;
    Ok(msft_roots)
}