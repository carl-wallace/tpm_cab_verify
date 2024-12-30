use certval::{
    buffer_to_hex, CertFile, CertVector, CertificationPathSettings, PkiEnvironment, TaSource,
};
use tpm_cab_verify::CabVerifyParts;

// Verify a CAB file that is current as of creation of this crate (and the tpm_roots crate)
#[tokio::test]
async fn test_cab() {
    let trusted_tpm = include_bytes!("../tests/examples/TrustedTpm.cab");
    let cursor = std::io::Cursor::new(trusted_tpm);
    let cvp = CabVerifyParts::new(cursor).unwrap();
    assert_eq!(
        "AF88ABB1A066AFB8C936D60DB00E4AD3FE0E5DE33A6DDF3501BD7D7E29FD0657",
        buffer_to_hex(&cvp.digest)
    );
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut cps = CertificationPathSettings::default();
    cps.set_time_of_interest(1720008737);
    cvp.verify(&mut pe, &cps).await.unwrap();
}

// Attempt to verify a CAB file that has had contents altered (setup.cmd filename was changed to Setup.cmd)
#[tokio::test]
async fn test_altered_contents() {
    let trusted_tpm = include_bytes!("../tests/examples/altered_contents.cab");
    let cursor = std::io::Cursor::new(trusted_tpm);
    let cvp = CabVerifyParts::new(cursor).unwrap();
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut cps = CertificationPathSettings::default();
    cps.set_time_of_interest(1720008737);
    assert!(cvp.verify(&mut pe, &cps).await.is_err());
}

// Verify a CAB file from April 2024 harvested from the wayback machine
#[tokio::test]
async fn test_cab2() {
    let trusted_tpm = include_bytes!("../tests/examples/TrustedTpm-2-04152024.cab");
    let cursor = std::io::Cursor::new(trusted_tpm);
    let cvp = CabVerifyParts::new(cursor).unwrap();
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut cps = CertificationPathSettings::default();
    cps.set_time_of_interest(1720008737);
    cvp.verify(&mut pe, &cps).await.unwrap();
}

// Verify a CAB file from October 2021 harvested from the wayback machine
#[tokio::test]
async fn test_cab3() {
    let trusted_tpm = include_bytes!("../tests/examples/TrustedTpm-3-10232021.cab");
    let cursor = std::io::Cursor::new(trusted_tpm);
    let cvp = CabVerifyParts::new(cursor).unwrap();
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let mut legacy_msft_root = TaSource::new();
    let msft_root_old_bytes = include_bytes!("../microsoftrootcert.crt");
    let cf3 = CertFile {
        filename: "microsoftrootcert.crt".to_string(),
        bytes: msft_root_old_bytes.to_vec(),
    };
    legacy_msft_root.push(cf3);
    legacy_msft_root.initialize().unwrap();
    pe.add_trust_anchor_source(Box::new(legacy_msft_root));

    let mut cps = CertificationPathSettings::default();
    cps.set_time_of_interest(1635008378);
    cvp.verify(&mut pe, &cps).await.unwrap();
}
