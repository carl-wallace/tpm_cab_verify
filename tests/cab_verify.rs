use certval::{buffer_to_hex, CertificationPathSettings};
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
    let cps = CertificationPathSettings::default();
    cvp.verify(&cps).await.unwrap();
}

// Attempt to verify a CAB file that has had contents altered (setup.cmd filename was changed to Setup.cmd)
#[tokio::test]
async fn test_altered_contents() {
    let trusted_tpm = include_bytes!("../tests/examples/altered_contents.cab");
    let cursor = std::io::Cursor::new(trusted_tpm);
    let cvp = CabVerifyParts::new(cursor).unwrap();
    let cps = CertificationPathSettings::default();
    assert!(cvp.verify(&cps).await.is_err());
}

// Verify a CAB file from April 2024 harvested from the wayback machine
#[tokio::test]
async fn test_cab2() {
    let trusted_tpm = include_bytes!("../tests/examples/TrustedTpm-2-04152024.cab");
    let cursor = std::io::Cursor::new(trusted_tpm);
    let cvp = CabVerifyParts::new(cursor).unwrap();
    let cps = CertificationPathSettings::default();
    cvp.verify(&cps).await.unwrap();
}

// Verify a CAB file from October 2021 harvested from the wayback machine
#[tokio::test]
async fn test_cab3() {
    let trusted_tpm = include_bytes!("../tests/examples/TrustedTpm-3-10232021.cab");
    let cursor = std::io::Cursor::new(trusted_tpm);
    let cvp = CabVerifyParts::new(cursor).unwrap();
    let mut cps = CertificationPathSettings::default();
    cps.set_time_of_interest(1635008378);
    cvp.verify(&cps).await.unwrap();
}
