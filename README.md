# Trusted platform module (TPM) cabinet (CAB) file verification

The `tpm_cab_verify` crate provides support for verifying the TrustedTpm.cab files that contain trust anchors and
certification authority (CA) certificates in support of verifying attestations from TPM-backed virtual smart cards (VSCs).

CAB files processed using this crate are assumed to have been obtained per the instructions [here](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates).
This is not a general purpose CAB verification utility (though it probably could be if documentation describing the
structure of signed CAB files were available).

The digest calculation performed by this crate is based on the digest calculation in the `cab_digest_calc` function in
the [osslsigncode](https://github.com/mtrojnar/osslsigncode/) utility.

SignedData verification is performed using the [certval](https://github.com/carl-wallace/rust-pki) crate built with baked in
Microsoft trust anchors. 

Signatures on CAB files are validated to a Microsoft trust anchor that was downloaded from [here](https://download.microsoft.com/download/2/4/8/248D8A62-FCCD-475C-85E7-6ED59520FC0F/MicrosoftRootCertificateAuthority2011.cer).