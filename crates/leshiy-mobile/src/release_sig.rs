//! Minisign verification for the Android in-app updater.
//!
//! The updater used to trust `SHA256SUMS` fetched from the same GitHub release as the APK, which
//! only proves the download wasn't corrupted, not who published it. The release pipeline signs
//! `SHA256SUMS` with the project's minisign key — the same key the CLI installer and
//! `leshiy upgrade` verify against — and the app now refuses checksums that key did not sign.
//!
//! Format (minisign 0.11): the public key is `base64("Ed" ‖ key_id[8] ‖ ed25519_pk[32])`; the
//! signature file is an untrusted comment line, `base64(alg[2] ‖ key_id[8] ‖ sig[64])`, a
//! `trusted comment: …` line, and `base64(global_sig[64])` over `sig ‖ trusted_comment`. `alg` is
//! `ED` (the default: the signed message is BLAKE2b-512 of the file) or legacy `Ed` (the raw file).
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signature, VerifyingKey};

/// The release signing public key, embedded at build time (last line is the key).
const RELEASE_PUB: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/minisign.pub"
));

/// True only when `minisig` is a valid signature of exactly `sums` by the release key.
#[uniffi::export]
pub fn verify_release_checksums(sums: Vec<u8>, minisig: String) -> bool {
    RELEASE_PUB
        .lines()
        .last()
        .is_some_and(|key| verify(key, &sums, &minisig).is_some())
}

fn verify(pubkey_b64: &str, data: &[u8], minisig: &str) -> Option<()> {
    let pk = B64.decode(pubkey_b64.trim()).ok()?;
    if pk.len() != 42 || &pk[..2] != b"Ed" {
        return None;
    }
    let key_id = &pk[2..10];
    let key = VerifyingKey::from_bytes(pk[10..].try_into().ok()?).ok()?;

    let mut lines = minisig.lines().map(|l| l.trim_end_matches('\r'));
    lines.next()?; // untrusted comment — by definition not covered by any signature
    let sig = B64.decode(lines.next()?.trim()).ok()?;
    if sig.len() != 74 || &sig[2..10] != key_id {
        return None;
    }
    let file_sig = Signature::from_bytes(sig[10..].try_into().ok()?);
    let comment = lines.next()?.strip_prefix("trusted comment: ")?;
    let global = B64.decode(lines.next()?.trim()).ok()?;
    let global = Signature::from_bytes(global.as_slice().try_into().ok()?);

    match &sig[..2] {
        b"ED" => key.verify_strict(Blake2b512::digest(data).as_slice(), &file_sig),
        b"Ed" => key.verify_strict(data, &file_sig),
        _ => return None,
    }
    .ok()?;
    let mut signed = sig[10..].to_vec();
    signed.extend_from_slice(comment.as_bytes());
    key.verify_strict(&signed, &global).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors made with `minisign 0.11` and a throwaway key (never used for anything else).
    const TEST_PUB: &str = "RWRRMN6Co2BDmitECh/7zwDqKZWFAxf3Dg+sSh6UHMatS+n2KEWdnuUs";
    const SUMS: &[u8] = b"abc123  leshiy_v9.9.9.apk\n";
    const PREHASHED: &str = "untrusted comment: signature from minisign secret key
RURRMN6Co2BDmt4fYh1qq2OMIKlCCODQo9AlNe+j5W4LHU2c+ixuY6liKZcElyEA5NNkMKcFJfAq1+9f8gf8zZk0YgKdgXwyKwE=
trusted comment: timestamp:1 file:SHA256SUMS
o2pZ29fsLN0fR660rxP3f+OH2+rvAMkgD5qCQwUEHrt8Xokb60UK2GZZXhYc/xz8U5JmuhtBhzb8hX3psorTDA==
";
    const LEGACY: &str = "untrusted comment: signature from minisign secret key
RWRRMN6Co2BDmoye5iTfAZkuuKeRvZhH3XmtByVgBRmqtAaGIEJsb9mAItebwd0/frk7FvozRPTse9Ir0NXiaHcbWh5Zpwcusg4=
trusted comment: timestamp:1 file:SHA256SUMS
D6k3lWXxc+t7yBD0cADvoUgGGsnkL28G26A05rcdQO9jJc/akVhdgEpBS97O4RerxsgWeIvY4Y46IqSeO0hWCQ==
";

    #[test]
    fn accepts_prehashed_and_legacy_signatures() {
        assert!(verify(TEST_PUB, SUMS, PREHASHED).is_some());
        assert!(verify(TEST_PUB, SUMS, LEGACY).is_some());
        assert!(verify(TEST_PUB, SUMS, &PREHASHED.replace('\n', "\r\n")).is_some());
    }

    #[test]
    fn rejects_a_tampered_file() {
        assert!(verify(TEST_PUB, b"abc124  leshiy_v9.9.9.apk\n", PREHASHED).is_none());
        assert!(verify(TEST_PUB, b"abc124  leshiy_v9.9.9.apk\n", LEGACY).is_none());
    }

    #[test]
    fn rejects_a_tampered_trusted_comment() {
        let forged = PREHASHED.replace("file:SHA256SUMS", "file:SHA256SUMZ");
        assert!(verify(TEST_PUB, SUMS, &forged).is_none());
    }

    #[test]
    fn rejects_another_key_and_garbage() {
        let release_key = RELEASE_PUB.lines().last().unwrap();
        assert!(verify(release_key, SUMS, PREHASHED).is_none());
        assert!(verify(TEST_PUB, SUMS, "").is_none());
        assert!(verify(TEST_PUB, SUMS, "untrusted comment: x\nnot base64\n").is_none());
        assert!(!verify_release_checksums(SUMS.to_vec(), PREHASHED.into()));
    }

    #[test]
    fn embedded_release_key_is_well_formed() {
        let key = B64
            .decode(RELEASE_PUB.lines().last().unwrap().trim())
            .unwrap();
        assert_eq!((key.len(), &key[..2]), (42, &b"Ed"[..]));
        assert!(VerifyingKey::from_bytes(key[10..].try_into().unwrap()).is_ok());
    }
}
