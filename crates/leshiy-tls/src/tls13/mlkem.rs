//! ML-KEM-768 wrapper for the X25519MLKEM768 (0x11EC) hybrid key exchange.
//! The client holds the decapsulation key; the server (REALITY) only encapsulates.

pub const ML_KEM_EK: usize = 1184; // encapsulation key bytes
pub const ML_KEM_CT: usize = 1088; // ciphertext bytes
pub const ML_KEM_SS: usize = 32; // shared secret bytes

use ml_kem::{
    Decapsulate, Encapsulate, Kem, KeyExport, MlKem768,
    kem::{self, DecapsulationKey as RawDk, EncapsulationKey as RawEk},
};

/// Holds the ML-KEM-768 decapsulation key (client side).
pub struct MlKemDecapKey(RawDk<MlKem768>);

/// Generate a keypair; return the decap key + the 1184-byte encapsulation key bytes.
pub fn generate() -> (MlKemDecapKey, [u8; ML_KEM_EK]) {
    let (dk, ek) = MlKem768::generate_keypair();
    let ek_arr = ek.to_bytes();
    let mut ek_bytes = [0u8; ML_KEM_EK];
    ek_bytes.copy_from_slice(ek_arr.as_slice());
    (MlKemDecapKey(dk), ek_bytes)
}

/// Server side: parse an encapsulation key and encapsulate → (ciphertext, shared secret).
pub fn encapsulate(ek_bytes: &[u8]) -> Option<([u8; ML_KEM_CT], [u8; ML_KEM_SS])> {
    if ek_bytes.len() != ML_KEM_EK {
        return None;
    }
    let key_arr: &kem::Key<RawEk<MlKem768>> = ek_bytes.try_into().ok()?;
    let ek = RawEk::<MlKem768>::new(key_arr).ok()?;
    let (ct, ss) = ek.encapsulate();
    let mut ct_bytes = [0u8; ML_KEM_CT];
    ct_bytes.copy_from_slice(ct.as_slice());
    let mut ss_bytes = [0u8; ML_KEM_SS];
    ss_bytes.copy_from_slice(ss.as_slice());
    Some((ct_bytes, ss_bytes))
}

/// Client side: decapsulate a ciphertext → shared secret.
pub fn decapsulate(dk: &MlKemDecapKey, ct_bytes: &[u8]) -> Option<[u8; ML_KEM_SS]> {
    if ct_bytes.len() != ML_KEM_CT {
        return None;
    }
    let ct: &kem::Ciphertext<MlKem768> = ct_bytes.try_into().ok()?;
    let ss = dk.0.decapsulate(ct);
    let mut ss_bytes = [0u8; ML_KEM_SS];
    ss_bytes.copy_from_slice(ss.as_slice());
    Some(ss_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encaps_decaps_roundtrip() {
        let (dk, ek) = generate();
        assert_eq!(ek.len(), ML_KEM_EK);
        let (ct, ss_server) = encapsulate(&ek).unwrap();
        assert_eq!(ct.len(), ML_KEM_CT);
        let ss_client = decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss_client, ss_server); // both sides agree
    }

    #[test]
    fn bad_inputs_return_none() {
        let (dk, _ek) = generate();
        assert!(encapsulate(&[0u8; 10]).is_none()); // wrong ek length
        assert!(decapsulate(&dk, &[0u8; 10]).is_none()); // wrong ct length
    }
}
