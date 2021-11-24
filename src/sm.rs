// WARNING: efficient_sm2 and libsm didn't consider the potential security risk that
// privkey/secret leaks from un-zeroized memory. Using Secret is as far as we can do now.

// Reference impl here, with some improvement.
// https://github.com/cita-cloud/kms_sm

use rand::Rng;
use secrecy::ExposeSecret;
use secrecy::Secret;

use efficient_sm2::KeyPair;

pub const ADDR_BYTES_LEN: usize = 20;
pub const SM2_PUBKEY_BYTES_LEN: usize = 64;
pub const SM2_PRIVKEY_BYTES_LEN: usize = 32;
pub const SM2_SIGNATURE_BYTES_LEN: usize = 128;
pub const SM3_HASH_BYTES_LEN: usize = 32;

pub type Hash = [u8; SM3_HASH_BYTES_LEN];
pub type Address = [u8; ADDR_BYTES_LEN];
pub type PublicKey = [u8; SM2_PUBKEY_BYTES_LEN];
pub type PrivateKey = [u8; SM2_PRIVKEY_BYTES_LEN];
pub type Signature = [u8; SM2_SIGNATURE_BYTES_LEN];

// return KeyPair is for cache.
pub fn sm2_gen_keypair() -> (KeyPair, Secret<PrivateKey>) {
    let sk: Secret<PrivateKey> = Secret::new(rand::thread_rng().gen());
    let keypair = efficient_sm2::KeyPair::new(&sk.expose_secret()[..]).unwrap();
    (keypair, sk)
}

pub fn sm2_sign(key_pair: &KeyPair, msg: &[u8]) -> Signature {
    let sig = key_pair.sign(msg).expect("sm2 sign failed");

    let mut sig_bytes = [0u8; SM2_SIGNATURE_BYTES_LEN];
    sig_bytes[..32].copy_from_slice(&sig.r());
    sig_bytes[32..64].copy_from_slice(&sig.s());
    sig_bytes[64..].copy_from_slice(&key_pair.public_key().bytes_less_safe()[1..]);
    sig_bytes
}

// TODO: may use in future
#[allow(unused)]
pub fn sm2_recover_signature(msg: &[u8], signature: &Signature) -> Option<PublicKey> {
    let r = &signature[0..32];
    let s = &signature[32..64];
    let pk = &signature[64..];

    let pubkey = efficient_sm2::PublicKey::new(&pk[..32], &pk[32..]);
    let sig = efficient_sm2::Signature::new(r, s).ok()?;

    sig.verify(&pubkey, msg).ok()?;

    Some(pk.try_into().unwrap())
}

pub fn sm4_encrypt(data: &[u8], password_hash: &[u8]) -> Vec<u8> {
    let (key, iv) = password_hash.split_at(16);
    let cipher = libsm::sm4::Cipher::new(key, libsm::sm4::Mode::Cfb);

    cipher.encrypt(data, iv)
}

pub fn sm4_decrypt(data: &[u8], password_hash: &[u8]) -> Vec<u8> {
    let (key, iv) = password_hash.split_at(16);
    let cipher = libsm::sm4::Cipher::new(key, libsm::sm4::Mode::Cfb);

    cipher.decrypt(data, iv)
}

pub fn sm3_hash(input: &[u8]) -> Hash {
    libsm::sm3::hash::Sm3Hash::new(input).get_hash()
}

pub fn addr_from_keypair(keypair: &KeyPair) -> Address {
    let pk = keypair.public_key();
    let hash = sm3_hash(&pk.bytes_less_safe()[1..]);

    hash[SM3_HASH_BYTES_LEN - ADDR_BYTES_LEN..]
        .try_into()
        .unwrap()
}
