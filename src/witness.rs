//! Generate witnesses for different AES cipher modes
//!
//! NOTES on AES
//! - AES-GCM, the authentication is a 16 byte string appended to the ciphertext.
//! - AES-GCM auth tag is encrypted at the end.
//! - AES-GCM the AAD only effects the auth tag
//! - AES-GCM-SIV, AAD impacts all ciphertext.
//! - AES is processed in 16 byte chunks. The chunks are then appended together.
//! - AES-CTR is a subset of GCM with some adjustments to IV prep (16 bytes)
//! - AES-GCM can be decrypted by AES-CTR, by skipping the auth tag and setting up the IV correctly.

use aes::{
    cipher::{BlockEncrypt, InnerIvInit, KeyInit, KeyIvInit, StreamCipher, StreamCipherCore},
    Aes128,
};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Payload},
    Aes128Gcm, Aes256Gcm,
};
use anyhow::Result;
use serde::Serialize;

use crate::{
    consts::*,
    utils::{apply_keystream, make_nonce, make_tls13_aad},
    Aes128Ctr32BE, Aes256Ctr32BE, Block, Ctr32BE,
};

/// Witness bytes generated by this binary
#[derive(Debug, Serialize)]
pub struct Witness {
    pub key: Vec<u8>,
    pub iv:  Vec<u8>,
    pub ct:  Vec<u8>,
    pub pt:  Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct AesGcmSivInputs {
    pub K1:  Vec<u8>,
    pub N:   Vec<u8>,
    pub AAD: Vec<u8>,
    pub CT:  Vec<u8>,
}

impl Witness {
    pub fn new(key: &[u8], iv: &[u8], ct: &[u8], pt: &[u8]) -> Self {
        Self { key: key.to_vec(), iv: iv.to_vec(), ct: ct.to_vec(), pt: pt.to_vec() }
    }
}

/// AES cipher modes.
#[derive(Default)]
pub(crate) enum CipherMode {
    Vanilla, // no IV Here
    Ctr256,
    GcmSiv,
    GCM256,
    Ctr128,
    /// AES-GCM-128 bit
    #[default]
    GCM128,
}

/// borrowed from rust-tls
fn encrypt_tls(message: &[u8], key: &[u8], iv: &[u8], seq: u64) -> Result<Vec<u8>> {
    // see tls1.3; 1 byte type, 16b aad
    let total_len = message.len() + 1 + 16;
    let aad = make_tls13_aad(total_len);
    let fixed_iv = iv[..12].try_into()?;
    let nonce = make_nonce(fixed_iv, seq);

    println!("ENC: msg={:?}, msg_len={:?}, seq={:?}", hex::encode(message), message.len(), seq);
    println!("ENC: iv={:?}, dec_key={:?}", hex::encode(iv), hex::encode(key));
    println!("ENC: nonce={:?}, aad={:?}", hex::encode(nonce), hex::encode(aad));

    let mut payload = Vec::with_capacity(total_len);
    payload.extend_from_slice(message);
    // payload.push(0x17);  // Very important, encrypted messages must have the type appended.

    let aes_payload = Payload {
        msg: &payload,
        aad: &[], /* refactor remove
                   * aad: &aad, */
    };

    let cipher = Aes128Gcm::new_from_slice(key).unwrap();
    let nonce = GenericArray::from_slice(iv);
    Ok(cipher.encrypt(nonce, aes_payload).expect("error generating ct"))
}

pub fn aes_witnesses(cipher_mode: CipherMode) -> Result<Witness> {
    // Base ASCII versions using TLS encryption.
    let ct = encrypt_tls(MESSAGE.as_bytes(), KEY_ASCII.as_bytes(), IV_ASCII.as_bytes(), 1).unwrap();
    println!("ENC: cipher_text={:?}, cipher_len={:?}", hex::encode(ct.clone()), ct.len());

    let key = GenericArray::from(KEY_BYTES_156);
    let key_256 = GenericArray::from(KEY_BYTES_256);
    let iv = GenericArray::from(IV_BYTES);
    let mut block = GenericArray::from(MESSAGE_BYTES);
    let mut block_256 = GenericArray::from(ZERO_MESSAGE_BYTES_256);

    let ct = match cipher_mode {
        CipherMode::Vanilla => {
            let cipher = Aes128::new(&key);
            cipher.encrypt_block(&mut block);
            block.to_vec()
        },
        CipherMode::Ctr256 => {
            // AES CTR 256, adjusted to match GCM. ✅, matches AES-256-GCM impl
            let mut cipher_256 = Aes256Ctr32BE::new(&key_256, &IV_BYTES_256.into());
            let mut tag_mask_256 = Block::default();

            cipher_256.apply_keystream(&mut tag_mask_256);
            cipher_256.apply_keystream(&mut block_256);
            block_256.to_vec()
        },
        CipherMode::GcmSiv => {
            // AES GCM SIV, WOO MATCHES CIRCOM!! ✅
            use aes_gcm_siv::{
                aead::{Aead, Payload as SIVPayload},
                Aes256GcmSiv,
            };
            let cipher = Aes256GcmSiv::new_from_slice(&key_256).unwrap();
            let nonce = GenericArray::from_slice(&IV_BYTES_SHORT_256);
            let aes_payload = SIVPayload { msg: &ZERO_MESSAGE_BYTES_256, aad: &SIV_AAD };
            let ciphertext_siv = cipher.encrypt(nonce, aes_payload).expect("error generating ct");
            println!(
                "AES GCM 256 SIV: ct={:?}, bytes={:?}",
                hex::encode(ciphertext_siv.clone()),
                ciphertext_siv
            );
            ciphertext_siv.to_vec()
        },
        CipherMode::GCM256 => {
            // Standard AES 256 GCM
            let cipher = Aes256Gcm::new_from_slice(&key_256).unwrap();
            let nonce = GenericArray::from_slice(&IV_BYTES_SHORT_256);
            let aes_payload = Payload { msg: &ZERO_MESSAGE_BYTES_256, aad: &SIV_AAD };
            let ct = cipher.encrypt(nonce, aes_payload).expect("error generating ct");
            ct.to_vec()
        },
        CipherMode::Ctr128 => {
            // AES CTR 128, adjusted to match GCM. ✅, matches AES-128-GCM impl
            let mut cipher = Aes128Ctr32BE::new(&key, &iv);
            let mut tag_mask = Block::default();
            cipher.apply_keystream(&mut tag_mask); // In AES-GCM, an empty mask is encrypted first.
            cipher.apply_keystream(&mut block);
            block.to_vec()
        },
        CipherMode::GCM128 => {
            unimplemented!()
        },
    };

    // more manual AESGCM using rust crypto should be equiv to output of encrypt tls
    // can remove or assert equiv later
    //
    // AES-GCM Duplication. NOTE: This is identical to section 246.
    // Init logic in AES-GCM. This standard procedure can be applied to the TLS IV.
    let mut ghash_iv = ghash::Block::default();
    ghash_iv[..12].copy_from_slice(&IV_BYTES_SHORT);
    ghash_iv[15] = 1;

    let inner_cipher = Aes128::new(&key);
    let mut ctr = Ctr32BE::inner_iv_init(&inner_cipher, &ghash_iv);
    let mut tag_mask = Block::default();

    ctr.write_keystream_block(&mut tag_mask);
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(MESSAGE.as_bytes());
    apply_keystream(ctr, &mut buffer);

    // WORKING! The aes-ctr and aes-gcm now match.
    println!("INPUT iv={:?}, key={:?}", hex::encode(IV_BYTES), hex::encode(KEY_BYTES_156));
    println!(
        "AES GCM IV={:?}, tm={:?}, ct={:?}",
        hex::encode(ghash_iv),
        hex::encode(tag_mask),
        hex::encode(buffer)
    );
    println!("AES CTR: ct={:?}", hex::encode(block));
    println!("AES CTR 256, 96 IV: ct={:?}", hex::encode(block));
    println!("AES GCM 256: ct={:?}", hex::encode(ct.clone()));

    Ok(Witness::new(&KEY_BYTES_156, &IV_BYTES_SHORT_256, &ct, &ZERO_MESSAGE_BYTES_256))
}
