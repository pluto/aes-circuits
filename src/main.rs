//! This generates witnesses to test circom artifacts in the `circuits` directory.

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(clippy::clone_on_copy)]

use std::io;

use aes::{cipher::generic_array::GenericArray, Aes256};
use cipher::consts::U16;
use utils::make_json_witness;

mod consts;
mod proof;
mod utils;
mod witness;

/// Circom compilation artifacts
/// Must compile circom artifacts first if these aren't found.
const SIV_WTNS: &str = "./build/gcm_siv_dec_2_keys_test_js/gcm_siv_dec_2_keys_test.wasm";
const SIV_R1CS: &str = "./build/gcm_siv_dec_2_keys_test.r1cs";
const AES_256_CRT_WTNS: &str = "./build/aes_256_ctr_test_js/aes_256_ctr_test.wasm";
const AES_256_CRT_R1CS: &str = "./build/aes_256_ctr_test.r1cs";

pub type AAD = [u8; 5];
pub type Nonce = [u8; 12];

// convenience type aliases for AES-CTR, wrapping type aliases from `ctr` crate
pub(crate) type Ctr32BE<Aes128> = ctr::CtrCore<Aes128, ctr::flavors::Ctr32BE>;
pub(crate) type Aes256Ctr32BE = ctr::Ctr32BE<Aes256>;
pub(crate) type Aes128Ctr32BE = ctr::Ctr32BE<aes::Aes128>; // Note: Ctr32BE is used in AES GCM

/// AES 128-bit block
pub(crate) type Block = GenericArray<u8, U16>;

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut witness = witness::aes_witnesses(witness::CipherMode::Vanilla).unwrap();
    witness.iv.extend_from_slice(&[0, 0, 0, 0]);

    make_json_witness(&witness, witness::CipherMode::Vanilla).unwrap();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test the AES-GCM-SIV circuit (from electron labs)
    #[tokio::test]
    async fn test_aes_gcm_siv() {
        // generate witness
        let mut witness = witness::aes_witnesses(witness::CipherMode::GcmSiv).unwrap();

        // log one of them
        println!(
            "proof gen: key={:?}, iv={:?}, ct={:?}, pt={:?}",
            witness.key, witness.iv, witness.ct, witness.pt
        );

        // tls1.3 junk
        witness.iv.extend_from_slice(&[0; 4]);

        // generate proof
        proof::gen_proof_aes_gcm_siv(&witness, SIV_WTNS, SIV_R1CS);
    }

    // AES GCM multiple blocks of data
    // cargo test test_aes_gcm_10_blocks -- --show-output
    #[tokio::test]
    async fn test_aes_gcm_10_blocks() {
        use aes_gcm::{
            aead::{generic_array::GenericArray, Aead, NewAead, Payload},
            Aes128Gcm,
        };

        let test_key = [
            0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
            0x31, 0x31,
        ];
        let test_iv = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];

        let mut payload: Vec<u8> = Vec::new();
        for last_byte in 0..10 {
            let message = format!("testhello000000{}", last_byte);
            payload.extend(message.as_bytes());
        }
        let aes_payload = Payload { msg: &payload, aad: &[] };

        let cipher = Aes128Gcm::new_from_slice(&test_key).unwrap();
        let nonce = GenericArray::from_slice(&test_iv);
        let ct = cipher.encrypt(nonce, aes_payload).expect("error generating ct");

        println!("key={}", hex::encode(test_key));
        println!("iv={}", hex::encode(test_iv));
        println!("msg={}", hex::encode(payload));
        println!("ct={}", hex::encode(ct));
    }

    // AES GCM multiple blocks of data
    // cargo test test_aes_gcm_10_blocks -- --show-output
    #[tokio::test]
    async fn test_aes_gcm_10_blocks1() {
        use aes_gcm::{
            aead::{generic_array::GenericArray, Aead, NewAead, Payload},
            Aes128Gcm,
        };

        let test_key = [
            0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
            0x31, 0x31,
        ];
        let test_iv = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];

        let mut payload: Vec<u8> = Vec::new();
        for last_byte in 0..10 {
            let message = format!("testhello000000{}", last_byte);
            payload.extend(message.as_bytes());
        }
        let aes_payload = Payload { msg: &payload, aad: &[] };

        let cipher = Aes128Gcm::new_from_slice(&test_key).unwrap();
        let nonce = GenericArray::from_slice(&test_iv);
        let ct = cipher.encrypt(nonce, aes_payload).expect("error generating ct");

        println!("key={}", hex::encode(test_key));
        println!("iv={}", hex::encode(test_iv));
        println!("msg={}", hex::encode(payload));
        println!("ct={}", hex::encode(ct));
    }

    /// Test AES-GCM with data length not a multiple of block size
    #[tokio::test]
    async fn test_aes_gcm_non_multiple_length() {
        use aes_gcm::{
            aead::{generic_array::GenericArray, Aead, NewAead, Payload},
            Aes128Gcm,
        };

        let test_key = [
            0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
            0x31, 0x31,
        ];
        let test_iv = [0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31];

        let mut payload: Vec<u8> = Vec::new();
        for last_byte in 0..2 {
            let message = format!("testhelloworld{}", last_byte);
            payload.extend(message.as_bytes());
        }
        let aes_payload = Payload { msg: &payload, aad: &[] };

        let cipher = Aes128Gcm::new_from_slice(&test_key).unwrap();
        let nonce = GenericArray::from_slice(&test_iv);
        let ct = cipher.encrypt(nonce, aes_payload).expect("error generating ct");

        println!("key={}", hex::encode(test_key));
        println!("iv={}", hex::encode(test_iv));
        println!("msg={}", hex::encode(payload));
        println!("ct={}", hex::encode(ct));
    }

    #[tokio::test]
    async fn test_ghash() {
        use ghash::{
            universal_hash::{KeyInit, UniversalHash},
            GHash,
        };
        use hex_literal::hex;

        const H: [u8; 16] = hex!("aae06992acbf52a3e8f4a96ec9300bd7");
        const X_1: [u8; 16] = hex!("98e7247c07f0fe411c267e4384b0f600");

        let mut ghash = GHash::new(&H.into());
        ghash.update(&[X_1.into()]);
        let result = ghash.finalize();

        let hash_key = [
            0xaa, 0xe0, 0x69, 0x92, 0xac, 0xbf, 0x52, 0xa3, 0xe8, 0xf4, 0xa9, 0x6e, 0xc9, 0x30,
            0x0b, 0xd7,
        ];
        let ct = [
            0x98, 0xe7, 0x24, 0x7c, 0x07, 0xf0, 0xfe, 0x41, 0x1c, 0x26, 0x7e, 0x43, 0x84, 0xb0,
            0xf6, 0x00,
        ];
        let expected = [
            0x2f, 0xf5, 0x8d, 0x80, 0x03, 0x39, 0x27, 0xab, 0x8e, 0xf4, 0xd4, 0x58, 0x75, 0x14,
            0xf0, 0xfb,
        ];

        // Alternative.
        let mut ghash2 = GHash::new_with_init_block(&hash_key.into(), 0);
        let ga_data = GenericArray::from_slice(&ct);
        ghash2.update(&[*ga_data]);
        let result2 = ghash2.finalize();

        println!("GHASH NEW result: {:?}", hex::encode(result.as_slice()));
        println!("GHASH OLD result: {:?}", hex::encode(result2.as_slice()));
        println!("expected: {:?}", hex::encode(expected));
    }
}
