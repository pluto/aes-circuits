import { assert } from "chai";
import { WitnessTester } from "circomkit";
import { circomkit, hexBytesToBigInt, hexToBytes } from "../common";

describe("aes-gcm-general", () => {
  let circuit: WitnessTester<["key", "iv", "plainText", "aad"], ["cipherText", "authTag"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester(`aes-gcm-general`, {
      file: "aes-gcm/aes-gcm-general",
      template: "AESGCMGENERAL",
      params: [16, 16],
    });
  });

  it("should have correct output", async () => {
    let key = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let plainText = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let HashKey = [0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e];
    let aad = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let expected_output = [0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78];

    const witness = await circuit.compute({ key: key, iv: iv, plainText: plainText, aad: aad }, ["cipherText", "authTag"])

    assert.deepEqual(witness.cipherText, hexBytesToBigInt(expected_output))
  });

  it("should work for self generated test case", async () => {
    let circuit_one_block: WitnessTester<["key", "iv", "plainText", "aad"], ["cipherText", "authTag"]>;
    circuit_one_block = await circomkit.WitnessTester(`aes-gcm-general`, {
      file: "aes-gcm/aes-gcm-general",
      template: "AESGCMGENERAL",
      params: [16, 16],
    });

    const key = hexToBytes('31313131313131313131313131313131');
    const iv = hexToBytes('313131313131313131313131');
    const msg = hexToBytes('7465737468656c6c6f30303030303030');
    const aad = hexToBytes('00000000000000000000000000000000')
    const ct = hexToBytes('2929d2bb1ae94804402b8e776e0d3356');
    const auth_tag = hexToBytes('9a636f50dc842820c798d001d9a9c4bd');

    const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: msg, aad: aad }, ["cipherText", "authTag"])

    assert.deepEqual(witness.cipherText, hexBytesToBigInt(ct))
    assert.deepEqual(witness.authTag, hexBytesToBigInt(auth_tag));
  });

  it("should work for multiple blocks", async () => {
    let circuit_one_block: WitnessTester<["key", "iv", "plainText", "aad"], ["cipherText", "authTag"]>;
    circuit_one_block = await circomkit.WitnessTester(`aes-gcm-general`, {
      file: "aes-gcm/aes-gcm-general",
      template: "AESGCMGENERAL",
      params: [16, 32],
    });

    const key = hexToBytes('31313131313131313131313131313131');
    const iv = hexToBytes('313131313131313131313131');
    const msg = hexToBytes('7465737468656c6c6f303030303030307465737468656c6c6f30303030303030');
    const aad = hexToBytes('00000000000000000000000000000000')
    const ct = hexToBytes('2929d2bb1ae94804402b8e776e0d335626756530713e4c065af1d3c4f56e0204');
    const auth_tag = hexToBytes('d54d14668b92ce3e5b13880067df54d6');

    const witness = await circuit_one_block.compute({ key: key, iv: iv, plainText: msg, aad: aad }, ["cipherText", "authTag"])

    assert.deepEqual(witness.cipherText, hexBytesToBigInt(ct))
    assert.deepEqual(witness.authTag, hexBytesToBigInt(auth_tag));
  });

  it("should work for arbitrary length of aad and plaintext", async () => {
    let circuit_multiblock: WitnessTester<["key", "iv", "plainText", "aad"], ["cipherText", "authTag"]>;
    circuit_multiblock = await circomkit.WitnessTester(`aes-gcm-general`, {
      file: "aes-gcm/aes-gcm-general",
      template: "AESGCMGENERAL",
      params: [20, 40],
    });

    const key      = hexToBytes('0102030405060708090a0b0c0d0e0f10');
    const iv       = hexToBytes('102030405060708090a0b0c0');
    const msg      = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728');
    const aad      = hexToBytes('0102030405060708090a0b0c0d0e0f1011121314');
    const ct       = hexToBytes('e8a37cd1b913dfc89a3c469f2b8d6fc5dea1f7a17b3f2bece8e0179414e9209f817e848bde94e2a8');
    const auth_tag = hexToBytes('dec66aa48b49c2d1801c16aa3bdf9c29');

    const witness    = await circuit_multiblock.compute({key: key, iv: iv, plainText: msg, aad: aad}, ["cipherText", "authTag"]);
    const cipherText = witness.cipherText.toString();
    const ct_str     = ct.toString();

    assert.deepEqual(cipherText.slice(0, ct_str.length), ct_str);
    assert.deepEqual(witness.authTag, hexBytesToBigInt(auth_tag));
  })
});

// signal input key[16]; // 128-bit key
// signal input iv[12]; // IV length is 96 bits (12 bytes)
// signal input plainText[l];
// signal input additionalData[16]; // AAD length is 128 bits (16 bytes)

// K = 00000000000000000000000000000000
// P = 00000000000000000000000000000000
// IV = 000000000000000000000000
// H = 66e94bd4ef8a2c3b884cfa59ca342b2e
// Y0 = 00000000000000000000000000000001                                58E2FCCEFA7E3061367F1D57A4E7455A
// E(K, Y0) = 58e2fccefa7e3061367f1d57a4e7455a ==> This is our output?? 58E2FCCEFA7E3061367F1D57A4E7455A
// Y1 = 00000000000000000000000000000002
// E(K, Y1) = 0388dace60b6a392f328c2b971b2fe78
// X1 = 5e2ec746917062882c85b0685353deb7
// len(A)||len(C) = 00000000000000000000000000000080
// GHASH(H, A, C) = f38cbb1ad69223dcc3457ae5b6b0f885
// C = 0388dace60b6a392f328c2b971b2fe78
// T = ab6e47d42cec13bdf53a67b21257bddf