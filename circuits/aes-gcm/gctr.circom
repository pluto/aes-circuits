pragma circom 2.1.9;
include "aes/cipher.circom";
include "utils.circom";
// GCTR Process to be used in AES-GCM as in https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
//
//            ┌───────────┐           inc           ┌───────────┐
//            │    ICB    │ ──────────────────────▶ │    CB2    │
//            └───────────┘                         └───────────┘
//                  │                                      │
//                  ▼                                      ▼
//            ┌──────────┐                           ┌──────────┐
//            │  CIPH_K  │                           │  CIPH_K  │
//            └──────────┘                           └──────────┘
//                  │                                      │
//                  ▼                                      ▼
//             ┌──────────┐                           ┌──────────┐
//             │    X1    │                           │     X2   │
//             └──────────┘                           └──────────┘
//                   │                                      │
//                   ▼                                      ▼
//                  XOR                                   XOR
//                   │                                      │
//                   ▼                                      ▼
//               ┌──────┐                                ┌──────┐
//               │  Y1  │                                │  Y2  │
//               └──────┘                                └──────┘
//                   │                                       │
//                   ▼                                       ▼
//
// GCTR_K (ICB, X1 || X2 || ... || X_n*) = Y1 || Y2 || ... || Y_n*.


// We are opperating on 128 bit blocks represented as 16 bytes
template GCTR(INPUT_LEN) {
    signal input key[16];
    signal input initialCounterBlock[4][4];
    signal input plainText[INPUT_LEN];
    signal output cipherText[INPUT_LEN];

    // number of 16 byte blocks in the plaintext
    var nBlocks = (INPUT_LEN \ 16); // "\" is floored integer division
    // size of the last block
    var lastBlockSize = INPUT_LEN % 16;
    // total number of bits in the plaintext blocks
    var bytesExcludingLastBlock = 16 * (nBlocks);
    assert(INPUT_LEN == nBlocks * 16 + lastBlockSize);

    // generate plaintext blocks
    // note to not use the last block of plaintext
    // because it will be padded by the toBlocks components
    component plainTextBlocks = ToBlocks(INPUT_LEN);
    plainTextBlocks.stream <== plainText;

    // Step 1: Generate counter blocks
    signal CounterBlocks[nBlocks + 1][4][4];
    CounterBlocks[0] <== initialCounterBlock;

    // First counter block is passed in, as a combination of the IV right padded with zeros IV is 96 bits or 12 bytes
    // The next counter needs to be set by incrementing the right most 32 bits (4 bytes) of the previous counter block
    //
    // component to increment the last word of the counter block
    component inc32[nBlocks];
    // For i = 2 to nBlocks, let CBi = inc32(CBi-1).

    for (var i = 1; i < nBlocks + 1; i++) {
        inc32[i - 1] = IncrementWord();
        inc32[i - 1].in <== CounterBlocks[i - 1][3];

        // copy the previous 12 bytes of the counter block
        for (var j = 0; j < 3; j++) {
            CounterBlocks[i][j] <== CounterBlocks[i - 1][j];
        }
        // write the last 4 bytes of the incremented word
        CounterBlocks[i][3] <== inc32[i - 1].out;
    }

    // Convert blocks of 16 bytes to stream
    component toStream = ToStream(nBlocks, bytesExcludingLastBlock);
    // Step 2: Encrypt each counter block with the key
    component aes[nBlocks+1]; // +1 for the last block
    component AddCipher[nBlocks];

    // NOTE: All this code does for one block is encrypt and xor, 
    // which is identical to CTR. 
    for (var i = 0; i < nBlocks; i++) {
        // encrypt counter block
        aes[i] = Cipher();
        aes[i].key <== key;
        aes[i].block <== CounterBlocks[i];

        // XOR cipher text with input block
        AddCipher[i] = AddCipher();    
        AddCipher[i].state <== plainTextBlocks.blocks[i];
        AddCipher[i].cipher <== aes[i].cipher;

        // set output block
        toStream.blocks[i] <== AddCipher[i].newState;
    }

    // Step 3: Handle the last block separately
    // Y* = X* ⊕ MSBlen(X*) (CIPH_K (CB_n*))

    // encrypt the last counter block 
    aes[nBlocks] = Cipher();
    aes[nBlocks].key <== key;
    aes[nBlocks].block <== CounterBlocks[nBlocks];
    component aesCipherToStream = ToStream(1, 16);
    aesCipherToStream.blocks[0] <== aes[nBlocks].cipher;

    // XOR the cipher with the last chunk of unpadded plaintext
    if (lastBlockSize != 0) {
        component addLastCipher = XorMultiple(2, lastBlockSize);
        for (var i = 0; i < lastBlockSize; i++) {
            // convert cipher to stream
            addLastCipher.inputs[0][i] <== aesCipherToStream.stream[i];
            addLastCipher.inputs[1][i] <== plainText[bytesExcludingLastBlock + i];
        }
        for (var i = 0; i < lastBlockSize; i++) {
            cipherText[bytesExcludingLastBlock + i] <== addLastCipher.out[i];
        }
    }

    for (var i = 0; i < bytesExcludingLastBlock; i++) {
        cipherText[i] <== toStream.stream[i];
    }

}
