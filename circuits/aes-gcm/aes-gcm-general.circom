pragma circom 2.1.9;

include "ghash.circom";
include "aes/cipher.circom";
include "utils.circom";
include "gctr.circom";


/// AES-GCM with 128 bit key authenticated encryption according to: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
///
/// Parameters:
/// _al: length of aad
/// _cl: length of the plaintext
///
/// Inputs:
/// key: 128-bit key
/// iv: initialization vector
/// plainText: plaintext to be encrypted
/// aad: additional data to be authenticated
///
/// Outputs:
/// cipherText: encrypted ciphertext
/// authTag: authentication tag
///
template AESGCMGENERAL(_al, _cl) {
    // Inputs
    signal input key[16]; // 128-bit key
    signal input iv[12]; // IV length is 96 bits (12 bytes)
    signal input plainText[_cl];
    signal input aad[_al]; // AAD length is 128 bits (16 bytes)

    // Outputs
    signal output cipherText[_cl];
    signal output authTag[16]; //   Authentication tag length is 128 bits (16 bytes)
    
    var al = _al;
    if (al % 16 > 0) {
        al += 16 - al % 16;
    }

    var cl = _cl;
    if (cl % 16 > 0) {
        cl += 16 - cl % 16;
    }

    signal _plainText[cl];
    signal _aad[al];

    for (var i = 0; i < _cl; i++) {
        _plainText[i] <== plainText[i];
    }

    for (var i = _cl; i < cl; i++) {
        _plainText[i] <== 0;
    }

    for (var i = 0; i < _al; i++) {
        _aad[i] <== aad[i];
    }

    for (var i = _al; i < al; i++) {
        _aad[i] <== 0;
    }

    component zeroBlock = ToBlocks(16);
    for (var i = 0; i < 16; i++) {
        zeroBlock.stream[i] <== 0;
    }

    // Step 1: Let H = aes(key, zeroBlock)
    component cipherH = Cipher();
    cipherH.key <== key;
    cipherH.block <== zeroBlock.blocks[0];

    // Step 2: Define a block, J0 with 96 bits of iv and 32 bits of 0s
    component J0builder = ToBlocks(16);
    for (var i = 0; i < 12; i++) {
        J0builder.stream[i] <== iv[i];
    }
    for (var i = 12; i < 16; i++) {
        J0builder.stream[i] <== 0;
    }
    component J0WordIncrementer = IncrementWord();
    J0WordIncrementer.in <== J0builder.blocks[0][3];

    component J0WordIncrementer2 = IncrementWord();
    J0WordIncrementer2.in <== J0WordIncrementer.out;

    signal J0[4][4];
    for (var i = 0; i < 3; i++) {
        J0[i] <== J0builder.blocks[0][i];
    }
    J0[3] <== J0WordIncrementer2.out;

    // Step 3: Let C = GCTRK(inc32(J0), P)
    component gctr = GCTR(cl);
    gctr.key <== key;
    gctr.initialCounterBlock <== J0;
    gctr.plainText <== _plainText;

    // Step 4: Let u and v (v is always zero with out key size and aad length)
    var cBlockCount = cl \ 16;
    var aBlockCount = al \ 16;
    // so the reason there is a plus two is because 
    // the first block is the aad 
    // the second is the ciphertext
    // the last is the length of the aad and ciphertext
    // i.e. S = GHASHH (A || C || [len(A)] || [len(C)]). <- which is always 48 bytes: 3 blocks
    var ghashblocks = aBlockCount + cBlockCount + 1; 
    signal ghashMessage[ghashblocks][4][4];

    // set aad as first block
    component additionalBlocks = ToBlocks(al);
    additionalBlocks.stream <== _aad;

    for (var i=0; i<aBlockCount; i++) {
        ghashMessage[i] <== additionalBlocks.blocks[i];
    }

    // set cipher text block padded
    component ciphertextBlocks = ToBlocks(cl);
    ciphertextBlocks.stream <== gctr.cipherText;

    for (var i=0; i<cBlockCount-1; i++) {
        ghashMessage[i+aBlockCount] <== ciphertextBlocks.blocks[i];
    }

    var lastBlockLen = _cl % 16;
    if (lastBlockLen == 0) {
        lastBlockLen = 16;
    }

    for  (var i = 0; i < lastBlockLen; i++) {
        ghashMessage[aBlockCount+cBlockCount-1][i%4][i\4] <== ciphertextBlocks.blocks[cBlockCount-1][i%4][i\4];
    }

    // if padding zero in plaintext, it should still be zero in ghash msg
    if (_cl % 16 > 0) {
        for (var i = 0; i < 16 - _cl % 16; i++) {
            ghashMessage[aBlockCount+cBlockCount-1][3-i%4][3-i\4] <== 0;
        }
    }

    // length of aad
    var a_len = _al * 8;
    for (var i=0; i<8; i++) {
        var byte_value = 0;
        for (var j=0; j<8; j++) {
            byte_value *= 2;
            byte_value += (a_len >> ((7-i)*8+(7-j))) & 1;
        }
        ghashMessage[ghashblocks-1][i%4][i\4] <== byte_value;
    }

    var c_len = _cl * 8;
    for (var i=0; i<8; i++) {
        var byte_value = 0;
        for (var j=0; j<8; j++) {
            byte_value *= 2;
            byte_value += (c_len >> (7-i)*8+(7-j)) & 1;
        }
        ghashMessage[ghashblocks-1][i%4][i\4+2] <== byte_value;
    }

    // Step 5: Define a block, S
    // needs to take in the number of blocks
    component ghash = GHASH(ghashblocks);
    component hashKeyToStream = ToStream(1, 16);
    hashKeyToStream.blocks[0] <== cipherH.cipher;
    ghash.HashKey <== hashKeyToStream.stream;
    // S = GHASHH (A || 0^v || C || 0^u || [len(A)] || [len(C)]).
    component selectedBlocksToStream[ghashblocks];
    for (var i = 0 ; i<ghashblocks ; i++) {
        ghash.msg[i] <== ToStream(1, 16)([ghashMessage[i]]);
    }

    // signal bytes[16];
    // ghash_tag <== ghash.tag;
    // signal tagBytes[16 * 8] <== BytesToBits(16)(ghash.tag);
    // for(var i = 0; i < 16; i++) {
    //     var byteValue = 0;
    //     var sum=1;
    //     for(var j = 0; j<8; j++) {
    //         var bitIndex = i*8+j;
    //         byteValue += tagBytes[bitIndex]*sum;
    //         sum = sum*sum;
    //     }
    //     bytes[i] <== byteValue;
    // }

    // pre step 6: restore the g0
    component g0builder = ToBlocks(16);
    for (var i = 0; i < 12; i++) {
        g0builder.stream[i] <== iv[i];
    }
    for (var i = 12; i < 16; i++) {
        g0builder.stream[i] <== 0;
    }
    component g0WordIncrementer = IncrementWord();
    g0WordIncrementer.in <== g0builder.blocks[0][3];

    signal g0[4][4];
    for (var i = 0; i < 3; i++) {
        g0[i] <== g0builder.blocks[0][i];
    }
    g0[3] <== g0WordIncrementer.out;

    // Step 6: Let T = MSBt(GCTRK(J0, S))
    component gctrT = GCTR(16);
    gctrT.key <== key;
    // gctrT.initialCounterBlock <== J0;
    gctrT.initialCounterBlock <== g0;
    // gctrT.plainText <== bytes;
    gctrT.plainText <== ghash.tag;

    authTag <== gctrT.cipherText;

    for (var i = 0; i < _cl; i++) {
        cipherText[i] <== gctr.cipherText[i];
    }
    // cipherText <== gctr.cipherText;
}