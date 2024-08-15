pragma circom 2.1.9;

// include "circomlib/circuits/gates.circom";
include "helper_functions.circom";


// // Multiplies `in` by x in GF(2^128) defined by the 
// // ghash irreducible polynomial x^128 + x^7 + x^2 + x + 1
// template ghash_GFMULX() {
//     var size = 128;

//     signal input in[size];
//     signal output out[size];
//     signal temp[size];


//     // Get the most significant bit of the input signal
//     var msb;
//     msb = in[0]; /// [>1<,0,0,0,0,0,0,0]

//     // Left shift input by 1 into temp
//     for (var i = 0; i < size - 1; i++) {
//         temp[i] <== in[i+1];
//     }
//     temp[size - 1] <== 0;

//     component xor1 = XOR();
//     component xor2 = XOR();
//     component xor3 = XOR();
//     component xor4 = XOR();

//     // x^128 = x^7 + x^2 + x + 1
//     // XOR the input with msb * (x^7 + x^2 + x + 1)
//     for (var i = 0; i < size; i++) {
//         if (i == size - 1) {
//             // x^0 term
//             xor1.a <== temp[i];
//             xor1.b <== msb;
//             out[i] <== xor1.out;
//         } else if (i == size - 2) {
//             // x^1 term
//             xor2.a <== temp[i];
//             xor2.b <== msb;
//             out[i] <== xor2.out;
//         } else if (i == size - 3) {
//             // x^2 term
//             xor3.a <== temp[i];
//             xor3.b <== msb;
//             out[i] <== xor3.out;
//         } else if (i == size - 8) {
//             // x^7 term
//             xor4.a <== temp[i];
//             xor4.b <== msb;
//             out[i] <== xor4.out;
//         } 
//     }   
// }

// compute x * `in` over ghash polynomial
// ghash irreducible polynomial x^128 + x^7 + x^2 + x + 1
//
// spec: 
// https://tools.ietf.org/html/rfc8452#appendix-A
//
// rust-crypto reference implementation: todo
template ghash_GFMULX() {
    var block = 128;
    signal input in[block];
    signal output out[block];

    // v = in left-shifted by 1
    signal v[block];
    // v_xor = 0 if in[0] is 0, or the irreducible poly if in[0] is 1
    signal v_xor[block];

    // initialize v and v_xor. 
    v[block - 1] <== 0;
    v_xor[block - 1] <== in[0];

    for (var i=126; i>=0; i--) {
        v[i] <== in[i+1];

        // XOR with polynomial if MSB is 1
        // v_xor has 1s at positions 127, 126, 121, 1
        if (i==0 || i == 121 || i == 126) {
            v_xor[i] <== in[0];
        } else {
            v_xor[i] <== 0;
        }
    }

    // compute out
    component xor = BitwiseXor(block);
    xor.a <== v;
    xor.b <== v_xor;
    out <== xor.out;
}

// compute x * `in` over polyval polynomial
// polyval irreducible polynomial x^128 + x^127 + x^126 + x^121 + 1
//
// spec: 
// https://tools.ietf.org/html/rfc8452#appendix-A
//
// rust-crypto reference implementation: 
// https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/mulx.rs#L11
template polyval_GFMULX() {
    var block = 128;
    signal input in[block];
    signal output out[block];

    // v = in << 1; 
    signal v[block];
    // if `in` MSB set, assign irreducible poly bits, otherwise zero
    signal irreducible_poly[block];
    var msb = in[0]; // endianness: 0 in polyval, 127(?) in ghash

    v[block - 1] <== 0;
    irreducible_poly[block - 1] <== msb;

    for (var i=126; i>=0; i--) {
        v[i] <== in[i+1];

        // XOR with polynomial if MSB is 1
        // irreducible_poly has 1s at positions 127, 126, 121, 1
        if (i==0 || i == 121 || i == 126) {
            irreducible_poly[i] <== in[0];
        } else {
            irreducible_poly[i] <== 0;
        }
    }

    // compute out
    component xor = BitwiseXor(block);
    xor.a <== v;
    xor.b <== irreducible_poly;
    out <== xor.out;
}