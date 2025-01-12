pub use aes128_rdx_fhe::aes_fhe::{
    enc_rdx_vec, gen_rdx_keys, print_hex_rdx_fhe,
};
pub use aes128_rdx_fhe::aes128_keyschedule::key_expansion;
pub use aes128_rdx_fhe::aes128_rdx_fhe::{
    decrypt_block_fhe, encrypt_block_fhe, sub_bytes_fhe,
};
pub use aes128_rdx_fhe::aes128_tables::{GMUL2, GMUL3, SBOX, gen_tbl};

use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::shortint::Ciphertext;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

use rand::RngCore;
use rand::rngs::OsRng;
use std::time::Instant;

pub struct KeyTest {
    pub key: &'static [u8],
    pub enc: &'static [u8],
}

pub const KEY_TESTS: &[KeyTest] = &[KeyTest {
    key: &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ],
    enc: &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab,
        0x76, 0xfe, 0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68,
        0x30, 0xb3, 0xfe, 0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf,
        0x04, 0x69, 0xbf, 0x41, 0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03, 0xf9, 0x6c, 0x32,
        0xbc, 0xfd, 0x05, 0x8d, 0xfd, 0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb, 0x50, 0xf3,
        0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa, 0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96, 0xa7,
        0x55, 0x3d, 0xc1, 0x0a, 0xa3, 0x1f, 0x6b, 0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c,
        0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26, 0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65,
        0xb9, 0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2, 0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85,
        0x57, 0x68, 0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e, 0x13, 0x11, 0x1d, 0x7f, 0xe3,
        0x94, 0x4a, 0x17, 0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5,
    ],
}];

#[cfg(test)]
mod tests {
    use aes128_rdx_fhe::aes_fhe::NUM_BLOCK;

    use super::*;

    #[test]
    fn test_key_expansion() {
        for (i, test) in KEY_TESTS.iter().enumerate() {
            let key: &[u8; 16] = test
                .key
                .try_into()
                .expect("Key must be 128 bits (16 bytes)");
            let xk = key_expansion(key);

            for (j, &v) in xk.iter().enumerate() {
                assert_eq!(
                    v, test.enc[j],
                    "key {}: enc[{}] = {:#x}, want {:#x}",
                    i, j, v, test.enc[j]
                );
            }
        }
    }

    #[test]
    fn test_encrypt_block_tfhe1() {
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let expected_ciphertext: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let xk = key_expansion(&key);

        let mut dst = [0u8; 16];
        encrypt_block_fhe(&plaintext, &xk, &mut dst, 1);

        assert_eq!(
            dst, expected_ciphertext,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected_ciphertext, dst
        );
    }

    #[test]
    fn test_decrypt_block_tfhe1() {
        let ciphertext: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let expected_plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        let xk = key_expansion(&key);

        let mut dst = [0u8; 16];
        decrypt_block_fhe(&ciphertext, &xk, &mut dst, 1);

        assert_eq!(
            dst, expected_plaintext,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected_plaintext, dst
        );
    }

    #[test]
    fn test_encrypt_block_tfhe2() {
        let plaintext: [u8; 16] = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];
        let key: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let expected_ciphertext: [u8; 16] = [
            0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66,
            0xEF, 0x97,
        ];

        let xk = key_expansion(&key);

        let mut dst = [0u8; 16];
        encrypt_block_fhe(&plaintext, &xk, &mut dst, 1);

        assert_eq!(
            dst, expected_ciphertext,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected_ciphertext, dst
        );
    }

    #[test]
    fn test_decrypt_block_tfhe2() {
        let ciphertext: [u8; 16] = [
            0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66,
            0xEF, 0x97,
        ];
        let key: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let expected_plaintext: [u8; 16] = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];

        let xk = key_expansion(&key);

        let mut dst = [0u8; 16];
        decrypt_block_fhe(&ciphertext, &xk, &mut dst, 1);

        assert_eq!(
            dst, expected_plaintext,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected_plaintext, dst
        );
    }

    #[test]
    fn test_encrypt_decrypt_rnd_block() {
        let mut key = [0u8; 16];
        OsRng.fill_bytes(&mut key);

        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);

        let mut expected = GenericArray::from(iv);
        let cipher = Aes128::new(&GenericArray::from(key));
        cipher.encrypt_block(&mut expected);

        let xk = key_expansion(&key);
        let mut dst = [0u8; 16];
        encrypt_block_fhe(&iv, &xk, &mut dst, 1);

        assert_eq!(
            GenericArray::from(dst),
            expected,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected,
            dst
        );

        let mut out = [0u8; 16];
        decrypt_block_fhe(&dst, &xk, &mut out, 1);

        assert_eq!(
            out, iv,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected, out
        );
    }

    #[test]
    fn test_match_value_sbox_tfhe() {
        let (ck, sk) = gen_rdx_keys();
        let sbox_tbl = gen_tbl(&SBOX);

        let state = vec![0xff, 0x0f, 0x00]; // byte to rdx
        let mut state_ck = enc_rdx_vec(&state, &ck);
        print_hex_rdx_fhe("state_ck      ", 0, &state_ck, &ck);

        sub_bytes_fhe(&mut state_ck, &sbox_tbl, &sk);
        print_hex_rdx_fhe("sbox match value", 0, &state_ck, &ck);

        assert_eq!(ck.decrypt::<u8>(&state_ck[0]), 0x16);

        assert_eq!(ck.decrypt::<u8>(&state_ck[1]), 0x76);

        assert_eq!(ck.decrypt::<u8>(&state_ck[2]), 0x63);
    }

    #[test]
    fn test_match_value_lookup_gmul2_tfhe() {
        println!("gmul2 {:?}", GMUL2);

        let (ck, sk) = gen_rdx_keys();
        let lut_tbl = gen_tbl(&GMUL2);

        let state = vec![0xff, 0x0f, 0x00]; // byte to rdx
        let mut state_ck = enc_rdx_vec(&state, &ck);
        print_hex_rdx_fhe("state_ck      ", 0, &state_ck, &ck);

        sub_bytes_fhe(&mut state_ck, &lut_tbl, &sk);
        print_hex_rdx_fhe("gmul2 match value", 0, &state_ck, &ck);

        assert_eq!(ck.decrypt::<u8>(&state_ck[0]), 0x0e5);

        assert_eq!(ck.decrypt::<u8>(&state_ck[1]), 0x01e);

        assert_eq!(ck.decrypt::<u8>(&state_ck[2]), 0);
    }

    #[test]
    fn test_match_value_lookup_gmul3_tfhe() {
        println!("gmul3 {:?}", GMUL3);

        let (ck, sk) = gen_rdx_keys();
        let lut_tbl = gen_tbl(&GMUL3);

        let state = vec![0xff, 0x0f, 0x00]; // byte to rdx
        let mut state_ck = enc_rdx_vec(&state, &ck);
        print_hex_rdx_fhe("state_ck      ", 0, &state_ck, &ck);

        sub_bytes_fhe(&mut state_ck, &lut_tbl, &sk);
        print_hex_rdx_fhe("gmul3 match value", 0, &state_ck, &ck);

        assert_eq!(ck.decrypt::<u8>(&state_ck[0]), 0x01a);

        assert_eq!(ck.decrypt::<u8>(&state_ck[1]), 0x011);

        assert_eq!(ck.decrypt::<u8>(&state_ck[2]), 0);
    }

    #[test]
    fn test_perf_rdx_xor() {
        let (ck, sk) = gen_rdx_keys();

        let state = vec![0xfe, 0xff]; // byte to rdx
        let mut state_ck = enc_rdx_vec(&state, &ck);
        print_hex_rdx_fhe("state_ck      ", 0, &state_ck, &ck);

        let start = Instant::now();
        for _ in 1..10 {
            let tmp = state_ck.to_vec();
            state_ck[1] = sk.unchecked_bitxor(&tmp[0], &tmp[1]);
            state_ck[0] = sk.unchecked_bitxor(&tmp[1], &tmp[0]);
            print_hex_rdx_fhe("rdx bitxor", 0, &state_ck, &ck);
        }
        println!(
            "test_perf_rdx_xor {:.?}",
            start.elapsed().checked_div(2 * 10)
        );

        print_hex_rdx_fhe("rdx bitxor", 0, &state_ck, &ck);
    }

    // https://github.com/zama-ai/tfhe-rs/issues/816
    // https://doc.rust-lang.org/stable/std/array/fn.from_fn.html
    #[test]
    fn test_init_arr_ciphertext() {
        let (ck, sk) = gen_rdx_keys();

        let start = Instant::now();
        let state_ck: [BaseRadixCiphertext<Ciphertext>; 16] = core::array::from_fn(|_| sk.create_trivial_radix(0, NUM_BLOCK));
        println!(
            "test_init_arr_ciphertext  {:.?}",
            start.elapsed()
        );
        assert!(state_ck.len() == 16);

        print_hex_rdx_fhe("init arr ciphertext", 0, &state_ck.to_vec(), &ck);
    }

    #[test]
    fn test_init_vec_ciphertext() {
        let (ck, sk) = gen_rdx_keys();

        let start = Instant::now();
        let state_ck: Vec<BaseRadixCiphertext<Ciphertext>> = (0..16)
        .map(|_| sk.create_trivial_radix(0, NUM_BLOCK))
        .collect();

        println!(
            "test_init_vec_ciphertext  {:.?}",
            start.elapsed()
        );
        assert!(state_ck.len() == 16);

        print_hex_rdx_fhe("init vec ciphertext", 0, &state_ck, &ck);
    }
}
