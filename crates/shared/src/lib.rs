#![allow(
    clippy::identity_op,
    clippy::needless_range_loop,
    clippy::missing_safety_doc,
    clippy::manual_rotate,
    clippy::manual_is_multiple_of,
    clippy::manual_swap,
    clippy::unnecessary_cast
)]

pub mod aes;
pub mod config;
pub mod hash;
pub mod kdf;
pub mod license;
pub mod random;

pub use aes::{aes256_cbc_decrypt, aes256_cbc_encrypt};
pub use config::{ConfigData, CONFIG_DATA_SIZE, CONFIG_MARKER};
pub use hash::sha1;
pub use kdf::pbkdf2_hmac_sha1_32;
pub use license::{
    decode_from_key, encode_to_key, generate_license, is_license_expired, validate_license,
    LicenseInfo, LicenseType,
};
pub use random::secure_random;

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
}

pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
}
