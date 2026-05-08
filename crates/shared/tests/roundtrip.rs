use kg_shared::{
    aes256_cbc_decrypt, aes256_cbc_encrypt, crc32, generate_license, is_license_expired,
    pbkdf2_hmac_sha1_32, sha1, validate_license, LicenseInfo, LicenseType,
};
use kg_shared::hash::md5;

#[test]
fn aes_roundtrip_short() {
    let key = [0x42u8; 32];
    let plain = b"Hello, World!";
    let cipher = aes256_cbc_encrypt(plain, &key);
    let decrypted = aes256_cbc_decrypt(&cipher, &key);
    assert_eq!(decrypted, plain);
}

#[test]
fn aes_roundtrip_block_aligned() {
    let key = [0x33u8; 32];
    let plain = vec![0xAA; 64];
    let cipher = aes256_cbc_encrypt(&plain, &key);
    let decrypted = aes256_cbc_decrypt(&cipher, &key);
    assert_eq!(decrypted, plain);
}

#[test]
fn aes_roundtrip_large() {
    let key = [0x77u8; 32];
    let mut plain = Vec::with_capacity(8192);
    for i in 0..8192 {
        plain.push(((i * 7) & 0xFF) as u8);
    }
    let cipher = aes256_cbc_encrypt(&plain, &key);
    let decrypted = aes256_cbc_decrypt(&cipher, &key);
    assert_eq!(decrypted, plain);
}

#[test]
fn aes_wrong_key_fails() {
    let key1 = [0x11u8; 32];
    let key2 = [0x22u8; 32];
    let plain = b"secret message";
    let cipher = aes256_cbc_encrypt(plain, &key1);
    let decrypted = aes256_cbc_decrypt(&cipher, &key2);
    assert_ne!(decrypted, plain);
}

#[test]
fn sha1_known_vector() {
    let h = sha1(b"abc");
    let expected: [u8; 20] = [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    ];
    assert_eq!(h, expected);
}

#[test]
fn sha1_empty() {
    let h = sha1(b"");
    let expected: [u8; 20] = [
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
        0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
    ];
    assert_eq!(h, expected);
}

#[test]
fn md5_known_vector() {
    let h = md5("abc");
    let expected: [u8; 16] = [
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
    ];
    assert_eq!(h, expected);
}

#[test]
fn md5_empty() {
    let h = md5("");
    let expected: [u8; 16] = [
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
    ];
    assert_eq!(h, expected);
}

#[test]
fn crc32_known_vector() {
    assert_eq!(crc32(b""), 0);
    assert_eq!(crc32(b"abc"), 0x352441C2);
    assert_eq!(crc32(b"123456789"), 0xCBF43926);
}

#[test]
fn pbkdf2_deterministic() {
    let k1 = pbkdf2_hmac_sha1_32("password", "myapp");
    let k2 = pbkdf2_hmac_sha1_32("password", "myapp");
    let k3 = pbkdf2_hmac_sha1_32("password", "MYAPP");
    assert_eq!(k1, k2);
    assert_eq!(k1, k3);
    let k4 = pbkdf2_hmac_sha1_32("Password", "myapp");
    assert_ne!(k1, k4);
}

#[test]
fn license_roundtrip_lifetime() {
    let hwid = "1234-5678-9ABC-DEF0";
    let enc_map = [0x55u8; 32];
    let info = LicenseInfo {
        kind: LicenseType::Lifetime,
        value: 0,
        year: 0,
        month: 0,
        day: 0,
    };
    let key = generate_license(hwid, &enc_map, &info);
    let parsed = validate_license(&key, hwid, &enc_map).expect("valid license");
    assert_eq!(parsed.kind, LicenseType::Lifetime);
    assert!(!is_license_expired(&parsed));
}

#[test]
fn license_roundtrip_days() {
    let hwid = "AAAA-BBBB-CCCC-DDDD";
    let enc_map = [0xA5u8; 32];
    let info = LicenseInfo {
        kind: LicenseType::Days,
        value: 30,
        year: 0,
        month: 0,
        day: 0,
    };
    let key = generate_license(hwid, &enc_map, &info);
    let parsed = validate_license(&key, hwid, &enc_map).expect("valid license");
    assert_eq!(parsed.kind, LicenseType::Days);
    assert_eq!(parsed.value, 30);
}

#[test]
fn license_roundtrip_months() {
    let hwid = "FFFF-EEEE-DDDD-CCCC";
    let enc_map = [0x42u8; 32];
    let info = LicenseInfo {
        kind: LicenseType::Months,
        value: 6,
        year: 0,
        month: 0,
        day: 0,
    };
    let key = generate_license(hwid, &enc_map, &info);
    let parsed = validate_license(&key, hwid, &enc_map).expect("valid license");
    assert_eq!(parsed.kind, LicenseType::Months);
    assert_eq!(parsed.value, 6);
}

#[test]
fn license_roundtrip_specific_date() {
    let hwid = "1111-2222-3333-4444";
    let enc_map = [0x99u8; 32];
    let info = LicenseInfo {
        kind: LicenseType::Date,
        value: 0,
        year: 2030,
        month: 6,
        day: 15,
    };
    let key = generate_license(hwid, &enc_map, &info);
    let parsed = validate_license(&key, hwid, &enc_map).expect("valid license");
    assert_eq!(parsed.kind, LicenseType::Date);
    assert_eq!(parsed.year, 2030);
    assert_eq!(parsed.month, 6);
    assert_eq!(parsed.day, 15);
    assert!(!is_license_expired(&parsed));
}

#[test]
fn license_wrong_hwid_fails() {
    let enc_map = [0x55u8; 32];
    let info = LicenseInfo {
        kind: LicenseType::Lifetime,
        value: 0,
        year: 0,
        month: 0,
        day: 0,
    };
    let key = generate_license("ABCD-1234-EF56-7890", &enc_map, &info);
    let result = validate_license(&key, "0000-0000-0000-0000", &enc_map);
    assert!(result.is_none(), "license must reject mismatched HWID");
}

#[test]
fn license_wrong_key_fails() {
    let hwid = "ABCD-1234-EF56-7890";
    let enc_map_a = [0x55u8; 32];
    let enc_map_b = [0xAAu8; 32];
    let info = LicenseInfo {
        kind: LicenseType::Lifetime,
        value: 0,
        year: 0,
        month: 0,
        day: 0,
    };
    let key = generate_license(hwid, &enc_map_a, &info);
    let result = validate_license(&key, hwid, &enc_map_b);
    assert!(result.is_none(), "license must reject mismatched encryption map");
}

#[test]
fn license_garbage_fails() {
    let enc_map = [0x55u8; 32];
    let result = validate_license("AAAAAAAA", "ABCD-1234-EF56-7890", &enc_map);
    assert!(result.is_none());
    let result = validate_license("", "ABCD-1234-EF56-7890", &enc_map);
    assert!(result.is_none());
}

#[test]
fn license_expired_in_past() {
    let info = LicenseInfo {
        kind: LicenseType::Date,
        value: 0,
        year: 2000,
        month: 1,
        day: 1,
    };
    assert!(is_license_expired(&info));
}

#[test]
fn license_lifetime_never_expires() {
    let info = LicenseInfo {
        kind: LicenseType::Lifetime,
        value: 0,
        year: 0,
        month: 0,
        day: 0,
    };
    assert!(!is_license_expired(&info));
}
