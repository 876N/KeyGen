use crate::hash::hmac_sha1;

pub fn pbkdf2_hmac_sha1_32(password: &str, app_name: &str) -> [u8; 32] {
    let mut combined = String::from(password);
    combined.push('|');
    for c in app_name.chars() {
        if c.is_ascii_lowercase() {
            combined.push((c as u8 - 32) as char);
        } else {
            combined.push(c);
        }
    }
    let salt = b"KeyGenSalt2024!!";
    let pwd = combined.into_bytes();
    let iterations = 10000;
    let dk_len = 32usize;
    let mut result = Vec::<u8>::with_capacity(dk_len);
    let mut block_num: u32 = 1;
    while result.len() < dk_len {
        let mut u: Vec<u8> = salt.to_vec();
        u.push(((block_num >> 24) & 0xFF) as u8);
        u.push(((block_num >> 16) & 0xFF) as u8);
        u.push(((block_num >> 8) & 0xFF) as u8);
        u.push((block_num & 0xFF) as u8);
        let mut u_arr = hmac_sha1(&pwd, &u);
        let mut t = u_arr;
        for _ in 1..iterations {
            u_arr = hmac_sha1(&pwd, &u_arr);
            for j in 0..t.len() {
                t[j] ^= u_arr[j];
            }
        }
        result.extend_from_slice(&t);
        block_num += 1;
    }
    result.truncate(dk_len);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
