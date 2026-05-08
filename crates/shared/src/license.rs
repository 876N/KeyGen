use crate::hash::sha1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LicenseType {
    Days = 1,
    Months = 2,
    Date = 3,
    Lifetime = 4,
}

impl LicenseType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Days),
            2 => Some(Self::Months),
            3 => Some(Self::Date),
            4 => Some(Self::Lifetime),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LicenseInfo {
    pub kind: LicenseType,
    pub value: i32,
    pub year: i32,
    pub month: i32,
    pub day: i32,
}

impl Default for LicenseInfo {
    fn default() -> Self {
        Self {
            kind: LicenseType::Lifetime,
            value: 0,
            year: 0,
            month: 0,
            day: 0,
        }
    }
}

pub fn complex_math(input: u64, key: u64) -> u64 {
    let mut result = input;
    result ^= key;
    result = result.rotate_left(17);
    result ^= 0xA5A5A5A5A5A5A5A5u64;
    result = result.rotate_left(31);
    result ^= key;
    result ^= 0x5555555555555555u64;
    for i in 0..8u32 {
        let left = result >> 32;
        let right = result & 0xFFFFFFFFu64;
        let f = ((right.wrapping_mul(0x85EBCA6Bu64)) ^ (key >> i))
            .wrapping_add((i as u64).wrapping_mul(0x1337u64));
        let new_left = left ^ (f & 0xFFFFFFFFu64);
        result = (right << 32) | (new_left & 0xFFFFFFFFu64);
    }
    result
}

pub fn reverse_complex_math(input: u64, key: u64) -> u64 {
    let mut result = input;
    for i in (0..8u32).rev() {
        let right = result >> 32;
        let left = result & 0xFFFFFFFFu64;
        let f = ((right.wrapping_mul(0x85EBCA6Bu64)) ^ (key >> i))
            .wrapping_add((i as u64).wrapping_mul(0x1337u64));
        let new_left = left ^ (f & 0xFFFFFFFFu64);
        result = (new_left << 32) | (right & 0xFFFFFFFFu64);
    }
    result ^= 0x5555555555555555u64;
    result ^= key;
    result = result.rotate_right(31);
    result ^= 0xA5A5A5A5A5A5A5A5u64;
    result = result.rotate_right(17);
    result ^= key;
    result
}

const ENC_CHARS: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode_to_key(data: &[u8]) -> String {
    let mut result = String::new();
    let mut acc: u64 = 0;
    let mut bits: i32 = 0;
    for &b in data {
        acc = (acc << 8) | (b as u64);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1F) as usize;
            result.push(ENC_CHARS[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((acc << (5 - bits)) & 0x1F) as usize;
        result.push(ENC_CHARS[idx] as char);
    }
    result
}

pub fn decode_from_key(key: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut acc: u64 = 0;
    let mut bits: i32 = 0;
    for raw in key.chars() {
        let c = if raw.is_ascii_lowercase() {
            (raw as u8 - 32) as char
        } else {
            raw
        };
        let mut val: i32 = -1;
        for j in 0..32 {
            if ENC_CHARS[j] as char == c {
                val = j as i32;
                break;
            }
        }
        if val < 0 {
            continue;
        }
        acc = (acc << 5) | (val as u64);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    result
}

fn clean_hwid(hwid: &str) -> String {
    hwid.chars().filter(|c| *c != '-' && *c != ' ').collect()
}

fn build_hash_input(hwid: &str, enc_map: &[u8]) -> Vec<u8> {
    let cleaned = clean_hwid(hwid);
    let mut buf: Vec<u8> = cleaned.into_bytes();
    buf.extend_from_slice(enc_map);
    buf
}

pub fn now_unix_seconds() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn generate_license(hwid: &str, enc_map: &[u8], info: &LicenseInfo) -> String {
    let hash_input = build_hash_input(hwid, enc_map);
    let hwid_hash = sha1(&hash_input);
    let mut master_key: u64 = 0;
    for i in 0..8 {
        master_key = (master_key << 8) | (hwid_hash[i] as u64);
    }

    let mut lic_data: Vec<u8> = Vec::new();
    lic_data.push(0x4B);
    lic_data.push(0x47);
    lic_data.push(info.kind as u8);
    match info.kind {
        LicenseType::Days | LicenseType::Months => {
            lic_data.push(((info.value >> 8) & 0xFF) as u8);
            lic_data.push((info.value & 0xFF) as u8);
            let now = now_unix_seconds();
            let created: u32 = (now / 86400) as u32;
            lic_data.push(((created >> 24) & 0xFF) as u8);
            lic_data.push(((created >> 16) & 0xFF) as u8);
            lic_data.push(((created >> 8) & 0xFF) as u8);
            lic_data.push((created & 0xFF) as u8);
        }
        LicenseType::Date => {
            lic_data.push(((info.year >> 8) & 0xFF) as u8);
            lic_data.push((info.year & 0xFF) as u8);
            lic_data.push((info.month & 0xFF) as u8);
            lic_data.push((info.day & 0xFF) as u8);
        }
        LicenseType::Lifetime => {
            lic_data.push(0xFF);
            lic_data.push(0xFF);
            lic_data.push(0xFF);
            lic_data.push(0xFF);
        }
    }
    for i in 0..4 {
        lic_data.push(hwid_hash[i + 8]);
    }
    let mut checksum: u8 = 0;
    for &b in &lic_data {
        checksum ^= b;
    }
    lic_data.push(checksum);
    while lic_data.len() % 8 != 0 {
        lic_data.push(0);
    }

    let mut encrypted: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < lic_data.len() {
        let mut block: u64 = 0;
        for j in 0..8 {
            if i + j < lic_data.len() {
                block = (block << 8) | (lic_data[i + j] as u64);
            }
        }
        let mut enc_block_v = complex_math(block, master_key);
        for j in 0..8 {
            enc_block_v ^= (enc_map[j % enc_map.len()] as u64) << (j * 8);
        }
        for j in (0..8).rev() {
            encrypted.push(((enc_block_v >> (j * 8)) & 0xFF) as u8);
        }
        i += 8;
    }

    encode_to_key(&encrypted)
}

pub fn validate_license(key: &str, hwid: &str, enc_map: &[u8]) -> Option<LicenseInfo> {
    let encrypted = decode_from_key(key);
    if encrypted.len() < 16 {
        return None;
    }
    let hash_input = build_hash_input(hwid, enc_map);
    let hwid_hash = sha1(&hash_input);
    let mut master_key: u64 = 0;
    for i in 0..8 {
        master_key = (master_key << 8) | (hwid_hash[i] as u64);
    }

    let mut decrypted: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < encrypted.len() {
        let mut block: u64 = 0;
        for j in 0..8 {
            if i + j < encrypted.len() {
                block = (block << 8) | (encrypted[i + j] as u64);
            }
        }
        for j in 0..8 {
            block ^= (enc_map[j % enc_map.len()] as u64) << (j * 8);
        }
        let dec_block_v = reverse_complex_math(block, master_key);
        for j in (0..8).rev() {
            decrypted.push(((dec_block_v >> (j * 8)) & 0xFF) as u8);
        }
        i += 8;
    }

    if decrypted.len() < 12 || decrypted[0] != 0x4B || decrypted[1] != 0x47 {
        return None;
    }
    let lic_type = LicenseType::from_u8(decrypted[2])?;
    let (hwid_start, checksum_pos) = match lic_type {
        LicenseType::Date | LicenseType::Lifetime => (7usize, 11usize),
        _ => (9usize, 13usize),
    };
    for i in 0..4 {
        if hwid_start + i >= decrypted.len() {
            return None;
        }
        if decrypted[hwid_start + i] != hwid_hash[i + 8] {
            return None;
        }
    }
    if checksum_pos >= decrypted.len() {
        return None;
    }
    let mut checksum: u8 = 0;
    for j in 0..checksum_pos {
        checksum ^= decrypted[j];
    }
    if checksum != decrypted[checksum_pos] {
        return None;
    }

    let mut info = LicenseInfo {
        kind: lic_type,
        value: 0,
        year: 0,
        month: 0,
        day: 0,
    };
    match lic_type {
        LicenseType::Days => {
            info.value = ((decrypted[3] as i32) << 8) | (decrypted[4] as i32);
            let created: u32 = ((decrypted[5] as u32) << 24)
                | ((decrypted[6] as u32) << 16)
                | ((decrypted[7] as u32) << 8)
                | (decrypted[8] as u32);
            let expiry_secs: i64 = (created as i64 + info.value as i64) * 86400;
            let (y, m, d) = unix_seconds_to_local_date(expiry_secs);
            info.year = y;
            info.month = m;
            info.day = d;
        }
        LicenseType::Months => {
            info.value = ((decrypted[3] as i32) << 8) | (decrypted[4] as i32);
            let created: u32 = ((decrypted[5] as u32) << 24)
                | ((decrypted[6] as u32) << 16)
                | ((decrypted[7] as u32) << 8)
                | (decrypted[8] as u32);
            let created_secs: i64 = (created as i64) * 86400;
            let (mut y, mut m, d) = unix_seconds_to_local_date(created_secs);
            let total = m + info.value;
            let mut new_m = total;
            while new_m > 12 {
                new_m -= 12;
                y += 1;
            }
            while new_m < 1 {
                new_m += 12;
                y -= 1;
            }
            m = new_m;
            info.year = y;
            info.month = m;
            info.day = d;
        }
        LicenseType::Date => {
            info.year = ((decrypted[3] as i32) << 8) | (decrypted[4] as i32);
            info.month = decrypted[5] as i32;
            info.day = decrypted[6] as i32;
            info.value = 0;
        }
        LicenseType::Lifetime => {
            info.year = 9999;
            info.month = 12;
            info.day = 31;
            info.value = 0;
        }
    }

    Some(info)
}

pub fn is_license_expired(info: &LicenseInfo) -> bool {
    if info.kind == LicenseType::Lifetime {
        return false;
    }
    let now = now_unix_seconds() as i64;
    let (y, m, d) = unix_seconds_to_local_date(now);
    if y > info.year {
        return true;
    }
    if y == info.year && m > info.month {
        return true;
    }
    if y == info.year && m == info.month && d > info.day {
        return true;
    }
    false
}

pub fn unix_seconds_to_local_date(secs: i64) -> (i32, i32, i32) {
    #[cfg(windows)]
    {
        unsafe {
            let ft100ns: i64 = 116444736000000000i64 + secs * 10000000i64;
            let ft = WinFileTime {
                dw_low_date_time: ft100ns as u32,
                dw_high_date_time: ((ft100ns as u64 >> 32) as u32),
            };
            let mut utc: WinSystemTime = std::mem::zeroed();
            if FileTimeToSystemTime(&ft, &mut utc) == 0 {
                return civil_from_unix(secs);
            }
            let mut local: WinSystemTime = std::mem::zeroed();
            if SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) == 0 {
                return (utc.w_year as i32, utc.w_month as i32, utc.w_day as i32);
            }
            (local.w_year as i32, local.w_month as i32, local.w_day as i32)
        }
    }
    #[cfg(not(windows))]
    {
        civil_from_unix(secs)
    }
}

#[cfg(windows)]
#[repr(C)]
struct WinFileTime {
    dw_low_date_time: u32,
    dw_high_date_time: u32,
}

#[cfg(windows)]
#[repr(C)]
struct WinSystemTime {
    w_year: u16,
    w_month: u16,
    w_day_of_week: u16,
    w_day: u16,
    w_hour: u16,
    w_minute: u16,
    w_second: u16,
    w_milliseconds: u16,
}

#[cfg(windows)]
#[allow(non_snake_case)]
extern "system" {
    fn FileTimeToSystemTime(lpFileTime: *const WinFileTime, lpSystemTime: *mut WinSystemTime) -> i32;
    fn SystemTimeToTzSpecificLocalTime(
        lpTimeZoneInformation: *const std::ffi::c_void,
        lpUniversalTime: *const WinSystemTime,
        lpLocalTime: *mut WinSystemTime,
    ) -> i32;
}

fn civil_from_unix(secs: i64) -> (i32, i32, i32) {
    let z = secs.div_euclid(86400) + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let yy = if m <= 2 { y + 1 } else { y };
    (yy as i32, m as i32, d as i32)
}
