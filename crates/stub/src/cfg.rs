use std::sync::atomic::{AtomicBool, Ordering};

#[repr(C, packed)]
pub struct ConfigData {
    pub marker: [u8; 20],
    pub enc_map: [u8; 32],
    pub tool_name: [u8; 32],
    pub orig_ext: [u8; 16],
    pub payload_size: u32,
    pub no_license: u8,
    pub version: u8,
    pub integrity: u32,
    pub build_salt: [u8; 32],
    pub text_crc32: u32,
    pub reserved: [u8; 10],
}

#[no_mangle]
#[used]
pub static mut G_CONFIG: ConfigData = ConfigData {
    marker: *b"[[CONFIG_START]]!!!\0",
    enc_map: [0u8; 32],
    tool_name: *b"APPNAME_HERE!!!!!!!!!!!!!!!!!!!\0",
    orig_ext: *b".exe!!!!!!!!!!!\0",
    payload_size: 0,
    no_license: 0,
    version: 0,
    integrity: 0,
    build_salt: [0u8; 32],
    text_crc32: 0,
    reserved: *b"[[END!]]!\0",
};

static INIT_GUARD: AtomicBool = AtomicBool::new(false);

fn ensure_referenced() {
    if !INIT_GUARD.swap(true, Ordering::SeqCst) {
        unsafe {
            let p = std::ptr::addr_of!(G_CONFIG) as *const u8;
            let _ = std::ptr::read_volatile(p);
        }
    }
}

pub fn get_enc_map() -> [u8; 32] {
    ensure_referenced();
    unsafe { std::ptr::addr_of!(G_CONFIG.enc_map).read_unaligned() }
}

pub fn get_payload_key() -> [u8; 32] {
    ensure_referenced();
    let mut k = unsafe { std::ptr::addr_of!(G_CONFIG.enc_map).read_unaligned() };
    let salt: [u8; 32] = unsafe { std::ptr::addr_of!(G_CONFIG.build_salt).read_unaligned() };
    for i in 0..32 {
        k[i] ^= salt[i];
    }
    k
}

pub fn get_tool_name() -> String {
    ensure_referenced();
    unsafe {
        let raw = std::ptr::addr_of!(G_CONFIG.tool_name).read_unaligned();
        let mut end = 0usize;
        while end < raw.len() && raw[end] != 0 && raw[end] != b'!' {
            end += 1;
        }
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }
}

pub fn get_no_license() -> bool {
    ensure_referenced();
    unsafe { std::ptr::addr_of!(G_CONFIG.no_license).read_unaligned() == 1 }
}

pub fn get_payload_size() -> u32 {
    ensure_referenced();
    unsafe { std::ptr::addr_of!(G_CONFIG.payload_size).read_unaligned() }
}

pub fn get_integrity() -> u32 {
    ensure_referenced();
    unsafe { std::ptr::addr_of!(G_CONFIG.integrity).read_unaligned() }
}

pub fn get_text_crc32() -> u32 {
    ensure_referenced();
    unsafe { std::ptr::addr_of!(G_CONFIG.text_crc32).read_unaligned() }
}

pub fn verify_self_integrity() -> bool {
    let expected = get_text_crc32();
    if expected == 0 {
        return true;
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let bytes = match std::fs::read(&exe) {
        Ok(b) => b,
        Err(_) => return false,
    };
    use kg_shared::CONFIG_MARKER;
    let pos = match bytes.windows(CONFIG_MARKER.len()).position(|w| w == CONFIG_MARKER) {
        Some(p) => p,
        None => return false,
    };
    let actual = kg_shared::crc32(&bytes[..pos]);
    actual == expected
}
