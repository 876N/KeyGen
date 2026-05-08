pub const CONFIG_MARKER: &[u8; 19] = b"[[CONFIG_START]]!!!";
pub const CONFIG_DATA_SIZE: usize = 156;

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

impl ConfigData {
    pub fn empty_marker_template() -> [u8; CONFIG_DATA_SIZE] {
        let mut buf = [0u8; CONFIG_DATA_SIZE];
        buf[..CONFIG_MARKER.len()].copy_from_slice(CONFIG_MARKER);
        buf
    }
}
