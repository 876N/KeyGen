use kg_shared::{ConfigData, CONFIG_DATA_SIZE};
use std::mem::{offset_of, size_of};

#[test]
fn config_data_size_matches_cpp() {
    assert_eq!(size_of::<ConfigData>(), CONFIG_DATA_SIZE);
    assert_eq!(size_of::<ConfigData>(), 156);
}

#[test]
fn config_data_field_offsets() {
    assert_eq!(offset_of!(ConfigData, marker), 0);
    assert_eq!(offset_of!(ConfigData, enc_map), 20);
    assert_eq!(offset_of!(ConfigData, tool_name), 52);
    assert_eq!(offset_of!(ConfigData, orig_ext), 84);
    assert_eq!(offset_of!(ConfigData, payload_size), 100);
    assert_eq!(offset_of!(ConfigData, no_license), 104);
    assert_eq!(offset_of!(ConfigData, version), 105);
    assert_eq!(offset_of!(ConfigData, integrity), 106);
    assert_eq!(offset_of!(ConfigData, build_salt), 110);
    assert_eq!(offset_of!(ConfigData, text_crc32), 142);
    assert_eq!(offset_of!(ConfigData, reserved), 146);
}
