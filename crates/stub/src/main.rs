#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![allow(
    clippy::identity_op,
    clippy::needless_range_loop,
    clippy::missing_safety_doc,
    clippy::manual_c_str_literals,
    clippy::upper_case_acronyms
)]

mod antidebug;
mod cfg;
mod console;
mod dotnet_loader;
mod hwid;
mod payload;
mod runner;

use std::path::PathBuf;

use kg_shared::{crc32, is_license_expired, validate_license, wipe, LicenseType};

use console::{print_line, print_text, read_line};
use payload::load_payload;
use runner::{is_dotnet_assembly, run_payload};

fn run_program() {
    print_line("\n  [*] Loading...", 11);
    let mut encrypted = match load_payload() {
        Some(d) => d,
        None => {
            print_line("  [!] Load failed!", 12);
            console::sleep_ms(2000);
            return;
        }
    };

    let mut key = cfg::get_payload_key();
    antidebug::apply_environment_transform(&mut key);
    if !cfg::verify_self_integrity() {
        for b in key.iter_mut() {
            *b ^= 0xEF;
        }
    }

    print_line("  [*] Decrypting...", 11);
    let decrypted = kg_shared::aes256_cbc_decrypt(&encrypted, &key);
    wipe(&mut key);
    wipe(&mut encrypted);

    if decrypted.is_empty() {
        print_line("  [!] Decrypt failed!", 12);
        console::sleep_ms(2000);
        return;
    }
    if decrypted.len() < 64 || decrypted[0] != b'M' || decrypted[1] != b'Z' {
        let mut d = decrypted;
        wipe(&mut d);
        print_line("  [!] Invalid PE!", 12);
        console::sleep_ms(2000);
        return;
    }

    let integrity = cfg::get_integrity();
    if integrity != 0 {
        let crc = crc32(&decrypted);
        if crc != integrity {
            let mut d = decrypted;
            wipe(&mut d);
            print_line("  [!] Integrity check failed!", 12);
            console::sleep_ms(2000);
            return;
        }
    }

    let is_dotnet = is_dotnet_assembly(&decrypted);
    if is_dotnet {
        print_line("  [*] Type: .NET Assembly", 11);
    } else {
        print_line("  [*] Type: Native PE", 11);
    }
    print_line("  [+] Starting...", 10);
    console::sleep_ms(300);

    let mut data_owned = decrypted;
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleWindow};
        use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
        let cw = GetConsoleWindow();
        if cw != 0 {
            ShowWindow(cw, SW_HIDE);
        }
        FreeConsole();
    }
    let r = run_payload(&data_owned);
    wipe(&mut data_owned);

    if r != 0 {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Console::{AllocConsole, GetConsoleWindow};
            use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_SHOW};
            if GetConsoleWindow() == 0 {
                AllocConsole();
            } else {
                ShowWindow(GetConsoleWindow(), SW_SHOW);
            }
            console::init_console_handle();
        }
        let msg = format!("\n  [!] Execution failed! (E{r})");
        print_line(&msg, 12);
        console::sleep_ms(5000);
    }
}

fn write_auth_file(path: &PathBuf, key: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::File::create(path) {
        let _ = write!(f, "{key}");
    }
    #[cfg(windows)]
    unsafe {
        use std::ffi::CString;
        #[allow(non_snake_case)]
        extern "system" {
            fn SetFileAttributesA(lpFileName: *const u8, dwFileAttributes: u32) -> i32;
        }
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        if let Some(s) = path.to_str() {
            if let Ok(c) = CString::new(s) {
                SetFileAttributesA(c.as_ptr() as *const u8, FILE_ATTRIBUTE_HIDDEN);
            }
        }
    }
}

fn main() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
        let _ = CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32);
    }

    let no_license = cfg::get_no_license();
    if no_license {
        run_program();
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::Com::CoUninitialize();
        }
        return;
    }

    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::AllocConsole;
        AllocConsole();
        console::init_console_handle();
    }

    let tool_name = cfg::get_tool_name();
    #[cfg(windows)]
    unsafe {
        use std::ffi::CString;
        use windows_sys::Win32::System::Console::SetConsoleTitleA;
        let title_c = CString::new(tool_name.as_bytes()).unwrap_or_else(|_| CString::new("App").unwrap());
        SetConsoleTitleA(title_c.as_ptr() as *const u8);
    }

    let auth_path = build_auth_path(&tool_name);

    #[cfg(windows)]
    console::cls();

    print_line("", 7);
    print_line("  ==============================================", 6);
    let title = format!("              {tool_name}");
    print_line(&title, 6);
    print_line("  ==============================================", 6);
    print_line("              License Required", 8);
    print_line("", 7);

    let hwid = hwid::get_hwid();
    print_text("  Hardware ID: ", 6);
    print_line(&hwid, 15);
    print_line("", 7);

    if let Some(p) = &auth_path {
        if let Ok(saved) = std::fs::read_to_string(p) {
            let saved_key: String = saved.trim_end_matches(['\r', '\n']).to_string();
            let enc_map = cfg::get_enc_map();
            if let Some(info) = validate_license(&saved_key, &hwid, &enc_map) {
                if !is_license_expired(&info) {
                    print_line("  [+] License verified!", 10);
                    if info.kind != LicenseType::Lifetime {
                        let exp = format!(
                            "  [*] Expires: {:04}-{:02}-{:02}",
                            info.year, info.month, info.day
                        );
                        print_line(&exp, 11);
                    } else {
                        print_line("  [*] Lifetime License", 11);
                    }
                    run_program();
                    #[cfg(windows)]
                    unsafe {
                        windows_sys::Win32::System::Com::CoUninitialize();
                    }
                    return;
                } else {
                    print_line("  [!] License expired!", 12);
                    let _ = std::fs::remove_file(p);
                }
            } else {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    print_text("  Enter License Key: ", 6);
    console::set_color(15);
    let input_key = read_line();
    let enc_map = cfg::get_enc_map();
    let info = match validate_license(&input_key, &hwid, &enc_map) {
        Some(i) => i,
        None => {
            print_line("\n  [!] Invalid license key!", 12);
            wait_exit();
            return;
        }
    };
    if is_license_expired(&info) {
        print_line("\n  [!] License expired!", 12);
        wait_exit();
        return;
    }
    print_line("\n  [+] License accepted!", 10);
    if info.kind != LicenseType::Lifetime {
        let exp = format!(
            "  [*] Expires: {:04}-{:02}-{:02}",
            info.year, info.month, info.day
        );
        print_line(&exp, 11);
    } else {
        print_line("  [*] Lifetime License", 11);
    }
    print_text("\n  Save license? (Y/N): ", 6);
    console::set_color(15);
    let save = read_line();
    if save == "Y" || save == "y" {
        if let Some(p) = &auth_path {
            write_auth_file(p, &input_key);
            print_line("  [+] License saved!", 10);
        }
    }
    run_program();
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Com::CoUninitialize();
    }
}

fn wait_exit() {
    print_text("\n  Press any key to exit...", 8);
    let _ = read_line();
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Com::CoUninitialize();
    }
}

#[cfg(windows)]
fn build_auth_path(tool_name: &str) -> Option<PathBuf> {
    use windows_sys::Win32::UI::Shell::{SHGetFolderPathA, CSIDL_APPDATA};
    unsafe {
        let mut buf = [0u8; 260];
        let hr = SHGetFolderPathA(0, CSIDL_APPDATA as i32, 0, 0, buf.as_mut_ptr());
        if hr != 0 {
            return None;
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(0);
        let app_data = std::str::from_utf8(&buf[..len]).ok()?.to_string();
        let p = format!("{}\\.kg_{}", app_data, tool_name);
        Some(PathBuf::from(p))
    }
}

#[cfg(not(windows))]
fn build_auth_path(tool_name: &str) -> Option<PathBuf> {
    let mut p = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    p.push(format!(".kg_{}", tool_name));
    Some(p)
}
