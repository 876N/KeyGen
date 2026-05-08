#![allow(
    clippy::identity_op,
    clippy::needless_range_loop,
    clippy::missing_safety_doc,
    clippy::collapsible_match,
    clippy::too_many_arguments,
    clippy::field_reassign_with_default,
    clippy::upper_case_acronyms
)]

mod charmap;
mod console;
mod icon;
mod pe;
mod ui;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kg_shared::{
    aes256_cbc_encrypt, crc32, generate_license, pbkdf2_hmac_sha1_32,
    LicenseInfo, LicenseType, CONFIG_DATA_SIZE, CONFIG_MARKER,
};

use console::{
    clear, get_line, get_password_input, msg_err, msg_info, msg_ok, press_any_key, prompt,
    set_color, set_title, show_progress, sleep_ms, Color,
};
use charmap::CharMap;

#[derive(Default)]
struct AppState {
    data_dir: PathBuf,
    stub32_path: PathBuf,
    stub64_path: PathBuf,
    net32_path: PathBuf,
    net64_path: PathBuf,
    char_map_path: PathBuf,
    logs_path: PathBuf,
    char_map: CharMap,
}

static STATE: Mutex<Option<AppState>> = Mutex::new(None);

fn with_state<R, F: FnOnce(&mut AppState) -> R>(f: F) -> R {
    let mut guard = STATE.lock().unwrap();
    let st = guard.as_mut().expect("state not initialised");
    f(st)
}

fn show_header() {
    println!();
    set_color(Color::DarkYellow);
    print!("   ");
    set_color(Color::Yellow);
    print!("██╗░░██╗");
    set_color(Color::DarkYellow);
    print!("███████╗");
    set_color(Color::Yellow);
    print!("██╗░░░██╗");
    set_color(Color::DarkYellow);
    print!("░██████╗░");
    set_color(Color::Yellow);
    print!("███████╗");
    set_color(Color::DarkYellow);
    println!("███╗░░██╗");

    print!("   ");
    set_color(Color::Yellow);
    print!("██║░██╔╝");
    set_color(Color::DarkYellow);
    print!("██╔════╝");
    set_color(Color::Yellow);
    print!("╚██╗░██╔╝");
    set_color(Color::DarkYellow);
    print!("██╔════╝░");
    set_color(Color::Yellow);
    print!("██╔════╝");
    set_color(Color::DarkYellow);
    println!("████╗░██║");

    print!("   ");
    set_color(Color::DarkYellow);
    print!("█████═╝░");
    set_color(Color::Yellow);
    print!("█████╗░░");
    set_color(Color::DarkYellow);
    print!("░╚████╔╝░");
    set_color(Color::Yellow);
    print!("██║░░██╗░");
    set_color(Color::DarkYellow);
    print!("█████╗░░");
    set_color(Color::Yellow);
    println!("██╔██╗██║");

    print!("   ");
    set_color(Color::Yellow);
    print!("██╔═██╗░");
    set_color(Color::DarkYellow);
    print!("██╔══╝░░");
    set_color(Color::Yellow);
    print!("░░╚██╔╝░░");
    set_color(Color::DarkYellow);
    print!("██║░░╚██╗");
    set_color(Color::Yellow);
    print!("██╔══╝░░");
    set_color(Color::DarkYellow);
    println!("██║╚████║");

    print!("   ");
    set_color(Color::DarkYellow);
    print!("██║░╚██╗");
    set_color(Color::Yellow);
    print!("███████╗");
    set_color(Color::DarkYellow);
    print!("░░░██║░░░");
    set_color(Color::Yellow);
    print!("╚██████╔╝");
    set_color(Color::DarkYellow);
    print!("███████╗");
    set_color(Color::Yellow);
    println!("██║░╚███║");

    print!("   ");
    set_color(Color::Yellow);
    print!("╚═╝░░╚═╝");
    set_color(Color::DarkYellow);
    print!("╚══════╝");
    set_color(Color::Yellow);
    print!("░░░╚═╝░░░");
    set_color(Color::DarkYellow);
    print!("░╚═════╝░");
    set_color(Color::Yellow);
    print!("╚══════╝");
    set_color(Color::DarkYellow);
    println!("╚═╝░░╚══╝");

    set_color(Color::DarkGray);
    println!("                                    ByABOLHB");
    println!();
    set_color(Color::White);
}

fn show_menu() {
    set_color(Color::Yellow);
    println!("     [1]  Build Protected Program");
    println!("     [2]  Generate License Key");
    println!("     [3]  Saved Apps");
    println!("     [4]  License Logs");
    println!("     [5]  Edit Character Map");
    println!("     [6]  Generate Random Map");
    println!();
    set_color(Color::DarkGray);
    println!("     Type 'exit' to quit\n");
    set_color(Color::DarkYellow);
    print!("     Select > ");
    set_color(Color::White);
    let _ = std::io::stdout().flush();
}

fn get_exe_dir() -> PathBuf {
    if let Ok(p) = std::env::current_exe() {
        if let Some(parent) = p.parent() {
            return parent.to_path_buf();
        }
    }
    PathBuf::from(".")
}

fn save_app_config(name: &str, pass: &str, path: &str, arch: i32) {
    with_state(|st| {
        let cfg_path = st.data_dir.join(format!("{name}.kg"));
        if let Ok(mut f) = fs::File::create(cfg_path) {
            let now = ui::current_local_datetime();
            let date = format!("{:04}-{:02}-{:02}", now.year, now.month, now.day);
            let _ = writeln!(f, "name={name}");
            let _ = writeln!(f, "pass={pass}");
            let _ = writeln!(f, "path={path}");
            let _ = writeln!(f, "date={date}");
            let _ = writeln!(f, "arch={arch}");
        }
    });
}

fn save_license_log(app_name: &str, hwid: &str, lic_key: &str, lic_type: &str) {
    with_state(|st| {
        let f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&st.logs_path);
        if let Ok(mut f) = f {
            let now = ui::current_local_datetime();
            let dt = format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                now.year, now.month, now.day, now.hour, now.minute, now.second
            );
            let _ = writeln!(f, "---");
            let _ = writeln!(f, "date={dt}");
            let _ = writeln!(f, "app={app_name}");
            let _ = writeln!(f, "hwid={hwid}");
            let _ = writeln!(f, "key={lic_key}");
            let _ = writeln!(f, "type={lic_type}");
        }
    });
}

fn edit_char_map() {
    loop {
        clear();
        show_header();
        set_color(Color::Yellow);
        println!("     CHARACTER MAP\n");
        set_color(Color::DarkGray);
        let per_row = 6;
        let mut count = 0;
        let entries: Vec<(char, u32)> = with_state(|st| {
            st.char_map.entries().iter().map(|e| (e.character, e.value)).collect()
        });
        print!("     ");
        for (ch, val) in &entries {
            set_color(Color::Cyan);
            print!("{ch}");
            set_color(Color::DarkGray);
            print!("=");
            set_color(Color::White);
            print!("{val}");
            count += 1;
            if count % per_row == 0 {
                println!();
                print!("     ");
            } else {
                print!("  ");
            }
        }
        println!();
        println!();
        set_color(Color::DarkGray);
        println!("     [S] save | [E] edit | [B] back\n");
        set_color(Color::DarkYellow);
        print!("     > ");
        set_color(Color::White);
        let _ = std::io::stdout().flush();
        let cmd = get_line();
        let first = cmd.chars().next();
        match first {
            None | Some('B') | Some('b') => break,
            Some('S') | Some('s') => {
                with_state(|st| st.char_map.save_to(&st.char_map_path));
                msg_ok("Saved!");
                sleep_ms(1000);
                continue;
            }
            Some('E') | Some('e') => {
                prompt("Character: ");
                let cs = get_line();
                if cs.is_empty() {
                    continue;
                }
                let target_char = cs.chars().next().unwrap();
                let cur = with_state(|st| st.char_map.get_value(target_char));
                if cur.is_none() {
                    msg_err("Not found!");
                    sleep_ms(1000);
                    continue;
                }
                set_color(Color::Cyan);
                println!("\n     Current: {}", cur.unwrap());
                prompt("New value: ");
                let vs = get_line();
                if !vs.is_empty() {
                    if let Ok(v) = vs.parse::<u32>() {
                        with_state(|st| st.char_map.set_value(target_char, v));
                        msg_ok("Updated!");
                        sleep_ms(1000);
                    }
                }
            }
            _ => {}
        }
    }
}

fn do_generate_random_map() {
    clear();
    show_header();
    set_color(Color::Yellow);
    println!("     GENERATE RANDOM MAP\n");
    set_color(Color::Red);
    println!("     WARNING: All existing licenses will become INVALID!\n");
    set_color(Color::Yellow);
    print!("     Type 'YES' to confirm: ");
    set_color(Color::White);
    let _ = std::io::stdout().flush();
    if get_line() != "YES" {
        msg_info("Cancelled.");
        press_any_key();
        return;
    }
    with_state(|st| {
        st.char_map.regenerate_random();
        st.char_map.save_to(&st.char_map_path);
    });
    msg_ok("New random map generated!");
    press_any_key();
}

fn manage_apps() {
    loop {
        clear();
        show_header();
        set_color(Color::Yellow);
        println!("     SAVED APPS\n");
        let files: Vec<PathBuf> = with_state(|st| {
            let mut out: Vec<PathBuf> = Vec::new();
            if st.data_dir.exists() {
                if let Ok(rd) = fs::read_dir(&st.data_dir) {
                    for entry in rd.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("kg") {
                            out.push(path);
                        }
                    }
                }
            }
            out
        });
        if files.is_empty() {
            set_color(Color::DarkGray);
            println!("     No saved apps.\n");
        } else {
            for (i, f) in files.iter().enumerate() {
                set_color(Color::DarkYellow);
                print!("     [{}] ", i + 1);
                set_color(Color::White);
                let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                println!("{stem}");
            }
            println!();
        }
        set_color(Color::DarkGray);
        println!("     [number] view | [D] delete | [C] clear | [B] back\n");
        set_color(Color::DarkYellow);
        print!("     > ");
        set_color(Color::White);
        let _ = std::io::stdout().flush();
        let mut input = get_line();
        input.make_ascii_uppercase();
        if input.is_empty() || input == "B" {
            break;
        }
        if input == "C" && !files.is_empty() {
            set_color(Color::Red);
            print!("\n     Delete all? (Y/N): ");
            set_color(Color::White);
            let _ = std::io::stdout().flush();
            let conf = get_line();
            if conf == "Y" || conf == "y" {
                for path in &files {
                    let _ = fs::remove_file(path);
                }
                msg_ok("All deleted!");
                sleep_ms(1000);
            }
            continue;
        }
        if input == "D" && !files.is_empty() {
            prompt("Number: ");
            let line = get_line();
            let n: i32 = line.parse().unwrap_or(0);
            if n >= 1 && (n as usize) <= files.len() {
                set_color(Color::Red);
                print!("\n     Delete? (Y/N): ");
                set_color(Color::White);
                let _ = std::io::stdout().flush();
                let conf = get_line();
                if conf == "Y" || conf == "y" {
                    let _ = fs::remove_file(&files[(n - 1) as usize]);
                    msg_ok("Deleted!");
                    sleep_ms(1000);
                }
            }
            continue;
        }
        let idx: i32 = input.parse().unwrap_or(0);
        if idx >= 1 && (idx as usize) <= files.len() {
            clear();
            show_header();
            let content = fs::read_to_string(&files[(idx - 1) as usize]).unwrap_or_default();
            let mut name = String::new();
            let mut pass = String::new();
            let mut path = String::new();
            let mut date = String::new();
            let mut arch_str = String::new();
            for line in content.lines() {
                if let Some(rest) = line.strip_prefix("name=") {
                    name = rest.to_string();
                } else if let Some(rest) = line.strip_prefix("pass=") {
                    pass = rest.to_string();
                } else if let Some(rest) = line.strip_prefix("path=") {
                    path = rest.to_string();
                } else if let Some(rest) = line.strip_prefix("date=") {
                    date = rest.to_string();
                } else if let Some(rest) = line.strip_prefix("arch=") {
                    arch_str = rest.to_string();
                }
            }
            set_color(Color::Yellow);
            println!("     APP DETAILS\n");
            set_color(Color::DarkYellow);
            print!("     Name     : ");
            set_color(Color::White);
            println!("{name}");
            set_color(Color::DarkYellow);
            print!("     Password : ");
            set_color(Color::Green);
            println!("{pass}");
            set_color(Color::DarkYellow);
            print!("     Arch     : ");
            set_color(Color::Cyan);
            println!("{}", pe::arch_string(arch_str.parse().unwrap_or(0)));
            set_color(Color::DarkYellow);
            print!("     Path     : ");
            set_color(Color::Gray);
            println!("{path}");
            set_color(Color::DarkYellow);
            print!("     Created  : ");
            set_color(Color::Gray);
            println!("{date}");
            press_any_key();
        }
    }
}

fn view_license_logs() {
    clear();
    show_header();
    set_color(Color::Yellow);
    println!("     LICENSE LOGS\n");
    let logs_path = with_state(|st| st.logs_path.clone());
    if !logs_path.exists() {
        set_color(Color::DarkGray);
        println!("     No logs found.");
        press_any_key();
        return;
    }
    let content = fs::read_to_string(&logs_path).unwrap_or_default();
    let mut entries: Vec<String> = Vec::new();
    let mut current = String::new();
    for line in content.lines() {
        if line == "---" {
            if !current.is_empty() {
                entries.push(current.clone());
            }
            current.clear();
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }
    if !current.is_empty() {
        entries.push(current);
    }
    if entries.is_empty() {
        set_color(Color::DarkGray);
        println!("     No logs found.");
        press_any_key();
        return;
    }
    let total = entries.len();
    let start = total.saturating_sub(10);
    for entry in entries.iter().skip(start) {
        let mut dt = String::new();
        let mut app = String::new();
        let mut hwid = String::new();
        let mut key = String::new();
        let mut typ = String::new();
        for el in entry.lines() {
            if let Some(r) = el.strip_prefix("date=") {
                dt = r.to_string();
            } else if let Some(r) = el.strip_prefix("app=") {
                app = r.to_string();
            } else if let Some(r) = el.strip_prefix("hwid=") {
                hwid = r.to_string();
            } else if let Some(r) = el.strip_prefix("key=") {
                key = r.to_string();
            } else if let Some(r) = el.strip_prefix("type=") {
                typ = r.to_string();
            }
        }
        set_color(Color::DarkGray);
        println!("     {dt}");
        set_color(Color::DarkYellow);
        print!("     App: ");
        set_color(Color::White);
        print!("{app}");
        set_color(Color::DarkYellow);
        print!(" | HWID: ");
        set_color(Color::Cyan);
        println!("{hwid}");
        set_color(Color::DarkYellow);
        print!("     Key: ");
        set_color(Color::Green);
        println!("{key}");
        set_color(Color::DarkYellow);
        print!("     Type: ");
        set_color(Color::Yellow);
        println!("{typ}\n");
    }
    set_color(Color::DarkGray);
    println!("     Showing last {} of {} entries", total - start, total);
    press_any_key();
}

fn build_protected_exe(
    stub_path: &Path,
    output_path: &Path,
    enc_map: &[u8; 32],
    tool_name: &str,
    orig_ext: &str,
    encrypted_payload: &[u8],
    no_license: bool,
    integrity: u32,
    build_salt: &[u8; 32],
) -> bool {
    let mut stub_data = match fs::read(stub_path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let marker = CONFIG_MARKER;
    let pos = match memmem(&stub_data, marker) {
        Some(p) => p,
        None => return false,
    };
    if pos + CONFIG_DATA_SIZE > stub_data.len() {
        return false;
    }

    let pre_config_crc = crc32(&stub_data[..pos]);

    let mut cfg = [0u8; CONFIG_DATA_SIZE];
    cfg[..marker.len()].copy_from_slice(marker);
    cfg[20..52].copy_from_slice(enc_map);
    let tn = tool_name.as_bytes();
    let tn_len = tn.len().min(31);
    cfg[52..52 + tn_len].copy_from_slice(&tn[..tn_len]);
    let oe = orig_ext.as_bytes();
    let oe_len = oe.len().min(15);
    cfg[84..84 + oe_len].copy_from_slice(&oe[..oe_len]);
    let psize = encrypted_payload.len() as u32;
    cfg[100..104].copy_from_slice(&psize.to_le_bytes());
    cfg[104] = if no_license { 1 } else { 0 };
    cfg[105] = 3;
    cfg[106..110].copy_from_slice(&integrity.to_le_bytes());
    cfg[110..142].copy_from_slice(build_salt);
    cfg[142..146].copy_from_slice(&pre_config_crc.to_le_bytes());

    stub_data[pos..pos + CONFIG_DATA_SIZE].copy_from_slice(&cfg);

    let f = fs::File::create(output_path);
    if let Ok(mut f) = f {
        if f.write_all(&stub_data).is_err() {
            return false;
        }
        if f.write_all(encrypted_payload).is_err() {
            return false;
        }
        true
    } else {
        false
    }
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn format_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.2} KB", n as f64 / 1024.0)
    } else {
        format!("{:.2} MB", n as f64 / (1024.0 * 1024.0))
    }
}

fn do_build() {
    clear();
    show_header();
    set_color(Color::Yellow);
    println!("     BUILD PROTECTED PROGRAM\n");
    let exe_dir = get_exe_dir();
    let stub32_uac_path = exe_dir.join("S32U.dll");
    let stub64_uac_path = exe_dir.join("S64U.dll");
    let net32_uac_path = exe_dir.join("N32U.dll");
    let net64_uac_path = exe_dir.join("N64U.dll");
    let (stub32_path, stub64_path, net32_path, net64_path) =
        with_state(|st| (st.stub32_path.clone(), st.stub64_path.clone(), st.net32_path.clone(), st.net64_path.clone()));
    let has32 = stub32_path.exists();
    let has64 = stub64_path.exists();
    let has32_uac = stub32_uac_path.exists();
    let has64_uac = stub64_uac_path.exists();
    let has_n32 = net32_path.exists();
    let has_n64 = net64_path.exists();
    let has_n32_uac = net32_uac_path.exists();
    let has_n64_uac = net64_uac_path.exists();
    if !has32 && !has64 && !has_n32 && !has_n64 {
        msg_err("No Stub files found!");
        msg_info("Place S32.dll / N32.dll next to KeyGen.exe");
        press_any_key();
        return;
    }
    set_color(Color::DarkGray);
    print!("     Native : ");
    if has32 {
        set_color(Color::Green);
        print!("[32-bit] ");
    }
    if has64 {
        set_color(Color::Green);
        print!("[64-bit] ");
    }
    if has32_uac {
        set_color(Color::Cyan);
        print!("[32-UAC] ");
    }
    if has64_uac {
        set_color(Color::Cyan);
        print!("[64-UAC]");
    }
    if !has32 && !has64 {
        set_color(Color::DarkGray);
        print!("(none)");
    }
    println!();
    set_color(Color::DarkGray);
    print!("     .NET   : ");
    if has_n32 {
        set_color(Color::Green);
        print!("[32-bit] ");
    }
    if has_n64 {
        set_color(Color::Green);
        print!("[64-bit] ");
    }
    if has_n32_uac {
        set_color(Color::Cyan);
        print!("[32-UAC] ");
    }
    if has_n64_uac {
        set_color(Color::Cyan);
        print!("[64-UAC]");
    }
    if !has_n32 && !has_n64 {
        set_color(Color::DarkGray);
        print!("(none)");
    }
    println!();
    prompt("Target File: ");
    let target = get_line();
    if !Path::new(&target).exists() {
        msg_err("File not found!");
        press_any_key();
        return;
    }
    let arch = pe::detect_pe_arch(&target);
    if arch == 0 {
        msg_err("Invalid PE file!");
        press_any_key();
        return;
    }
    let dotnet = pe::is_dotnet_file(&target);
    set_color(Color::Cyan);
    print!("\n     [*] Detected: {}", pe::arch_string(arch));
    if dotnet {
        print!(" (.NET Assembly)");
    }
    println!();
    prompt("App Name: ");
    let tool_name = get_line();
    if tool_name.is_empty() {
        msg_err("Name required!");
        press_any_key();
        return;
    }
    if tool_name.len() > 30 {
        msg_err("Name too long!");
        press_any_key();
        return;
    }
    println!();
    set_color(Color::Yellow);
    println!("     [1] With License Key");
    println!("     [2] No License (Direct Run)");
    prompt("Select (1-2): ");
    let mode = get_line();
    let no_license = mode == "2";
    let mut password = String::from("NOKEY");
    if !no_license {
        prompt("Encryption Key (min 6): ");
        password = get_password_input();
        if password.len() < 6 {
            msg_err("Key too short!");
            press_any_key();
            return;
        }
    }
    let mut require_admin = false;
    prompt("Require Admin (UAC)? [Y/N]: ");
    let uac = get_line();
    if uac == "Y" || uac == "y" {
        require_admin = true;
        msg_ok("UAC enabled");
    }
    let mut stub_path = if dotnet {
        if require_admin {
            if arch == 32 { net32_uac_path.clone() } else { net64_uac_path.clone() }
        } else if arch == 32 {
            net32_path.clone()
        } else {
            net64_path.clone()
        }
    } else if require_admin {
        if arch == 32 { stub32_uac_path.clone() } else { stub64_uac_path.clone() }
    } else if arch == 32 {
        stub32_path.clone()
    } else {
        stub64_path.clone()
    };
    if !stub_path.exists() {
        if require_admin {
            msg_err("UAC Stub not found, falling back...");
            stub_path = if dotnet {
                if arch == 32 { net32_path.clone() } else { net64_path.clone() }
            } else if arch == 32 {
                stub32_path.clone()
            } else {
                stub64_path.clone()
            };
            require_admin = false;
        }
        if !stub_path.exists() && dotnet {
            msg_info("No .NET stub, trying native stub...");
            stub_path = if arch == 32 { stub32_path.clone() } else { stub64_path.clone() };
        }
        if !stub_path.exists() {
            msg_err("Stub not found!");
            press_any_key();
            return;
        }
    }
    set_color(Color::Green);
    let stub_filename = stub_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("?");
    println!("     [+] Using: {stub_filename}");
    let target_path = Path::new(&target);
    let dir = target_path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let name_only = target_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output")
        .to_string();
    let output = dir.join(format!("Protected_{name_only}.exe"));
    let mut ext = target_path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{s}"))
        .unwrap_or_else(|| ".exe".to_string());
    if ext.len() > 14 {
        ext.truncate(14);
    }

    let mut enc_map: [u8; 32] = pbkdf2_hmac_sha1_32(&password, &tool_name);
    let pwd_bytes = password.as_bytes();
    let charmap_values_xor: Vec<u8> = with_state(|st| {
        pwd_bytes
            .iter()
            .map(|&c| (st.char_map.get_value_or_raw(c as char) & 0xFF) as u8)
            .collect()
    });
    for i in 0..enc_map.len() {
        if i < charmap_values_xor.len() {
            enc_map[i] ^= charmap_values_xor[i];
        }
    }
    let sub_table: [u8; 256] = with_state(|st| st.char_map.sub_table());
    for i in 0..enc_map.len() {
        enc_map[i] = sub_table[enc_map[i] as usize];
    }

    show_progress("Reading", 300);
    let data = match fs::read(target_path) {
        Ok(d) => d,
        Err(_) => {
            msg_err("Failed to read file!");
            press_any_key();
            return;
        }
    };
    if data.is_empty() {
        msg_err("Failed to read file!");
        press_any_key();
        return;
    }
    let crc = crc32(&data);
    show_progress("Encrypting", 400);

    let mut build_salt = [0u8; 32];
    kg_shared::secure_random(&mut build_salt);
    let mut payload_key = [0u8; 32];
    for i in 0..32 {
        payload_key[i] = enc_map[i] ^ build_salt[i];
    }

    let encrypted = aes256_cbc_encrypt(&data, &payload_key);
    if encrypted.is_empty() {
        msg_err("Encryption failed!");
        press_any_key();
        return;
    }
    show_progress("Building", 500);
    let temp_stub = output.with_extension("exe.tmp");
    {
        let _ = fs::copy(&stub_path, &temp_stub);
    }
    show_progress("Copying icon", 300);
    let _ = icon::copy_icon_from_exe(target_path, &temp_stub);
    let success = build_protected_exe(
        &temp_stub,
        &output,
        &enc_map,
        &tool_name,
        &ext,
        &encrypted,
        no_license,
        crc,
        &build_salt,
    );
    let _ = fs::remove_file(&temp_stub);
    if success && output.exists() {
        if !no_license {
            save_app_config(&tool_name, &password, output.to_str().unwrap_or(""), arch);
        }
        show_progress("Done", 200);
        msg_ok("Build successful!");
        println!();
        msg_info(&format!("Output: {}", output.display()));
        let size = fs::metadata(&output).map(|m| m.len()).unwrap_or(0);
        msg_info(&format!("Size: {}", format_bytes(size)));
        msg_info(&format!("Architecture: {}", pe::arch_string(arch)));
        if dotnet {
            msg_info("Type: .NET Assembly (In-Memory)");
        } else {
            msg_info("Type: Native PE");
        }
        if no_license {
            msg_info("Mode: Direct Run (No License)");
        } else {
            msg_info("Mode: License Required");
        }
        if require_admin {
            msg_info("UAC: Enabled");
        }
    } else {
        msg_err("Build failed!");
    }
    press_any_key();
}

fn do_gen_key() {
    clear();
    show_header();
    set_color(Color::Yellow);
    println!("     GENERATE LICENSE KEY\n");
    prompt("Hardware ID: ");
    let hwid = get_line();
    if hwid.is_empty() {
        msg_err("Invalid ID!");
        press_any_key();
        return;
    }
    prompt("App Name: ");
    let tool_name = get_line();
    if tool_name.is_empty() {
        msg_err("Name required!");
        press_any_key();
        return;
    }
    prompt("Encryption Key: ");
    let password = get_password_input();
    if password.len() < 6 {
        msg_err("Key too short!");
        press_any_key();
        return;
    }
    println!();
    set_color(Color::Cyan);
    println!("     License Duration:");
    set_color(Color::Yellow);
    println!("     [1] Days");
    println!("     [2] Months");
    println!("     [3] Specific Date");
    println!("     [4] Lifetime");
    prompt("Select (1-4): ");
    let type_str = get_line();
    let mut type_num: i32 = type_str.parse().unwrap_or(4);
    if !(1..=4).contains(&type_num) {
        type_num = 4;
    }

    let mut info = LicenseInfo::default();
    info.kind = match type_num {
        1 => LicenseType::Days,
        2 => LicenseType::Months,
        3 => LicenseType::Date,
        _ => LicenseType::Lifetime,
    };
    let lic_type_str: String = match info.kind {
        LicenseType::Days => {
            prompt("Number of days: ");
            let v: i32 = get_line().parse().unwrap_or(0);
            info.value = if v <= 0 { 30 } else { v };
            format!("{} Days", info.value)
        }
        LicenseType::Months => {
            prompt("Number of months: ");
            let v: i32 = get_line().parse().unwrap_or(0);
            info.value = if v <= 0 { 1 } else { v };
            format!("{} Months", info.value)
        }
        LicenseType::Date => {
            prompt("Expiry date (YYYY-MM-DD): ");
            let date_str = get_line();
            if date_str.len() >= 10 {
                info.year = date_str[0..4].parse().unwrap_or(0);
                info.month = date_str[5..7].parse().unwrap_or(0);
                info.day = date_str[8..10].parse().unwrap_or(0);
            }
            if info.year < 2024
                || info.month < 1
                || info.month > 12
                || info.day < 1
                || info.day > 31
            {
                msg_err("Invalid date!");
                info.kind = LicenseType::Months;
                info.value = 12;
                format!("{} Months", 12)
            } else {
                format!(
                    "Until {:04}-{:02}-{:02}",
                    info.year, info.month, info.day
                )
            }
        }
        LicenseType::Lifetime => "Lifetime".to_string(),
    };

    let mut enc_map: [u8; 32] = pbkdf2_hmac_sha1_32(&password, &tool_name);
    let pwd_bytes = password.as_bytes();
    let charmap_values_xor: Vec<u8> = with_state(|st| {
        pwd_bytes
            .iter()
            .map(|&c| (st.char_map.get_value_or_raw(c as char) & 0xFF) as u8)
            .collect()
    });
    for i in 0..enc_map.len() {
        if i < charmap_values_xor.len() {
            enc_map[i] ^= charmap_values_xor[i];
        }
    }
    let sub_table: [u8; 256] = with_state(|st| st.char_map.sub_table());
    for i in 0..enc_map.len() {
        enc_map[i] = sub_table[enc_map[i] as usize];
    }

    show_progress("Generating", 500);
    let lic = generate_license(&hwid, &enc_map, &info);
    println!();
    set_color(Color::DarkYellow);
    println!("     License Key:");
    set_color(Color::Green);
    println!("     {lic}");
    println!();
    set_color(Color::Cyan);
    print!("     Type: ");
    set_color(Color::White);
    println!("{lic_type_str}");
    save_license_log(&tool_name, &hwid, &lic, &lic_type_str);
    msg_ok("Key generated and logged!");
    press_any_key();
}

fn main() {
    set_title("KeyGen Builder v2.0");
    console::enable_utf8();

    let exe_dir = get_exe_dir();
    let data_dir = exe_dir.join("data");
    let stub32_path = exe_dir.join("S32.dll");
    let stub64_path = exe_dir.join("S64.dll");
    let net32_path = exe_dir.join("N32.dll");
    let net64_path = exe_dir.join("N64.dll");
    let char_map_path = data_dir.join("map.dat");
    let logs_path = data_dir.join("keys.log");
    if !data_dir.exists() {
        let _ = fs::create_dir_all(&data_dir);
    }
    let mut state = AppState {
        data_dir,
        stub32_path,
        stub64_path,
        net32_path,
        net64_path,
        char_map_path: char_map_path.clone(),
        logs_path,
        char_map: CharMap::new(),
    };
    state.char_map.load_from(&char_map_path);
    {
        let mut g = STATE.lock().unwrap();
        *g = Some(state);
    }

    loop {
        clear();
        show_header();
        show_menu();
        let mut opt = get_line();
        opt.make_ascii_lowercase();
        if opt == "exit" {
            break;
        }
        match opt.as_str() {
            "1" => do_build(),
            "2" => do_gen_key(),
            "3" => manage_apps(),
            "4" => view_license_logs(),
            "5" => edit_char_map(),
            "6" => do_generate_random_map(),
            _ => {}
        }
    }
}
