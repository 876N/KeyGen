use std::io::{self, BufRead, Write};

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum Color {
    Black = 0,
    DarkBlue = 1,
    DarkGreen = 2,
    DarkCyan = 3,
    DarkRed = 4,
    DarkMagenta = 5,
    DarkYellow = 6,
    Gray = 7,
    DarkGray = 8,
    Blue = 9,
    Green = 10,
    Cyan = 11,
    Red = 12,
    Magenta = 13,
    Yellow = 14,
    White = 15,
}

#[cfg(windows)]
pub fn set_color(c: Color) {
    use windows_sys::Win32::System::Console::{
        GetStdHandle, SetConsoleTextAttribute, STD_OUTPUT_HANDLE,
    };
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(h, c as u16);
    }
}

#[cfg(not(windows))]
pub fn set_color(c: Color) {
    let codes = [
        "\x1b[30m", "\x1b[34m", "\x1b[32m", "\x1b[36m", "\x1b[31m", "\x1b[35m", "\x1b[33m",
        "\x1b[37m", "\x1b[90m", "\x1b[94m", "\x1b[92m", "\x1b[96m", "\x1b[91m", "\x1b[95m",
        "\x1b[93m", "\x1b[97m",
    ];
    print!("{}", codes[(c as usize) % 16]);
    let _ = io::stdout().flush();
}

#[cfg(windows)]
pub fn clear() {
    use windows_sys::Win32::System::Console::{
        FillConsoleOutputAttribute, FillConsoleOutputCharacterA, GetConsoleScreenBufferInfo,
        GetStdHandle, SetConsoleCursorPosition, CONSOLE_SCREEN_BUFFER_INFO, COORD,
        STD_OUTPUT_HANDLE,
    };
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let pos = COORD { X: 0, Y: 0 };
        let mut written: u32 = 0;
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(h, &mut info) == 0 {
            return;
        }
        let size = (info.dwSize.X as u32) * (info.dwSize.Y as u32);
        FillConsoleOutputCharacterA(h, b' ', size, pos, &mut written);
        FillConsoleOutputAttribute(h, info.wAttributes, size, pos, &mut written);
        SetConsoleCursorPosition(h, pos);
    }
}

#[cfg(not(windows))]
pub fn clear() {
    print!("\x1b[2J\x1b[H");
    let _ = io::stdout().flush();
}

#[cfg(windows)]
pub fn set_title(title: &str) {
    use windows_sys::Win32::System::Console::SetConsoleTitleA;
    let mut buf: Vec<u8> = title.as_bytes().to_vec();
    buf.push(0);
    unsafe {
        SetConsoleTitleA(buf.as_ptr());
    }
}

#[cfg(not(windows))]
pub fn set_title(title: &str) {
    print!("\x1b]0;{}\x07", title);
    let _ = io::stdout().flush();
}

#[cfg(windows)]
pub fn enable_utf8() {
    use windows_sys::Win32::System::Console::SetConsoleOutputCP;
    unsafe {
        SetConsoleOutputCP(65001);
    }
}

#[cfg(not(windows))]
pub fn enable_utf8() {}

#[cfg(windows)]
pub fn sleep_ms(ms: u32) {
    use windows_sys::Win32::System::Threading::Sleep;
    unsafe {
        Sleep(ms);
    }
}

#[cfg(not(windows))]
pub fn sleep_ms(ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
}

pub fn get_line() -> String {
    let stdin = io::stdin();
    let mut raw = String::new();
    let _ = stdin.lock().read_line(&mut raw);
    let mut s = raw.trim_end_matches(['\r', '\n']).to_string();
    if s.starts_with('"') {
        s.remove(0);
    }
    if s.ends_with('"') {
        s.pop();
    }
    s
}

#[cfg(windows)]
pub fn get_password_input() -> String {
    extern "C" {
        fn _getch() -> i32;
    }
    let mut password = String::new();
    loop {
        let ch = unsafe { _getch() };
        match ch {
            13 => {
                println!();
                break;
            }
            8 => {
                if !password.is_empty() {
                    password.pop();
                    print!("\x08 \x08");
                    let _ = io::stdout().flush();
                }
            }
            32..=126 => {
                password.push(ch as u8 as char);
                print!("*");
                let _ = io::stdout().flush();
            }
            _ => {}
        }
    }
    password
}

#[cfg(not(windows))]
pub fn get_password_input() -> String {
    get_line()
}

pub fn msg_ok(s: &str) {
    set_color(Color::Green);
    println!("\n     [+] {s}");
    set_color(Color::White);
}

pub fn msg_err(s: &str) {
    set_color(Color::Red);
    println!("\n     [!] {s}");
    set_color(Color::White);
}

pub fn msg_info(s: &str) {
    set_color(Color::Cyan);
    println!("     [*] {s}");
    set_color(Color::White);
}

pub fn prompt(s: &str) {
    set_color(Color::DarkYellow);
    print!("\n     {s}");
    set_color(Color::White);
    let _ = io::stdout().flush();
}

#[cfg(windows)]
pub fn press_any_key() {
    extern "C" {
        fn _getch() -> i32;
    }
    set_color(Color::DarkGray);
    print!("\n     Press any key...");
    set_color(Color::White);
    let _ = io::stdout().flush();
    unsafe {
        let _ = _getch();
    }
}

#[cfg(not(windows))]
pub fn press_any_key() {
    set_color(Color::DarkGray);
    print!("\n     Press any key...");
    set_color(Color::White);
    let _ = io::stdout().flush();
    let _ = get_line();
}

pub fn show_progress(task: &str, ms: u32) {
    set_color(Color::DarkGray);
    print!("     [");
    set_color(Color::Green);
    let _ = io::stdout().flush();
    let step = ms / 25;
    for _ in 0..25 {
        print!("#");
        let _ = io::stdout().flush();
        sleep_ms(step);
    }
    set_color(Color::DarkGray);
    print!("] ");
    set_color(Color::White);
    println!("100% {task}");
}
