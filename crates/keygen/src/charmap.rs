use std::fs;
use std::io::Write;
use std::path::Path;

use kg_shared::secure_random;

#[derive(Clone, Copy)]
pub struct CharMapEntry {
    pub character: char,
    pub value: u32,
}

pub struct CharMap {
    entries: Vec<CharMapEntry>,
    sub_table: [u8; 256],
    inv_sub_table: [u8; 256],
}

impl Default for CharMap {
    fn default() -> Self {
        Self::new()
    }
}

impl CharMap {
    pub fn new() -> Self {
        let mut s = Self {
            entries: Vec::new(),
            sub_table: [0u8; 256],
            inv_sub_table: [0u8; 256],
        };
        s.init_default_sub_table();
        s.init_default_entries();
        s
    }

    pub fn entries(&self) -> &[CharMapEntry] {
        &self.entries
    }

    pub fn sub_table(&self) -> [u8; 256] {
        self.sub_table
    }

    pub fn get_value(&self, c: char) -> Option<u32> {
        self.entries
            .iter()
            .find(|e| e.character == c)
            .map(|e| e.value)
    }

    pub fn get_value_or_raw(&self, c: char) -> u32 {
        self.get_value(c).unwrap_or(c as u32)
    }

    pub fn set_value(&mut self, c: char, v: u32) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.character == c) {
            e.value = v;
        }
    }

    fn init_default_sub_table(&mut self) {
        for i in 0..256 {
            self.sub_table[i] = i as u8;
            self.inv_sub_table[i] = i as u8;
        }
    }

    fn init_default_entries(&mut self) {
        self.entries.clear();
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for (i, &c) in chars.iter().enumerate() {
            let val = 10000 + ((i as u32).wrapping_mul(1337)) + (i as u32 * i as u32 * 7);
            self.entries.push(CharMapEntry {
                character: c as char,
                value: val,
            });
        }
    }

    pub fn regenerate_random(&mut self) {
        let mut buf = [0u8; 4];
        secure_random(&mut buf);
        let seed = u32::from_le_bytes(buf);
        let mut rng = SimpleRng::seed(seed);
        self.entries.clear();
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for &c in chars.iter() {
            let v = 10000 + (rng.next_u32() % 989999);
            self.entries.push(CharMapEntry {
                character: c as char,
                value: v,
            });
        }
        self.generate_random_sub_table();
    }

    pub fn generate_random_sub_table(&mut self) {
        for i in 0..256 {
            self.sub_table[i] = i as u8;
        }
        let mut seed_buf = [0u8; 16];
        secure_random(&mut seed_buf);
        let mut seed_val: u32 = 0;
        for &b in &seed_buf {
            seed_val = seed_val.wrapping_mul(31).wrapping_add(b as u32);
        }
        let mut rng = SimpleRng::seed(seed_val);
        for i in (1..256).rev() {
            let j = (rng.next_u32() % (i as u32 + 1)) as usize;
            self.sub_table.swap(i, j);
        }
        for i in 0..256 {
            self.inv_sub_table[self.sub_table[i] as usize] = i as u8;
        }
    }

    pub fn save_to(&self, path: &Path) {
        if let Ok(mut f) = fs::File::create(path) {
            let _ = writeln!(f, "# KeyGen Map - DO NOT SHARE");
            for e in &self.entries {
                let _ = writeln!(f, "{}={}", e.character, e.value);
            }
            let mut hex = String::with_capacity(512);
            for &b in &self.sub_table {
                hex.push_str(&format!("{:02X}", b));
            }
            let _ = writeln!(f, "@SUB={hex}");
        }
    }

    pub fn load_from(&mut self, path: &Path) {
        self.init_default_sub_table();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => {
                self.init_default_entries();
                self.generate_random_sub_table();
                self.save_to(path);
                return;
            }
        };
        self.entries.clear();
        let mut has_sub = false;
        for line in content.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("@SUB=") {
                if rest.len() >= 512 {
                    for i in 0..256 {
                        let pair = &rest[i * 2..i * 2 + 2];
                        if let Ok(v) = u8::from_str_radix(pair, 16) {
                            self.sub_table[i] = v;
                        }
                    }
                    for i in 0..256 {
                        self.inv_sub_table[self.sub_table[i] as usize] = i as u8;
                    }
                    has_sub = true;
                }
                continue;
            }
            if let Some(eq) = line.find('=') {
                if eq > 0 {
                    let ch = line.chars().next().unwrap();
                    let val: u32 = line[eq + 1..].trim().parse().unwrap_or(0);
                    self.entries.push(CharMapEntry {
                        character: ch,
                        value: val,
                    });
                }
            }
        }
        if self.entries.is_empty() {
            self.init_default_entries();
        }
        if !has_sub {
            self.generate_random_sub_table();
            self.save_to(path);
        }
    }
}

struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn seed(seed: u32) -> Self {
        let s = if seed == 0 { 0xDEADBEEF } else { seed as u64 };
        Self { state: s }
    }
    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.state >> 33) & 0x7FFFFFFF) as u32
    }
}
