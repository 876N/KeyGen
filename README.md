# KeyGen

> **Executable Protection & License Management Tool**
![image](https://i.ibb.co/gbfhR9f0/image.png)
Protects Windows executables (Native & .NET) with AES-256 encryption, hardware-locked license keys, and anti-tamper mechanisms.

---

## Features

- **AES-256-CBC Encryption** — Payload encrypted at rest, decrypted only at runtime
- **HWID Binding** — Licenses locked to specific hardware
- **Expiration Control** — Days, months, specific date, or lifetime
- **Native PE Support** — Encrypted drop + hidden execution with auto-cleanup
- **.NET In-Memory Loading** — Assembly loaded directly into memory via pipe, never touches disk
- **UAC Elevation** — Optional admin privilege requirement
- **Icon Preservation** — Protected file keeps the original icon
- **Anti-Debug** — Encryption key transforms when debugger is detected
- **Integrity Verification** — CRC32 check on decrypted payload
- **Memory Wiping** — Volatile zeroing of all sensitive buffers

---

## Quick Start

1. Install [Rust](https://rustup.rs) (1.75+) with MSVC Build Tools
2. Run `build.bat` → Select **[1] Build All**
3. Output appears in `Release/`

---

## Requirements

| Requirement | Details |
|---|---|
| **Rust** | https://rustup.rs (1.75+) |
| **MSVC Build Tools** | Visual Studio Build Tools |
| **Targets** | `i686-pc-windows-msvc` + `x86_64-pc-windows-msvc` |

Install targets via `build.bat` option **[7]** or manually:
```cmd
rustup target add i686-pc-windows-msvc x86_64-pc-windows-msvc
```

---

## Project Structure

```
KeyGen/
├── build.bat                 Build script
├── Cargo.toml                Workspace config
├── crates/
│   ├── shared/               Crypto & license library
│   │   └── src/
│   │       ├── aes.rs        AES-256-CBC
│   │       ├── hash.rs       SHA1, MD5, HMAC-SHA1
│   │       ├── kdf.rs        PBKDF2
│   │       ├── license.rs    License encode/decode/validate
│   │       ├── random.rs     Secure random generation
│   │       └── config.rs     Binary config structure
│   ├── keygen/               KeyGen.exe (CLI tool)
│   │   └── src/
│   │       ├── main.rs       Menu, build, key generation
│   │       ├── console.rs    Console I/O helpers
│   │       ├── charmap.rs    Character map editor
│   │       ├── pe.rs         PE analysis
│   │       ├── icon.rs       Icon extraction
│   │       └── ui.rs         UI components
│   └── stub/                 Protected loader
│       └── src/
│           ├── main.rs       Entry point, license check
│           ├── runner.rs     Payload dispatcher
│           ├── dotnet_loader.rs  .NET in-memory loader
│           ├── cfg.rs        Runtime config reader
│           ├── console.rs    Console output
│           ├── hwid.rs       Hardware ID generation
│           ├── payload.rs    Payload extraction
│           ├── antidebug.rs  Anti-debug transforms
│           └── bootstrap_exe.cs  .NET bootstrap source
├── res/                      Resources (icon, manifest)
├── data/                     Character map storage
└── Release/                  Build output
```

---

## Output Files

| File | Description |
|---|---|
| `KeyGen.exe` | Protection tool & license generator |
| `S32.dll` | 32-bit Native loader |
| `S64.dll` | 64-bit Native loader |
| `S32U.dll` | 32-bit Native loader + UAC |
| `S64U.dll` | 64-bit Native loader + UAC |
| `N32.dll` | 32-bit .NET loader (in-memory) |
| `N64.dll` | 64-bit .NET loader (in-memory) |
| `N32U.dll` | 32-bit .NET loader (in-memory) + UAC |
| `N64U.dll` | 64-bit .NET loader (in-memory) + UAC |

---

## Usage

### 1. Build Protected Program

1. Run `KeyGen.exe`
2. Select **[1] Build Protected Program**
3. Enter the target executable path
4. Enter application name
5. Choose protection mode:
   - **With License Key** — Requires activation with HWID-bound key
   - **No License (Direct Run)** — Runs silently, encryption only
6. Set encryption key (min 6 characters)
7. Choose UAC requirement (Yes/No)
8. Protected file is generated

### 2. Generate License Key

1. Select **[2] Generate License Key**
2. Enter the Hardware ID (shown when the protected program runs)
3. Enter the app name (must match exactly)
4. Enter the encryption key (must match exactly)
5. Choose license type:

| Type | Description |
|---|---|
| **Days** | Expires N days after activation |
| **Months** | Expires N months after activation |
| **Date** | Expires on a specific date |
| **Lifetime** | Never expires |

### 3. Other Options

| Option | Description |
|---|---|
| **[3] Saved Apps** | View previously protected applications |
| **[4] License Logs** | View generated license history |
| **[5] Edit Character Map** | Customize the license key alphabet |
| **[6] Generate Random Map** | Create a new random character map |

---

## Security Notes

- **`data/map.dat`** is your unique encryption map — keep it secret
- Use **[6] Generate Random Map** for a unique installation
- Different maps produce incompatible licenses — backup before regenerating
- The encryption key entered during protection must match when generating licenses
- Protected .NET assemblies are loaded entirely in-memory and never written to disk

---

## Manual Build

```cmd
cargo build --release -p keygen
copy target\release\KeyGen.exe Release\KeyGen.exe

:: Native loaders
cargo build --release -p stub --target i686-pc-windows-msvc
copy target\i686-pc-windows-msvc\release\S.exe Release\S32.dll

cargo build --release -p stub --target x86_64-pc-windows-msvc
copy target\x86_64-pc-windows-msvc\release\S.exe Release\S64.dll

:: .NET loaders
cargo build --release -p stub --target i686-pc-windows-msvc --features dotnet
copy target\i686-pc-windows-msvc\release\S.exe Release\N32.dll

cargo build --release -p stub --target x86_64-pc-windows-msvc --features dotnet
copy target\x86_64-pc-windows-msvc\release\S.exe Release\N64.dll
```

Add `--features uac` for UAC variants, `--features dotnet,uac` for .NET + UAC.

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `cargo not found` | Install Rust via rustup-init.exe |
| `target not installed` | `build.bat` option [7] or `rustup target add` |
| `link.exe not found` | Install MSVC Build Tools |
| Invalid license | Verify app name and encryption key match |
| HWID mismatch | License is hardware-locked to a different machine |

---

**Made By ABOLHB**
