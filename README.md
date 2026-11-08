# Crypton

<p align="center"><img src="source/assets/logo.png" width="128" alt="Crypton logo"></p>

**Open-source** desktop application to protect your files: it encrypts and decrypts any file with a password, and hides a file inside an image.

One single file to download. No installation, no dependencies, no traces left on the system.

| Platform | Launcher | Status |
|---|---|---|
| Windows 10 / 11 (64-bit) | `Crypton-Windows.exe` | available |
| Linux | `Crypton-Linux` | planned |
| macOS | `Crypton-macOS` | planned |

## Usage

Run `Crypton-Windows.exe`. It works even when copied on its own to another computer or a USB stick. The `source/` folder is only needed by developers.

The start screen offers two options, **Encryption** and **Steganography**. Each opens its own section; **Back** returns to the menu.

### Encryption

Choose a file, type the password (twice when encrypting), then:

- **Encrypt** / **Decrypt**: produces a `.crypton` file that remembers the original name (encrypted as well) and suggests it when decrypting, even if the file was renamed. Content is compressed when worthwhile.
- **Verify**: without a password it checks the structure of an encrypted file; with the password it runs the complete check and writes nothing.
- **Info**: shows the details of an encrypted file or of an image with hidden data.

### Steganography

- **Hide file**: pick the file to hide, a cover image and where to save the result, then choose the method:
  - *Pixel (LSB)*: spreads the data over the least significant bits of the pixels. The result can only be saved as PNG or BMP, since lossy formats would destroy the data.
  - *Appended to file*: adds the data after the end of the image file. It is lost if the image is re-encoded (social networks, messaging apps).
  - Optionally protect the hidden file with a password; its name is encrypted too.
- **Extract file**: pick the image and a destination folder. The method and whether a password is needed are detected automatically.

> A forgotten password cannot be recovered. Use **Show** to check what you type before encrypting.

## Security

- **ChaCha20-Poly1305** authenticated encryption: if the file is modified, even by one bit, or truncated, Crypton refuses to open it.
- Key derived with **Argon2id** (64 MiB, 4 passes), deliberately slow against brute force.
- Fresh random salt for every operation: two files encrypted with the same password are different.
- The password is never stored.
- Keys, passwords and data are wiped from memory; a dedicated allocator wipes every freed block.
- A decrypted file is written only after the full verification, through a temporary file renamed at the end.
- File names extracted from images are sanitized: writing outside the chosen folder is impossible.

The `.crypton` format is documented in the comments of `source/src/crypto.rs`, the steganography formats in `source/src/stego.rs`.

## Requirements

Windows 10 or later and a graphics card with OpenGL 2.0 (found practically everywhere; it may be missing in virtual machines or remote desktops).

## Building

Requires [Rust](https://rustup.rs). From the `source/` folder:

```sh
# automated tests (encryption, tampering, steganography)
cargo test

# Windows launcher, also buildable from Linux with mingw-w64
RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-static" \
  cargo build --release --target x86_64-pc-windows-gnu
```

Rename `target/x86_64-pc-windows-gnu/release/crypton.exe` to `Crypton-Windows.exe` and place it in the top-level folder.

## Layout

```
Crypton/
├── Crypton-Windows.exe     single, self-contained launcher
├── README.md
├── LICENSE
└── source/
    ├── Cargo.toml
    ├── Cargo.lock
    ├── build.rs            embeds the icon and version info in the Windows executable
    ├── assets/
    │   ├── logo.png        logo shown in the app and used as window icon
    │   └── icon.ico        multi-size icon of the executable
    └── src/
        ├── main.rs         entry point and memory-wiping allocator
        ├── gui.rs          interface (egui, dark theme)
        ├── crypto.rs       .crypton format
        ├── stego.rs        steganography
        ├── ops.rs          file operations
        └── util.rs         errors and shared helpers
```

## License

[MIT](LICENSE): free code to read, audit, modify and redistribute.
