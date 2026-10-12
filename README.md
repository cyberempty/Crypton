# Crypton – Secure Cryptography Suite

Desktop application (Python + CustomTkinter) for **encrypting files** and **hiding data inside images** (steganography), with a dark-themed graphical interface.

Both functions share **one cryptographic engine**: **AES-256-GCM** for encryption and **Scrypt** for key derivation.

## Features

### File Cryptography (default page)
Encrypt/decrypt any file into the `.crypton` format.

- **AES-256-GCM** (AEAD): confidentiality and integrity in a single primitive
- Key derived from the password with **Scrypt** (n=2^15, r=8, p=1, 32-byte random salt)
- Header authenticated with **HMAC-SHA256** (key derived from the password)
- **SHA-256 of the original file** stored in the header and re-checked after decryption
- **Original extension** stored in the header, so the decrypted file gets the right name even if the `.crypton` file is renamed
- Automatic compression (zlib) before encryption, skipped when it doesn't reduce the size
- Buttons: **Encrypt**, **Decrypt**, **Verify**, **Info**
  - Verify without password: checks the header structure only
  - Verify with password: full check (header HMAC, GCM tag, SHA-256 of the content), nothing is written to disk

### Steganography
Hide a file inside an image (cover image: PNG/JPG/BMP/WEBP/TIFF).

- **LSB** method: the data is stored in the least significant bit of the pixel channels
- **APPEND** method: the data is added at the end of the image file
- Optional encryption of the hidden content with the same engine used for files (Scrypt + AES-256-GCM, same metadata layout: salt, nonce, integrity hash). The hidden **file name is encrypted too**
- Extraction tries LSB first, then APPEND, and detects automatically whether the payload is encrypted
- LSB output must be a **lossless** format (PNG, BMP, TIFF): JPEG/WEBP compression would destroy the hidden data, so the program refuses to save it

## Requirements

- Python 3.7+
- **tkinter** (part of Python, but on some Linux distributions it is a separate package)
- Dependencies (see `requirements.txt`):
  - `customtkinter>=5.2.0`
  - `Pillow>=10.0.0`
  - `cryptography>=41.0.0`
  - `reedsolo>=1.5.0` (optional, currently not used by the program)

## Installation and launch

### Windows
```bash
launch.bat
```
Checks that Python is installed, installs any missing dependency with `pip`, then starts `src/launcher.py`.

### Linux
```bash
chmod +x launch.sh
./launch.sh
```

### macOS
Double-click `launch.command` in Finder (the first time, if macOS blocks it: right-click > Open), or from a terminal:
```bash
chmod +x launch.sh launch.command
./launch.sh
```

On Linux/macOS the script:
1. looks for Python 3.7+ and for tkinter (and tells you the right install command if missing, e.g. `sudo apt install python3-tk` or `brew install python-tk`)
2. creates a local virtual environment in `.venv` (avoids the "externally-managed-environment" error of recent distributions)
3. installs the dependencies in the virtual environment, only if needed (internet required the first time)
4. starts `src/launcher.py`

### Manual launch (no automatic checks)
```bash
pip install -r requirements.txt
python src/app.py
```
or, from the project folder: `python -m src`

## Project structure

```
Crypton/
├── launch.bat          Windows launcher
├── launch.sh           Linux/macOS launcher
├── launch.command      macOS double-click launcher
├── requirements.txt
├── README.md
└── src/
    ├── app.py          Application: crypto engine, file crypto, steganography, GUI
    ├── launcher.py     Starts app.py in the background (no terminal window)
    ├── styles.py       Shared colors/spacing/theme
    ├── __init__.py
    └── __main__.py     Entry point for `python -m src`
```

## `.crypton` file format (version 2)

All integers are little-endian.

| Field | Size | Notes |
|---|---|---|
| Magic | 7 bytes | `CRYPTON` |
| Version | 2 bytes | currently `2` |
| Algorithm | 1 byte | `0x01` = AES-256-GCM |
| Flags | 1 byte | bit 0 = content is zlib-compressed |
| Salt | 32 bytes | random, per file |
| Nonce | 12 bytes | random, per file |
| Timestamp | 8 bytes | creation time (Unix) |
| Original size | 8 bytes | size of the original file |
| SHA-256 | 32 bytes | hash of the original file |
| Extension length | 2 bytes | |
| Extension | variable | original extension, UTF-8 (e.g. `.pdf`), max 255 bytes |
| Header HMAC | 32 bytes | HMAC-SHA256 of everything above |
| Ciphertext | variable | AES-256-GCM output (ciphertext + 16-byte tag) |

The header and its HMAC are also passed to GCM as associated data, so a header cannot be paired with a different ciphertext. Scrypt produces 64 bytes: the first 32 are the AES-256 key, the last 32 the HMAC key.

Files created by the old, pre-2.0 format are not compatible.

## Error messages

Decryption failures are reported distinctly:

| Message | Meaning |
|---|---|
| Il file non è un Crypton valido | Wrong magic, truncated file or unsupported format version |
| Algoritmo di cifratura non riconosciuto | The algorithm byte is not supported by this version |
| Password errata o file corrotto | The header HMAC does not match: wrong password or damaged header |
| L'integrità del file è compromessa | The password is right but the data was altered (GCM tag or SHA-256 mismatch) |

No output file is written unless every check passes.

## Security notes

- The password is **never stored**: it is only used to derive the keys. After every operation the password fields (entries and variables) are cleared, and the byte buffer used for key derivation is zeroed. Python strings cannot be reliably wiped from memory, so this reduces the exposure window but does not eliminate it.
- If you lose the password, **the encrypted data cannot be recovered**.
- Use long, complex passphrases: Scrypt slows down brute-force attacks, but cannot protect a weak password.
- A new random salt (32 bytes) and nonce (12 bytes) are generated for every operation.
- Names of extracted files are sanitized (only the last path component is kept) to prevent writing outside the chosen folder.

## Limitations

- Files are processed in memory: very large files need a proportional amount of RAM.
- Steganography is **not** encryption by itself: without a password, the hidden file is plain data that anyone who knows the format can extract. LSB changes can also be detected statistically, and the APPEND method is easy to spot (the image file is larger than expected).
- LSB data does not survive resizing, cropping or recompression of the image (e.g. uploading to social networks).
- The cover image's alpha channel (RGBA) is dropped when using LSB.

## Troubleshooting

- **The window does not appear:** the launcher hides the application's output. Run it directly to see the error: `python src/app.py` (or `.venv/bin/python src/app.py` on Linux/macOS).
- **`No module named tkinter`:** install the tkinter package for your system (see Requirements).
- **"Password errata o file corrotto" with the right password:** the header of the file is damaged.
