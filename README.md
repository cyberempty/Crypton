# Crypton

**Crypton** is a desktop application for protecting files. It can encrypt any file with a password and hide data inside images. It is written in Python with a dark-themed [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) interface.

File encryption and steganography share the same cryptographic engine: **AES-256-GCM** for encryption and **Scrypt** for password-based key derivation.

## Features

### File Cryptography

Encrypts and decrypts any file into the `.crypton` format.

- **AES-256-GCM** authenticated encryption: confidentiality and integrity in one primitive
- **Scrypt** key derivation (n = 2^15, r = 8, p = 1) with a random 32-byte salt
- Header authenticated with **HMAC-SHA256**, keyed from the password
- **SHA-256 of the original file** stored in the header and checked after decryption
- **Original extension** stored in the header, so the right file name is suggested even if the `.crypton` file is renamed
- zlib compression before encryption (skipped when it would not reduce the size)
- **Verify** checks the header structure without a password, or runs a full integrity check (header HMAC, GCM tag, content hash) when a password is entered. Nothing is written to disk
- **Info** shows file details and, for `.crypton` files, their metadata

### Steganography

Hides a file inside an image (PNG, JPG, BMP, WEBP or TIFF cover image).

- **LSB** mode stores the data in the least significant bit of the pixel channels
- **APPEND** mode adds the data at the end of the image file
- Optional password protection of the hidden file, using the same engine and metadata layout as file encryption (salt, nonce, integrity hash). The hidden file name is encrypted as well
- Extraction tries LSB first, then APPEND, and detects by itself whether the payload is encrypted
- LSB output must be a lossless format (PNG, BMP or TIFF); JPEG and WEBP compression would destroy the hidden data, so saving to them is refused

## Requirements

- Python 3.7 or later
- tkinter (bundled with Python; some Linux distributions ship it as a separate package)
- Python packages listed in `requirements.txt`:
  - `customtkinter>=5.2.0`
  - `Pillow>=10.0.0`
  - `cryptography>=41.0.0`
  - `reedsolo>=1.5.0` (optional, reserved for error correction, not used yet)

## Getting started

### Windows

```bash
launch.bat
```

The script checks that Python is installed, installs any missing package with `pip`, and starts the application.

### Linux

```bash
chmod +x launch.sh
./launch.sh
```

### macOS

Double-click `launch.command` in Finder. The first time, if macOS blocks it, right-click the file and choose Open. From a terminal:

```bash
chmod +x launch.sh launch.command
./launch.sh
```

On Linux and macOS the script:

1. looks for Python 3.7+ and tkinter, and prints the install command for your system if either is missing (for example `sudo apt install python3-tk` or `brew install python-tk`)
2. creates a local virtual environment in `.venv`
3. installs the dependencies into it when needed (internet access is required the first time)
4. starts `src/launcher.py`

### Manual start

```bash
pip install -r requirements.txt
python src/app.py
```

Or, from the project folder: `python -m src`

## Project structure

```
Crypton/
├── launch.bat          Windows launcher
├── launch.sh           Linux / macOS launcher
├── launch.command      macOS double-click launcher
├── requirements.txt
├── README.md
└── src/
    ├── app.py          Crypto engine, file encryption, steganography and GUI
    ├── launcher.py     Starts app.py in the background, without a terminal window
    ├── styles.py       Shared colors, spacing and theme
    ├── __init__.py
    └── __main__.py     Entry point for `python -m src`
```

## `.crypton` file format

Integers are little-endian.

| Field | Size | Description |
|---|---|---|
| Magic | 7 bytes | `CRYPTON` |
| Format version | 2 bytes | `2` |
| Algorithm | 1 byte | `0x01` = AES-256-GCM |
| Flags | 1 byte | bit 0: content is zlib-compressed |
| Salt | 32 bytes | random, generated per file |
| Nonce | 12 bytes | random, generated per file |
| Timestamp | 8 bytes | creation time (Unix) |
| Original size | 8 bytes | size of the original file |
| SHA-256 | 32 bytes | hash of the original file |
| Extension length | 2 bytes | |
| Extension | variable | original extension in UTF-8, e.g. `.pdf` (max 255 bytes) |
| Header HMAC | 32 bytes | HMAC-SHA256 of all the fields above |
| Ciphertext | variable | AES-256-GCM output, ending with the 16-byte tag |

Scrypt derives 64 bytes from the password and salt: the first 32 are the AES-256 key and the last 32 are the HMAC key. The header and its HMAC are also supplied to GCM as associated data, so a header cannot be combined with a different ciphertext.

## Error messages

| Message | Meaning |
|---|---|
| The file is not a valid Crypton file | Wrong magic bytes, truncated file or unsupported format version |
| Unrecognized encryption algorithm | The algorithm byte is not supported |
| Wrong password or corrupted file | The header HMAC does not match: wrong password or damaged header |
| File integrity is compromised | The password is correct but the data was altered (GCM tag or SHA-256 mismatch) |

A decrypted file is written to disk only after every check has passed.

## Security notes

- The password is never stored. It is used only to derive the keys. After each operation the password fields are cleared and the byte buffer used for key derivation is zeroed. Python strings cannot be reliably erased from memory, so this shortens the exposure window but does not remove it.
- If you lose the password, the encrypted data cannot be recovered.
- Use a long passphrase. Scrypt makes brute-force attacks expensive but cannot protect a weak password.
- Every operation uses a fresh random salt and nonce.
- File names found in hidden payloads are sanitized (only the last path component is kept) so that extraction cannot write outside the chosen folder.

## Limitations

- Files are processed in memory, so very large files need a proportional amount of RAM.
- Steganography without a password is not protection: anyone who knows the format can extract the hidden file. LSB changes can be detected statistically, and APPEND is easy to spot because the image file is larger than expected.
- LSB data does not survive resizing, cropping or recompression of the image, for example when it is uploaded to a social network.
- The alpha channel of the cover image is dropped in LSB mode.

## Troubleshooting

- **The window does not appear.** The launcher hides the application's output. Run `python src/app.py` directly (or `.venv/bin/python src/app.py` on Linux and macOS) to see the error.
- **`No module named tkinter`.** Install the tkinter package for your system (see Requirements).
- **"Wrong password or corrupted file" although the password is right.** The header of the file is damaged.
