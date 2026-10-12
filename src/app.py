#!/usr/bin/env python3

import sys
import os
import hashlib
import hmac
import struct
import zlib
import time
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

sys.dont_write_bytecode = True

# ============================================================================
# IMPORTS
# ============================================================================
try:
    import customtkinter as ctk
    from PIL import Image
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    print("Installing dependencies...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter", "Pillow", "cryptography"])
    print("Dependencies installed. Restart the program.")
    sys.exit(0)

try:
    import reedsolo
    RS_AVAILABLE = True
except ImportError:
    RS_AVAILABLE = False


# ============================================================================
# CONSTANTS
# ============================================================================
# --- Primitive crittografiche condivise (file + steganografia) ---
ALGO_AES256GCM = 0x01
SUPPORTED_ALGORITHMS = {ALGO_AES256GCM: "AES-256-GCM"}

SALT_SIZE = 32          # random bytes per operation
NONCE_SIZE = 12         # random bytes per operation
KEY_SIZE = 32           # AES-256
MAC_KEY_SIZE = 32       # chiave HMAC, derivata dalla stessa password
MAC_SIZE = 32           # HMAC-SHA256
TAG_SIZE = 16           # GCM authentication tag
SHA_SIZE = 32           # SHA-256 del plaintext originale

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

# --- Formato .crypton ---
MAGIC = b"CRYPTON"
VERSION = 2
FLAG_COMPRESSED = 0x01
MAX_EXT_LEN = 255
# magic | version | algo | flags | salt | nonce | timestamp | size | sha256 | ext_len
HEADER_FMT = '<7sHBB32s12sQQ32sH'
HEADER_FIXED_SIZE = struct.calcsize(HEADER_FMT)

# --- Steganografia ---
STEGO_MAGIC_LSB = b'STEGO\x00'
STEGO_MAGIC_APP = b'\x00HIDDEN_FILE_START\x00'
STEGO_END_APP = b'\x00HIDDEN_FILE_END\x00'
STEGO_ENCRYPT_MARKER = b'ENCRYPTED_AES256_GCM_'
# marker | algo | salt | nonce | sha256   (followed by HMAC and ciphertext)
STEGO_META_SIZE = len(STEGO_ENCRYPT_MARKER) + 1 + SALT_SIZE + NONCE_SIZE + SHA_SIZE
LOSSLESS_EXTENSIONS = {'.png', '.bmp', '.tif', '.tiff'}


# ============================================================================
# COLORS
# ============================================================================
COLORS = {
    "bg": "#0a0a0a",
    "bg_secondary": "#121212",
    "bg_tertiary": "#1a1a1a",
    "bg_card": "#181818",
    "text": "#e8e8e8",
    "text_secondary": "#888888",
    "text_muted": "#555555",
    "accent": "#3a3a3a",
    "border": "#252525",
    "border_light": "#2a2a2a",
    "button": "#1e1e1e",
    "button_hover": "#2a2a2a",
    "button_active": "#333333",
    "success": "#2d7a3a",
    "success_hover": "#3a8f4a",
    "danger": "#7a2d2d",
    "danger_hover": "#8f3a3a",
    "warning": "#7a6a2d",
    "warning_hover": "#8f7a3a",
    "info": "#2d4a7a",
    "info_hover": "#3a5a8f",
}

SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_XXL = 4, 8, 12, 16, 24, 32


def setup_theme():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")


# ============================================================================
# ERRORS
# ============================================================================
class CryptonError(Exception):
    default_message = "Errore Crypton"

    def __init__(self, message=None):
        super().__init__(message or self.default_message)


class InvalidFormatError(CryptonError):
    default_message = "The file is not a valid Crypton file"


class UnsupportedAlgorithmError(CryptonError):
    default_message = "Unrecognized encryption algorithm"


class WrongPasswordError(CryptonError):
    default_message = "Wrong password or corrupted file"


class IntegrityError(CryptonError):
    default_message = "File integrity is compromised"


# ============================================================================
# CRYPTO ENGINE (single engine shared by file encryption and steganography)
# ============================================================================
class CryptoEngine:
    """AES-256-GCM + Scrypt + HMAC-SHA256.

    Every encrypted blob has the same structure:
        header (with salt, nonce, SHA-256 of the plaintext) | HMAC-SHA256(header) | ciphertext+tag
    The header and the HMAC are also passed to GCM as AAD.
    """

    @staticmethod
    def sha256(data):
        return hashlib.sha256(data).digest()

    def derive_keys(self, password, salt):
        """Scrypt -> 64 bytes: 32 for AES-256, 32 for the header HMAC."""
        pw = bytearray(password.encode('utf-8'))
        try:
            kdf = Scrypt(salt=salt, length=KEY_SIZE + MAC_KEY_SIZE,
                         n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
            material = kdf.derive(pw)
        finally:
            for i in range(len(pw)):
                pw[i] = 0
        return material[:KEY_SIZE], material[KEY_SIZE:]

    @staticmethod
    def header_mac(mac_key, header):
        return hmac.new(mac_key, header, hashlib.sha256).digest()

    def seal(self, payload, password, build_header):
        """Encrypts `payload`. build_header(salt, nonce) must return the header bytes."""
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        enc_key, mac_key = self.derive_keys(password, salt)
        header = build_header(salt, nonce)
        mac = self.header_mac(mac_key, header)
        ciphertext = AESGCM(enc_key).encrypt(nonce, payload, header + mac)
        return header + mac + ciphertext

    def open(self, data, header_end, password, salt, nonce):
        """Verifies the header HMAC, then decrypts.

        - invalid HMAC         -> wrong password or damaged header
        - valid HMAC, bad tag -> right password but tampered ciphertext
        """
        enc_key, mac_key = self.derive_keys(password, salt)
        mac_end = header_end + MAC_SIZE
        expected = self.header_mac(mac_key, data[:header_end])
        if not hmac.compare_digest(expected, data[header_end:mac_end]):
            raise WrongPasswordError()
        try:
            return AESGCM(enc_key).decrypt(nonce, data[mac_end:], data[:mac_end])
        except InvalidTag:
            raise IntegrityError()


# ============================================================================
# CRYPTO CORE (formato .crypton)
# ============================================================================
class CryptoCore:
    """File encryption: AES-256-GCM + Scrypt"""

    def __init__(self, engine=None):
        self.engine = engine or CryptoEngine()

    @staticmethod
    def _safe_ext(raw):
        """Extension as a string; discarded if suspicious (only used for file names)."""
        try:
            ext = raw.decode('utf-8')
        except UnicodeDecodeError:
            return ""
        if ext and (not ext.startswith('.') or any(c in ext for c in '/\\:\x00')):
            return ""
        return ext

    def _parse(self, head, total_size):
        """Parses the (not yet authenticated) header. `head` may be just the start of the file."""
        if len(head) < len(MAGIC) or head[:len(MAGIC)] != MAGIC:
            raise InvalidFormatError()
        if len(head) < HEADER_FIXED_SIZE:
            raise InvalidFormatError()

        (_magic, version, algo, flags, salt, nonce,
         timestamp, size, sha, ext_len) = struct.unpack(HEADER_FMT, head[:HEADER_FIXED_SIZE])

        if version != VERSION:
            raise InvalidFormatError(f"Unsupported format version: {version}")
        if algo not in SUPPORTED_ALGORITHMS:
            raise UnsupportedAlgorithmError()
        if ext_len > MAX_EXT_LEN:
            raise InvalidFormatError()

        header_end = HEADER_FIXED_SIZE + ext_len
        mac_end = header_end + MAC_SIZE
        if len(head) < mac_end or total_size < mac_end + TAG_SIZE:
            raise InvalidFormatError()

        return {
            'version': version,
            'algorithm': SUPPORTED_ALGORITHMS[algo],
            'compressed': bool(flags & FLAG_COMPRESSED),
            'salt': salt,
            'nonce': nonce,
            'timestamp': timestamp,
            'size_original': size,
            'sha256': sha,
            'extension': self._safe_ext(head[HEADER_FIXED_SIZE:header_end]),
            'header_end': header_end,
        }

    def _decrypt_bytes(self, data, password):
        h = self._parse(data, len(data))
        payload = self.engine.open(data, h['header_end'], password, h['salt'], h['nonce'])

        if h['compressed']:
            try:
                plaintext = zlib.decompress(payload)
            except zlib.error:
                raise IntegrityError()
        else:
            plaintext = payload

        if len(plaintext) != h['size_original'] or \
                not hmac.compare_digest(self.engine.sha256(plaintext), h['sha256']):
            raise IntegrityError()
        return plaintext, h

    def encrypt(self, input_path, output_path, password):
        input_path = Path(input_path)
        output_path = Path(output_path)

        plaintext = input_path.read_bytes()
        sha = self.engine.sha256(plaintext)
        size = len(plaintext)
        timestamp = int(time.time())

        ext = input_path.suffix.encode('utf-8')
        if len(ext) > MAX_EXT_LEN:
            ext = b""

        payload = zlib.compress(plaintext, level=9)
        flags = FLAG_COMPRESSED
        if len(payload) >= size:        # compression does not help
            payload = plaintext
            flags = 0

        def build_header(salt, nonce):
            return struct.pack(HEADER_FMT, MAGIC, VERSION, ALGO_AES256GCM, flags,
                               salt, nonce, timestamp, size, sha, len(ext)) + ext

        blob = self.engine.seal(payload, password, build_header)
        output_path.write_bytes(blob)

        return {
            'input': str(input_path),
            'output': str(output_path),
            'size_original': size,
            'size_encrypted': len(blob)
        }

    def decrypt(self, input_path, output_path, password):
        input_path = Path(input_path)
        output_path = Path(output_path)

        data = input_path.read_bytes()
        plaintext, h = self._decrypt_bytes(data, password)

        # Write only after every check has passed
        output_path.write_bytes(plaintext)
        return {
            'input': str(input_path),
            'output': str(output_path),
            'size_original': h['size_original'],
            'extension': h['extension'],
        }

    def verify(self, file_path, password=None):
        """Without a password: structural check of the header only.
        With a password: full check (HMAC, GCM tag, SHA-256 of the plaintext), nothing is written."""
        file_path = Path(file_path)
        total = file_path.stat().st_size

        if password:
            data = file_path.read_bytes()
            _plain, h = self._decrypt_bytes(data, password)
            authenticated = True
        else:
            with open(file_path, 'rb') as f:
                head = f.read(HEADER_FIXED_SIZE + MAX_EXT_LEN + MAC_SIZE)
            h = self._parse(head, total)
            authenticated = False

        return {
            'valid': True,
            'authenticated': authenticated,
            'version': h['version'],
            'algorithm': h['algorithm'],
            'size_original': h['size_original'],
            'timestamp': h['timestamp'],
            'compressed': h['compressed'],
            'extension': h['extension'],
        }


# ============================================================================
# STEGO CORE
# ============================================================================
class StegoCore:
    """LSB/APPEND Steganography (payload encrypted with the same engine used for files)"""

    def __init__(self, engine=None):
        self.engine = engine or CryptoEngine()

    # ---- payload -----------------------------------------------------------
    def build_payload(self, file_path, password=None):
        file_path = Path(file_path)
        name = file_path.name.encode('utf-8')
        inner = struct.pack('>H', len(name)) + name + file_path.read_bytes()
        if not password:
            return inner

        sha = self.engine.sha256(inner)

        def build_header(salt, nonce):
            return STEGO_ENCRYPT_MARKER + bytes([ALGO_AES256GCM]) + salt + nonce + sha

        # With encryption the file name stays hidden too
        return self.engine.seal(inner, password, build_header)

    def is_encrypted(self, payload):
        return payload.startswith(STEGO_ENCRYPT_MARKER)

    def process_payload(self, payload, password=None):
        if self.is_encrypted(payload):
            if not password:
                raise CryptonError("Password required")
            if len(payload) < STEGO_META_SIZE + MAC_SIZE + TAG_SIZE:
                raise InvalidFormatError("Invalid hidden data")

            idx = len(STEGO_ENCRYPT_MARKER)
            algo = payload[idx]
            if algo not in SUPPORTED_ALGORITHMS:
                raise UnsupportedAlgorithmError()
            idx += 1
            salt = payload[idx:idx + SALT_SIZE]
            idx += SALT_SIZE
            nonce = payload[idx:idx + NONCE_SIZE]
            idx += NONCE_SIZE
            sha = payload[idx:idx + SHA_SIZE]

            inner = self.engine.open(payload, STEGO_META_SIZE, password, salt, nonce)
            if not hmac.compare_digest(self.engine.sha256(inner), sha):
                raise IntegrityError()
        else:
            inner = payload

        if len(inner) < 2:
            raise InvalidFormatError("Invalid hidden data")
        name_len = struct.unpack('>H', inner[:2])[0]
        if 2 + name_len > len(inner):
            raise InvalidFormatError("Invalid hidden data")
        try:
            file_name = inner[2:2 + name_len].decode('utf-8')
        except UnicodeDecodeError:
            raise InvalidFormatError("Invalid hidden data")
        return file_name, inner[2 + name_len:]

    # ---- LSB ---------------------------------------------------------------
    @staticmethod
    def _load_image(image_path):
        img = Image.open(image_path)
        if img.mode not in ('RGB', 'L'):
            img = img.convert('RGB')
        return img

    def hide_lsb(self, image_path, file_path, output_path, password=None):
        if Path(output_path).suffix.lower() not in LOSSLESS_EXTENSIONS:
            raise ValueError("LSB requires a lossless output format (PNG, BMP or TIFF): "
                             "JPEG/WEBP compression would destroy the hidden data")

        payload = self.build_payload(file_path, password)
        data = STEGO_MAGIC_LSB + struct.pack('>I', len(payload)) + payload

        img = self._load_image(image_path)
        raw = bytearray(img.tobytes())      # one byte per channel: R,G,B,R,G,B... (or L)
        if len(data) * 8 > len(raw):
            raise Exception(f"File too large. Max: {len(raw) // 8 - len(STEGO_MAGIC_LSB) - 4} bytes")

        pos = 0
        for byte in data:
            for shift in range(7, -1, -1):
                raw[pos] = (raw[pos] & 0xFE) | ((byte >> shift) & 1)
                pos += 1

        new_img = Image.frombytes(img.mode, img.size, bytes(raw))
        new_img.save(output_path)
        return True

    @staticmethod
    def _read_lsb_bytes(raw, start, count):
        out = bytearray(count)
        pos = start * 8
        for i in range(count):
            b = 0
            for k in range(8):
                b = (b << 1) | (raw[pos + k] & 1)
            out[i] = b
            pos += 8
        return bytes(out)

    def extract_lsb(self, image_path):
        raw = self._load_image(image_path).tobytes()
        head_len = len(STEGO_MAGIC_LSB) + 4
        if len(raw) < head_len * 8:
            return None

        # The magic must be exactly at the start of the decoded bits
        head = self._read_lsb_bytes(raw, 0, head_len)
        if head[:len(STEGO_MAGIC_LSB)] != STEGO_MAGIC_LSB:
            return None

        payload_len = struct.unpack('>I', head[len(STEGO_MAGIC_LSB):])[0]
        if (head_len + payload_len) * 8 > len(raw):
            return None
        return self._read_lsb_bytes(raw, head_len, payload_len)

    # ---- APPEND ------------------------------------------------------------
    def hide_append(self, image_path, file_path, output_path, password=None):
        payload = self.build_payload(file_path, password)
        image_data = Path(image_path).read_bytes()
        full_payload = STEGO_MAGIC_APP + struct.pack('>I', len(payload)) + payload + STEGO_END_APP
        with open(output_path, 'wb') as f:
            f.write(image_data)
            f.write(full_payload)
        return True

    def extract_append(self, image_path):
        data = Path(image_path).read_bytes()
        start = data.find(STEGO_MAGIC_APP)
        while start != -1:
            idx = start + len(STEGO_MAGIC_APP)
            if idx + 4 <= len(data):
                payload_len = struct.unpack('>I', data[idx:idx + 4])[0]
                idx += 4
                end = idx + payload_len
                # Accept only if the end marker is exactly where it should be
                if data[end:end + len(STEGO_END_APP)] == STEGO_END_APP:
                    return data[idx:end]
            start = data.find(STEGO_MAGIC_APP, start + 1)
        return None

    # ---- output ------------------------------------------------------------
    def save_file(self, file_name, file_data, output_dir):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        # The name comes from external data: keep only the last path component
        original = Path(file_name.replace('\\', '/').split('/')[-1] or "extracted")
        path = out / f"{original.stem}_extracted{original.suffix}"
        counter = 1
        while path.exists():
            path = out / f"{original.stem}_{counter}{original.suffix}"
            counter += 1
        with open(path, 'wb') as f:
            f.write(file_data)
        return path


# ============================================================================
# UI WIDGETS
# ============================================================================
class ModernButton(ctk.CTkButton):
    def __init__(self, parent, text, command=None, **kwargs):
        super().__init__(
            parent,
            text=text,
            command=command,
            height=38,
            corner_radius=8,
            font=("Segoe UI", 13),
            fg_color=COLORS["button"],
            hover_color=COLORS["button_hover"],
            text_color=COLORS["text"],
            border_width=0,
            **kwargs
        )


class ModernButtonAccent(ctk.CTkButton):
    def __init__(self, parent, text, command=None, color="success", **kwargs):
        colors = {
            "success": (COLORS["success"], COLORS["success_hover"]),
            "danger": (COLORS["danger"], COLORS["danger_hover"]),
            "warning": (COLORS["warning"], COLORS["warning_hover"]),
            "info": (COLORS["info"], COLORS["info_hover"]),
        }
        fg, hover = colors.get(color, (COLORS["success"], COLORS["success_hover"]))
        super().__init__(
            parent,
            text=text,
            command=command,
            height=38,
            corner_radius=8,
            font=("Segoe UI", 13, "bold"),
            fg_color=fg,
            hover_color=hover,
            text_color=COLORS["text"],
            border_width=0,
            **kwargs
        )


class SidebarButton(ctk.CTkButton):
    def __init__(self, parent, text, command):
        super().__init__(
            parent, 
            text=text, 
            anchor="w", 
            height=44,
            corner_radius=8, 
            font=("Segoe UI", 14),
            fg_color="transparent", 
            hover_color=COLORS["bg_tertiary"],
            text_color=COLORS["text_secondary"], 
            command=command,
            border_width=0
        )
    
    def set_selected(self, selected):
        if selected:
            self.configure(
                fg_color=COLORS["bg_tertiary"], 
                text_color=COLORS["text"], 
                font=("Segoe UI", 14, "bold")
            )
        else:
            self.configure(
                fg_color="transparent", 
                text_color=COLORS["text_secondary"], 
                font=("Segoe UI", 14)
            )


class FilePicker(ctk.CTkFrame):
    def __init__(self, parent, var, placeholder, command):
        super().__init__(parent, fg_color="transparent")
        self.var = var
        self.entry = ctk.CTkEntry(
            self, 
            textvariable=var, 
            placeholder_text=placeholder,
            font=("Segoe UI", 12), 
            height=38,
            fg_color=COLORS["bg"], 
            border_color=COLORS["border"],
            border_width=1, 
            corner_radius=8,
            text_color=COLORS["text"]
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ModernButton(
            self, 
            text="Browse", 
            width=80,
            command=command
        ).pack(side="left")


# ============================================================================
# MAIN APPLICATION
# ============================================================================
class CryptonApp:
    def __init__(self):
        setup_theme()
        self.root = ctk.CTk()
        self.root.title("Crypton")
        self.root.geometry("1020x800")
        self.root.minsize(920, 720)
        self.root.configure(fg_color=COLORS["bg"])
        
        self.crypto = CryptoCore()
        self.stego = StegoCore()
        self.current_file = None
        
        self.file_path = ctk.StringVar()
        self.password = ctk.StringVar()
        self.confirm_password = ctk.StringVar()
        self.show_password = False
        
        self.stego_show_password = False
        self.extract_show_password = False
        
        self.pages = {}
        self.sidebar_items = {}
        self.current_page = "crypto"
        
        self._build_ui()
    
    def _build_ui(self):
        main_container = ctk.CTkFrame(self.root, fg_color=COLORS["bg"])
        main_container.pack(fill="both", expand=True)
        
        sidebar = ctk.CTkFrame(main_container, width=220, fg_color=COLORS["bg_secondary"], corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        
        logo_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=16, pady=(20, 16))
        
        ctk.CTkLabel(logo_frame, text="Crypton", font=("Segoe UI", 20, "bold"), text_color=COLORS["text"]).pack()
        
        ctk.CTkFrame(sidebar, height=1, fg_color=COLORS["border"]).pack(fill="x", padx=12, pady=(0, 16))
        
        nav = ctk.CTkFrame(sidebar, fg_color="transparent")
        nav.pack(fill="x", padx=8)
        
        btn_crypto = SidebarButton(nav, "File Cryptography", lambda: self._select_page("crypto"))
        btn_crypto.pack(fill="x", pady=2)
        self.sidebar_items["crypto"] = btn_crypto
        
        btn_stego = SidebarButton(nav, "Steganography", lambda: self._select_page("stego"))
        btn_stego.pack(fill="x", pady=2)
        self.sidebar_items["stego"] = btn_stego
        
        footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=16, pady=16)
        ctk.CTkLabel(footer, text="v1.0", font=("Segoe UI", 10), text_color=COLORS["text_muted"]).pack()
        
        content = ctk.CTkFrame(main_container, fg_color=COLORS["bg"])
        content.pack(side="left", fill="both", expand=True, padx=20, pady=20)
        
        self.pages["stego"] = self._build_stego_page(content)
        self.pages["crypto"] = self._build_crypto_page(content)
        self._select_page("crypto")
    
    def _select_page(self, name):
        self.current_page = name
        for key, item in self.sidebar_items.items():
            item.set_selected(key == name)
        for key, page in self.pages.items():
            if key == name:
                page.pack(fill="both", expand=True)
            else:
                page.pack_forget()
    
    def _card(self, parent):
        return ctk.CTkFrame(parent, corner_radius=12, fg_color=COLORS["bg_card"], border_width=1, border_color=COLORS["border_light"])
    
    def _format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def _set_buttons_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        for btn in ['encrypt_btn', 'decrypt_btn', 'verify_btn', 'info_btn', 'hide_btn', 'extract_btn']:
            if hasattr(self, btn):
                getattr(self, btn).configure(state=state)
    
    # ========================================================================
    # STEGO PAGE
    # ========================================================================
    def _build_stego_page(self, parent):
        page = ctk.CTkFrame(parent, fg_color="transparent")
        container = ctk.CTkFrame(page, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=SP_XS, pady=SP_XS)
        
        ctk.CTkLabel(container, text="Steganography", font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(container, text="Hide files inside images using LSB pixel or APPEND method", font=("Segoe UI", 13), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 16))
        
        columns = ctk.CTkFrame(container, fg_color="transparent")
        columns.pack(fill="both", expand=True)
        columns.grid_columnconfigure(0, weight=1)
        columns.grid_columnconfigure(1, weight=1)
        
        # LEFT - Hide
        hide_card = self._card(columns)
        hide_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        hide_inner = ctk.CTkFrame(hide_card, fg_color="transparent")
        hide_inner.pack(fill="both", expand=True, padx=SP_MD, pady=SP_MD)
        
        ctk.CTkLabel(hide_inner, text="Hide File", font=("Segoe UI", 16, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 12))
        
        ctk.CTkLabel(hide_inner, text="File to hide", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.hide_file_var = ctk.StringVar()
        FilePicker(hide_inner, self.hide_file_var, "Select file...", lambda: self._browse_file_var(self.hide_file_var)).pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(hide_inner, text="Cover image", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.hide_image_var = ctk.StringVar()
        FilePicker(hide_inner, self.hide_image_var, "Select image...", lambda: self._browse_file_var(self.hide_image_var, "image")).pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(hide_inner, text="Save as", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.hide_output_var = ctk.StringVar()
        FilePicker(hide_inner, self.hide_output_var, "Choose path...", lambda: self._browse_save_var(self.hide_output_var)).pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(hide_inner, text="Method", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.hide_method_var = ctk.StringVar(value="lsb")
        method_frame = ctk.CTkFrame(hide_inner, fg_color="transparent")
        method_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkRadioButton(method_frame, text="LSB (Pixel)", variable=self.hide_method_var, value="lsb", font=("Segoe UI", 12), fg_color=COLORS["accent"], text_color=COLORS["text"]).pack(side="left", padx=(0, 16))
        ctk.CTkRadioButton(method_frame, text="APPEND (End of file)", variable=self.hide_method_var, value="append", font=("Segoe UI", 12), fg_color=COLORS["accent"], text_color=COLORS["text"]).pack(side="left")
        
        self.use_encryption = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(hide_inner, text="Encrypt with AES-256-GCM", font=("Segoe UI", 12), variable=self.use_encryption, fg_color=COLORS["bg_tertiary"], progress_color=COLORS["accent"], text_color=COLORS["text"], command=self._toggle_stego_encryption).pack(anchor="w", pady=(0, 6))
        
        # Password row with Show button for Hide
        stego_pass_row = ctk.CTkFrame(hide_inner, fg_color="transparent")
        stego_pass_row.pack(fill="x", pady=2)
        
        self.stego_pass_entry = ctk.CTkEntry(
            stego_pass_row, 
            show="*", 
            placeholder_text="Password",
            font=("Segoe UI", 12), 
            height=34,
            fg_color=COLORS["bg"], 
            border_color=COLORS["border"],
            border_width=1, 
            corner_radius=8, 
            state="disabled"
        )
        self.stego_pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        
        self.stego_show_btn = ModernButton(
            stego_pass_row, 
            text="Show", 
            width=60,
            state="disabled",
            command=self._toggle_stego_password
        )
        self.stego_show_btn.pack(side="right")
        
        self.stego_confirm_entry = ctk.CTkEntry(
            hide_inner, 
            show="*", 
            placeholder_text="Confirm password",
            font=("Segoe UI", 12), 
            height=34,
            fg_color=COLORS["bg"], 
            border_color=COLORS["border"],
            border_width=1, 
            corner_radius=8, 
            state="disabled"
        )
        self.stego_confirm_entry.pack(fill="x", pady=(0, 10))
        
        self.hide_btn = ModernButtonAccent(hide_inner, text="Hide File", color="success", command=self._do_hide)
        self.hide_btn.pack(fill="x")
        
        # RIGHT - Extract
        extract_card = self._card(columns)
        extract_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        extract_inner = ctk.CTkFrame(extract_card, fg_color="transparent")
        extract_inner.pack(fill="both", expand=True, padx=SP_MD, pady=SP_MD)
        
        ctk.CTkLabel(extract_inner, text="Extract File", font=("Segoe UI", 16, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 12))
        
        ctk.CTkLabel(extract_inner, text="Image with hidden file", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.extract_image_var = ctk.StringVar()
        FilePicker(extract_inner, self.extract_image_var, "Select image...", lambda: self._browse_file_var(self.extract_image_var, "image")).pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(extract_inner, text="Destination folder", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        self.extract_dir_var = ctk.StringVar(value=str(Path.home() / "Desktop"))
        FilePicker(extract_inner, self.extract_dir_var, "Select folder...", lambda: self._browse_dir_var(self.extract_dir_var)).pack(fill="x", pady=(0, 10))
        
        # Password for extract with Show button
        ctk.CTkLabel(extract_inner, text="Password (if encrypted)", font=("Segoe UI", 11), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 4))
        
        extract_pass_row = ctk.CTkFrame(extract_inner, fg_color="transparent")
        extract_pass_row.pack(fill="x", pady=(0, 10))
        
        self.extract_password = ctk.StringVar()
        self.extract_pass_entry = ctk.CTkEntry(
            extract_pass_row, 
            textvariable=self.extract_password,
            show="*", 
            placeholder_text="Enter password if file is encrypted",
            font=("Segoe UI", 12), 
            height=34,
            fg_color=COLORS["bg"], 
            border_color=COLORS["border"],
            border_width=1, 
            corner_radius=8,
            text_color=COLORS["text"]
        )
        self.extract_pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        
        self.extract_show_btn = ModernButton(
            extract_pass_row, 
            text="Show", 
            width=60,
            command=self._toggle_extract_password
        )
        self.extract_show_btn.pack(side="right")
        
        self.extract_btn = ModernButtonAccent(extract_inner, text="Extract File", color="info", command=self._do_extract)
        self.extract_btn.pack(fill="x", pady=(10, 0))
        
        return page
    
    # ========================================================================
    # CRYPTO PAGE
    # ========================================================================
    def _build_crypto_page(self, parent):
        page = ctk.CTkFrame(parent, fg_color="transparent")
        container = ctk.CTkFrame(page, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=SP_XS, pady=SP_XS)
        
        ctk.CTkLabel(container, text="File Cryptography", font=("Segoe UI", 24, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 4))
        ctk.CTkLabel(container, text="AES-256-GCM + Scrypt - Secure file encryption", font=("Segoe UI", 13), text_color=COLORS["text_secondary"]).pack(anchor="w", pady=(0, 16))
        
        main_card = self._card(container)
        main_card.pack(fill="both", expand=True)
        main_inner = ctk.CTkFrame(main_card, fg_color="transparent")
        main_inner.pack(fill="both", expand=True, padx=SP_LG, pady=SP_LG)
        
        ctk.CTkLabel(main_inner, text="File", font=("Segoe UI", 13, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 4))
        FilePicker(main_inner, self.file_path, "Paste file path or browse...", self._browse_file).pack(fill="x", pady=(0, 6))
        self.file_path.trace_add('write', self._on_file_change)
        
        self.file_info_frame = ctk.CTkFrame(main_inner, fg_color="transparent")
        self.file_info_frame.pack(fill="x")
        self.file_info_frame.pack_forget()
        self.file_info_label = ctk.CTkLabel(self.file_info_frame, text="", font=("Segoe UI", 10), text_color=COLORS["text_secondary"])
        self.file_info_label.pack(side="left")
        self.file_info_icon = ctk.CTkLabel(self.file_info_frame, text="", font=("Segoe UI", 11))
        self.file_info_icon.pack(side="right")
        
        ctk.CTkFrame(main_inner, height=1, fg_color=COLORS["border"]).pack(fill="x", pady=12)
        
        ctk.CTkLabel(main_inner, text="Password", font=("Segoe UI", 13, "bold"), text_color=COLORS["text"]).pack(anchor="w", pady=(0, 4))
        
        pass_row = ctk.CTkFrame(main_inner, fg_color="transparent")
        pass_row.pack(fill="x", pady=(0, 4))
        self.pass_entry = ctk.CTkEntry(pass_row, textvariable=self.password, show="*", height=36, placeholder_text="Enter your password", font=("Segoe UI", 12), border_color=COLORS["border"], border_width=1, corner_radius=8, fg_color=COLORS["bg"])
        self.pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.show_btn = ModernButton(pass_row, text="Show", width=60, command=self._toggle_password)
        self.show_btn.pack(side="right")
        
        self.confirm_pass_entry = ctk.CTkEntry(main_inner, textvariable=self.confirm_password, show="*", height=36, placeholder_text="Confirm your password", font=("Segoe UI", 12), border_color=COLORS["border"], border_width=1, corner_radius=8, fg_color=COLORS["bg"])
        self.confirm_pass_entry.pack(fill="x", pady=(0, 6))
        
        ctk.CTkFrame(main_inner, height=1, fg_color=COLORS["border"]).pack(fill="x", pady=12)
        
        btn_row = ctk.CTkFrame(main_inner, fg_color="transparent")
        btn_row.pack(fill="x")
        btn_row.grid_columnconfigure(0, weight=1)
        btn_row.grid_columnconfigure(1, weight=1)
        btn_row.grid_columnconfigure(2, weight=1)
        btn_row.grid_columnconfigure(3, weight=1)
        
        self.encrypt_btn = ModernButtonAccent(btn_row, text="Encrypt", color="success", command=self._encrypt)
        self.encrypt_btn.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        
        self.decrypt_btn = ModernButtonAccent(btn_row, text="Decrypt", color="info", command=self._decrypt)
        self.decrypt_btn.grid(row=0, column=1, sticky="ew", padx=(4, 4))
        
        self.verify_btn = ModernButton(btn_row, text="Verify", command=self._verify)
        self.verify_btn.grid(row=0, column=2, sticky="ew", padx=(4, 4))
        
        self.info_btn = ModernButton(btn_row, text="Info", command=self._show_info)
        self.info_btn.grid(row=0, column=3, sticky="ew", padx=(4, 0))
        
        return page
    
    # ========================================================================
    # STEGO HELPERS
    # ========================================================================
    def _toggle_stego_encryption(self):
        state = "normal" if self.use_encryption.get() else "disabled"
        self.stego_pass_entry.configure(state=state)
        self.stego_confirm_entry.configure(state=state)
        self.stego_show_btn.configure(state=state)
        if state == "disabled":
            self.stego_show_password = False
            self.stego_pass_entry.configure(show="*")
            self.stego_confirm_entry.configure(show="*")
            self.stego_show_btn.configure(text="Show")
            self.stego_pass_entry.delete(0, "end")
            self.stego_confirm_entry.delete(0, "end")
    
    def _toggle_stego_password(self):
        """Mostra/nasconde entrambe le password nella sezione Hide"""
        self.stego_show_password = not self.stego_show_password
        if self.stego_show_password:
            self.stego_pass_entry.configure(show="")
            self.stego_confirm_entry.configure(show="")
            self.stego_show_btn.configure(text="Hide")
        else:
            self.stego_pass_entry.configure(show="*")
            self.stego_confirm_entry.configure(show="*")
            self.stego_show_btn.configure(text="Show")
    
    def _toggle_extract_password(self):
        """Mostra/nasconde la password nella sezione Extract"""
        self.extract_show_password = not self.extract_show_password
        if self.extract_show_password:
            self.extract_pass_entry.configure(show="")
            self.extract_show_btn.configure(text="Hide")
        else:
            self.extract_pass_entry.configure(show="*")
            self.extract_show_btn.configure(text="Show")
    
    def _browse_file_var(self, var, type_="file"):
        if type_ == "image":
            path = filedialog.askopenfilename(title="Select image", filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp *.tiff"), ("All", "*.*")])
        else:
            path = filedialog.askopenfilename(title="Select file", filetypes=[("All", "*.*")])
        if path:
            var.set(path)
    
    def _browse_save_var(self, var):
        path = filedialog.asksaveasfilename(title="Save image", defaultextension=".png", filetypes=[("PNG", "*.png"), ("BMP", "*.bmp"), ("JPEG", "*.jpg"), ("All", "*.*")])
        if path:
            var.set(path)
    
    def _browse_dir_var(self, var):
        path = filedialog.askdirectory(title="Select folder")
        if path:
            var.set(path)
    
    def _do_hide(self):
        img = self.hide_image_var.get()
        fil = self.hide_file_var.get()
        out = self.hide_output_var.get()
        method = self.hide_method_var.get()
        
        if not img:
            messagebox.showerror("Error", "Select a cover image")
            return
        if not fil:
            messagebox.showerror("Error", "Select a file to hide")
            return
        if not out:
            messagebox.showerror("Error", "Specify output path")
            return
        
        password = None
        if self.use_encryption.get():
            password = self.stego_pass_entry.get()
            if not password:
                messagebox.showerror("Error", "Password required")
                return
            if password != self.stego_confirm_entry.get():
                messagebox.showerror("Error", "Passwords do not match")
                return
        
        try:
            if method == "lsb":
                self.stego.hide_lsb(img, fil, out, password)
            else:
                self.stego.hide_append(img, fil, out, password)
            messagebox.showinfo("Success", "File hidden successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            password = None
            self._clear_stego_password()
    
    def _do_extract(self):
        img = self.extract_image_var.get()
        out = self.extract_dir_var.get()
        password = self.extract_password.get()
        
        if not img:
            messagebox.showerror("Error", "Select an image")
            return
        if not out:
            out = str(Path.home() / "Desktop")
            self.extract_dir_var.set(out)
        
        try:
            payload = self.stego.extract_lsb(img)
            if not payload:
                payload = self.stego.extract_append(img)
            if not payload:
                messagebox.showwarning("Warning", "No hidden file found")
                return
            
            if self.stego.is_encrypted(payload) and not password:
                messagebox.showerror("Error", "Password required for encrypted file")
                return
            
            file_name, file_data = self.stego.process_payload(payload, password or None)
            path = self.stego.save_file(file_name, file_data, out)
            messagebox.showinfo("Success", f"Extracted: {path.name}")
        except Exception as e:
            # CryptonError already carries the specific message (wrong password / integrity / algorithm)
            messagebox.showerror("Error", str(e))
        finally:
            password = None
            self._clear_extract_password()
    
    # ========================================================================
    # PASSWORD CLEANUP
    # ========================================================================
    def _clear_crypto_password(self):
        """Clears the password fields of the Cryptography page (entries + variables)."""
        self.pass_entry.delete(0, "end")
        self.confirm_pass_entry.delete(0, "end")
        self.password.set("")
        self.confirm_password.set("")
    
    def _clear_stego_password(self):
        """Clears the password fields of the Hide section."""
        for entry in (self.stego_pass_entry, self.stego_confirm_entry):
            entry.delete(0, "end")
    
    def _clear_extract_password(self):
        """Clears the password field of the Extract section (entry + variable)."""
        self.extract_pass_entry.delete(0, "end")
        self.extract_password.set("")
    
    # ========================================================================
    # CRYPTO HELPERS
    # ========================================================================
    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select file", filetypes=[("All files", "*.*"), ("Crypton files", "*.crypton")])
        if path:
            self.file_path.set(path)
            self.current_file = Path(path)
            self._update_file_info()
    
    def _toggle_password(self):
        """Mostra/nasconde entrambe le password nella sezione Cryptography"""
        self.show_password = not self.show_password
        if self.show_password:
            self.pass_entry.configure(show="")
            self.confirm_pass_entry.configure(show="")
            self.show_btn.configure(text="Hide")
        else:
            self.pass_entry.configure(show="*")
            self.confirm_pass_entry.configure(show="*")
            self.show_btn.configure(text="Show")
    
    def _on_file_change(self, *args):
        path = self.file_path.get().strip()
        if path and Path(path).exists():
            self.current_file = Path(path)
            self._update_file_info()
        else:
            self.current_file = None
            self.file_info_frame.pack_forget()
    
    def _update_file_info(self):
        if self.current_file and self.current_file.exists():
            size = self.current_file.stat().st_size
            info_text = f"{self.current_file.name} | {self._format_size(size)}"
            if self.current_file.suffix.lower() == '.crypton':
                try:
                    self.crypto.verify(self.current_file)
                    info_text += " | Valid Crypton file"
                except CryptonError as e:
                    info_text += f" | {e}"
                except Exception:
                    pass
            self.file_info_frame.pack(fill="x")
            self.file_info_label.configure(text=info_text)
            self.file_info_icon.configure(text="OK", text_color=COLORS["success"])
    
    def _run_async(self, func, *args, fmt=None):
        self._set_buttons_enabled(False)
        
        def wrapper():
            try:
                result = func(*args)
                self.root.after(0, lambda: self._on_operation_done(result, True, fmt))
            except Exception as err:
                error_msg = str(err) or err.__class__.__name__
                self.root.after(0, lambda: self._on_operation_done(error_msg, False, fmt))
        
        threading.Thread(target=wrapper, daemon=True).start()
    
    def _on_operation_done(self, result, success, fmt=None):
        self._set_buttons_enabled(True)
        # After every operation the passwords must not stay in the fields
        self._clear_crypto_password()
        
        if success and fmt is not None:
            title, msg = fmt(result)
            messagebox.showinfo(title, msg)
        elif success and isinstance(result, dict):
            msg = "Success\n\n"
            msg += f"Input: {result.get('input', 'N/A')}\n"
            msg += f"Output: {result.get('output', 'N/A')}\n"
            if 'size_original' in result:
                msg += f"Original: {self._format_size(result['size_original'])}\n"
            if 'size_encrypted' in result:
                msg += f"Encrypted: {self._format_size(result['size_encrypted'])}\n"
            messagebox.showinfo("Success", msg)
        elif success:
            messagebox.showinfo("Success", "Operation completed successfully!")
        else:
            messagebox.showerror("Error", result)
    
    def _encrypt(self):
        if not self.current_file:
            messagebox.showerror("Error", "Select a file")
            return
        if not self.password.get():
            messagebox.showerror("Error", "Enter a password")
            return
        if self.password.get() != self.confirm_password.get():
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        default = f"{self.current_file.stem}.crypton"
        output = filedialog.asksaveasfilename(defaultextension=".crypton", initialfile=default, filetypes=[("Crypton files", "*.crypton"), ("All", "*.*")])
        if output:
            self._run_async(self.crypto.encrypt, self.current_file, Path(output), self.password.get())
        else:
            self._clear_crypto_password()
    
    def _decrypt(self):
        if not self.current_file:
            messagebox.showerror("Error", "Select a file")
            return
        if self.current_file.suffix.lower() != '.crypton':
            messagebox.showerror("Error", "Not a Crypton file")
            return
        if not self.password.get():
            messagebox.showerror("Error", "Enter the password")
            return
        
        # The original extension is stored in the header: no guessing from the file name
        try:
            ext = self.crypto.verify(self.current_file)['extension']
        except (CryptonError, OSError) as e:
            messagebox.showerror("Error", str(e))
            self._clear_crypto_password()
            return
        
        default = f"{self.current_file.stem}_decrypted{ext}"
        output = filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile=default,
            filetypes=[("All files", "*.*")]
        )
        if output:
            self._run_async(self.crypto.decrypt, self.current_file, Path(output), self.password.get())
        else:
            self._clear_crypto_password()
    
    @staticmethod
    def _format_timestamp(ts):
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        except (OverflowError, OSError, ValueError):
            return "N/A"
    
    def _format_verify(self, info):
        if info['authenticated']:
            msg = "Integrity verified: password, header, data and SHA-256 are all valid\n\n"
        else:
            msg = "Valid Crypton structure\n(enter the password for a full integrity check)\n\n"
        msg += f"Version: {info['version']}\n"
        msg += f"Algorithm: {info['algorithm']}\n"
        msg += f"Original Size: {self._format_size(info['size_original'])}\n"
        msg += f"Original Extension: {info['extension'] or '(none)'}\n"
        msg += f"Compressed: {'yes' if info['compressed'] else 'no'}\n"
        msg += f"Created: {self._format_timestamp(info['timestamp'])}"
        return "Verify", msg
    
    def _verify(self):
        if not self.current_file:
            messagebox.showerror("Error", "Select a file")
            return
        password = self.password.get()
        if password:
            # Full check (scrypt + in-memory decryption): run outside the UI thread
            self._run_async(self.crypto.verify, self.current_file, password, fmt=self._format_verify)
            return
        try:
            info = self.crypto.verify(self.current_file)
            messagebox.showinfo(*self._format_verify(info))
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _show_info(self):
        if not self.current_file:
            messagebox.showerror("Error", "Select a file")
            return
        size = self.current_file.stat().st_size
        info = "File Information\n\n"
        info += f"Name: {self.current_file.name}\n"
        info += f"Size: {self._format_size(size)}\n"
        info += f"Path: {self.current_file.parent}\n"
        if self.current_file.suffix.lower() == '.crypton':
            try:
                cinfo = self.crypto.verify(self.current_file)
                info += "\n--- Crypton Metadata ---\n"
                info += f"Algorithm: {cinfo['algorithm']}\n"
                info += f"Original: {self._format_size(cinfo['size_original'])}\n"
                info += f"Original Extension: {cinfo['extension'] or '(none)'}"
            except Exception:
                pass
        messagebox.showinfo("File Info", info)
    
    def run(self):
        self.root.mainloop()


# ============================================================================
# MAIN
# ============================================================================
if __name__ == "__main__":
    app = CryptonApp()
    app.run()