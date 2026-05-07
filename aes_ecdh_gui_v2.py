import os
import base64
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# Constants
# ============================================================

APP_TITLE = "X25519 + AES-256-GCM Secure Tool"

NONCE_SIZE = 12
AES_KEY_SIZE = 32

MAGIC = b"AECDH1"
TOKEN_PREFIX = "AECDH1."

DIR_A2B = b"\x01"
DIR_B2A = b"\x02"

ROLE_ALICE = "alice"
ROLE_BOB = "bob"


# ============================================================
# Encoding helpers
# ============================================================

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64decode(data: str) -> bytes:
    cleaned = "".join(data.strip().split())
    return base64.b64decode(cleaned, validate=True)


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64u_decode(data: str) -> bytes:
    cleaned = data.strip()
    padding = "=" * (-len(cleaned) % 4)
    return base64.urlsafe_b64decode(cleaned + padding)


# ============================================================
# X25519
# ============================================================

def generate_private_key():
    return x25519.X25519PrivateKey.generate()


def get_public_key_b64(private_key) -> str:
    public_key = private_key.public_key()

    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return b64encode(raw_public)


def load_public_key_from_b64(public_key_b64: str):
    raw_public = b64decode(public_key_b64)

    if len(raw_public) != 32:
        raise ValueError("X25519 public key должен быть ровно 32 байта")

    return x25519.X25519PublicKey.from_public_bytes(raw_public)


def fingerprint_public_key(public_key_b64: str) -> str:
    raw = b64decode(public_key_b64)
    digest = hashlib.sha256(raw).digest()
    return ":".join(f"{b:02x}" for b in digest[:16])


# ============================================================
# Key derivation
# ============================================================

def make_transcript_hash(alice_public_b64: str, bob_public_b64: str) -> bytes:
    """
    Transcript hash привязан к ролям.

    Важно:
    - Alice public key всегда идёт первым;
    - Bob public key всегда идёт вторым.

    Если пользователи перепутают роли, код проверки не совпадёт.
    """
    alice_raw = b64decode(alice_public_b64)
    bob_raw = b64decode(bob_public_b64)

    if len(alice_raw) != 32:
        raise ValueError("Alice public key должен быть 32 байта")

    if len(bob_raw) != 32:
        raise ValueError("Bob public key должен быть 32 байта")

    return hashlib.sha256(
        b"AECDH1 transcript\n"
        b"role:alice\n" + alice_raw + b"\n"
        b"role:bob\n" + bob_raw + b"\n"
    ).digest()


def hkdf_derive(shared_secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def format_verification_code(raw: bytes) -> str:
    """
    Код проверки не является ключом.

    Используем Base32 без padding, группами по 4 символа.
    10 байт = 80 бит проверочного кода.
    """
    code = base64.b32encode(raw).decode("utf-8").rstrip("=")
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


def derive_session_material(private_key, peer_public_b64: str, my_role: str):
    """
    Возвращает session dict:

    {
        role,
        transcript_hash,
        key_a2b,
        key_b2a,
        verification_code
    }

    key_a2b используется для сообщений Alice -> Bob.
    key_b2a используется для сообщений Bob -> Alice.
    """
    if my_role not in (ROLE_ALICE, ROLE_BOB):
        raise ValueError("Некорректная роль")

    my_public_b64 = get_public_key_b64(private_key)
    peer_public_key = load_public_key_from_b64(peer_public_b64)

    if peer_public_b64.strip() == my_public_b64:
        raise ValueError("Public key собеседника совпадает с вашим public key")

    shared_secret = private_key.exchange(peer_public_key)

    if my_role == ROLE_ALICE:
        alice_public_b64 = my_public_b64
        bob_public_b64 = peer_public_b64
    else:
        alice_public_b64 = peer_public_b64
        bob_public_b64 = my_public_b64

    transcript_hash = make_transcript_hash(
        alice_public_b64,
        bob_public_b64
    )

    key_a2b = hkdf_derive(
        shared_secret=shared_secret,
        salt=transcript_hash,
        info=b"AECDH1 key Alice-to-Bob",
        length=AES_KEY_SIZE
    )

    key_b2a = hkdf_derive(
        shared_secret=shared_secret,
        salt=transcript_hash,
        info=b"AECDH1 key Bob-to-Alice",
        length=AES_KEY_SIZE
    )

    verification_raw = hkdf_derive(
        shared_secret=shared_secret,
        salt=transcript_hash,
        info=b"AECDH1 verification code",
        length=10
    )

    verification_code = format_verification_code(verification_raw)

    return {
        "role": my_role,
        "transcript_hash": transcript_hash,
        "key_a2b": key_a2b,
        "key_b2a": key_b2a,
        "verification_code": verification_code,
    }


# ============================================================
# AES-GCM message format
# ============================================================

def encrypt_message(session: dict, plaintext: str) -> str:
    """
    Формат токена:

    AECDH1.base64url(
        MAGIC          6 bytes
        direction      1 byte
        nonce          12 bytes
        ciphertext+tag variable
    )

    direction:
    0x01 = Alice -> Bob
    0x02 = Bob -> Alice
    """
    role = session["role"]

    if role == ROLE_ALICE:
        direction = DIR_A2B
        key = session["key_a2b"]
    elif role == ROLE_BOB:
        direction = DIR_B2A
        key = session["key_b2a"]
    else:
        raise ValueError("Некорректная роль в session")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    header = MAGIC + direction

    aad = (
        b"AECDH1 aad\n" +
        header +
        session["transcript_hash"]
    )

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        aad
    )

    raw_token = header + nonce + ciphertext

    return TOKEN_PREFIX + b64u_encode(raw_token)


def decrypt_message(session: dict, token: str) -> str:
    token = token.strip()

    if not token.startswith(TOKEN_PREFIX):
        raise ValueError("Неверный формат токена. Ожидается AECDH1...")

    encoded = token[len(TOKEN_PREFIX):]
    raw = b64u_decode(encoded)

    min_len = len(MAGIC) + 1 + NONCE_SIZE + 16

    if len(raw) < min_len:
        raise ValueError("Слишком короткий токен")

    magic = raw[:len(MAGIC)]

    if magic != MAGIC:
        raise ValueError("Неверная версия сообщения")

    direction = raw[len(MAGIC):len(MAGIC) + 1]
    nonce_start = len(MAGIC) + 1
    nonce_end = nonce_start + NONCE_SIZE

    nonce = raw[nonce_start:nonce_end]
    ciphertext = raw[nonce_end:]

    if direction == DIR_A2B:
        key = session["key_a2b"]
    elif direction == DIR_B2A:
        key = session["key_b2a"]
    else:
        raise ValueError("Некорректное направление сообщения")

    header = magic + direction

    aad = (
        b"AECDH1 aad\n" +
        header +
        session["transcript_hash"]
    )

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        aad
    )

    return plaintext.decode("utf-8")


# ============================================================
# Tkinter UI
# ============================================================

class AESECDHApp:
    def __init__(self, root):
        self.root = root

        self.root.title(APP_TITLE)
        self.root.geometry("980x790")
        self.root.minsize(850, 680)

        self.private_key = None
        self.my_public_b64 = None
        self.session = None

        self.create_widgets()

    # --------------------------------------------------------

    def create_widgets(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(
            main,
            text="X25519 ECDH + HKDF-SHA256 + AES-256-GCM",
            font=("Arial", 15, "bold")
        )
        title.pack(pady=(0, 10))

        self.create_key_exchange_frame(main)
        self.create_crypto_frame(main)
        self.create_status_bar(main)

    # --------------------------------------------------------

    def create_key_exchange_frame(self, parent):
        frame = ttk.LabelFrame(
            parent,
            text="1. Обмен публичными ключами и выработка общего секрета",
            padding=10
        )
        frame.pack(fill=tk.BOTH, expand=False)

        role_row = ttk.Frame(frame)
        role_row.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(role_row, text="Моя роль:").pack(side=tk.LEFT)

        self.role_var = tk.StringVar(value=ROLE_ALICE)

        ttk.Radiobutton(
            role_row,
            text="Alice",
            variable=self.role_var,
            value=ROLE_ALICE,
            command=self.invalidate_session
        ).pack(side=tk.LEFT, padx=(8, 0))

        ttk.Radiobutton(
            role_row,
            text="Bob",
            variable=self.role_var,
            value=ROLE_BOB,
            command=self.invalidate_session
        ).pack(side=tk.LEFT, padx=(8, 0))

        role_hint = ttk.Label(
            role_row,
            text="Один пользователь выбирает Alice, второй — Bob.",
            foreground="#555555"
        )
        role_hint.pack(side=tk.LEFT, padx=12)

        buttons_row = ttk.Frame(frame)
        buttons_row.pack(fill=tk.X, pady=(0, 8))

        ttk.Button(
            buttons_row,
            text="Сгенерировать мой ключ",
            command=self.generate_my_key
        ).pack(side=tk.LEFT)

        ttk.Button(
            buttons_row,
            text="Скопировать мой public key",
            command=self.copy_my_public_key
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            buttons_row,
            text="Вставить public key собеседника",
            command=self.paste_peer_public_key
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            buttons_row,
            text="Выработать ключи AES",
            command=self.derive_session
        ).pack(side=tk.LEFT, padx=5)

        keys_area = ttk.Frame(frame)
        keys_area.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(keys_area)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        right = ttk.Frame(keys_area)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        ttk.Label(
            left,
            text="Мой public key, отправить собеседнику:"
        ).pack(anchor=tk.W)

        self.my_public_text = ScrolledText(left, height=5, wrap=tk.WORD)
        self.my_public_text.pack(fill=tk.BOTH, expand=True)
        self.my_public_text.configure(state=tk.DISABLED)

        ttk.Label(
            right,
            text="Public key собеседника, вставить сюда:"
        ).pack(anchor=tk.W)

        self.peer_public_text = ScrolledText(right, height=5, wrap=tk.WORD)
        self.peer_public_text.pack(fill=tk.BOTH, expand=True)

        info_row = ttk.Frame(frame)
        info_row.pack(fill=tk.X, pady=(8, 0))

        ttk.Label(info_row, text="Код проверки:").pack(side=tk.LEFT)

        self.verification_code_var = tk.StringVar(value="ключи ещё не выработаны")

        self.verification_code_entry = ttk.Entry(
            info_row,
            textvariable=self.verification_code_var,
            state="readonly",
            width=38
        )
        self.verification_code_entry.pack(side=tk.LEFT, padx=5)

        ttk.Button(
            info_row,
            text="Копировать код проверки",
            command=self.copy_verification_code
        ).pack(side=tk.LEFT, padx=5)

        self.fingerprint_var = tk.StringVar(value="Fingerprint моего public key: нет")

        ttk.Label(
            frame,
            textvariable=self.fingerprint_var
        ).pack(anchor=tk.W, pady=(6, 0))

        hint = ttk.Label(
            frame,
            text=(
                "Важно: код проверки не является ключом. "
                "Alice и Bob должны сравнить его по доверенному каналу. "
                "Если код не совпал — использовать соединение нельзя."
            ),
            foreground="#555555"
        )
        hint.pack(anchor=tk.W, pady=(5, 0))

    # --------------------------------------------------------

    def create_crypto_frame(self, parent):
        frame = ttk.LabelFrame(
            parent,
            text="2. AES-256-GCM Encrypt / Decrypt",
            padding=10
        )
        frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        mode_row = ttk.Frame(frame)
        mode_row.pack(fill=tk.X)

        self.mode_var = tk.StringVar(value="encrypt")

        ttk.Radiobutton(
            mode_row,
            text="Encrypt",
            variable=self.mode_var,
            value="encrypt",
            command=self.update_crypto_labels
        ).pack(side=tk.LEFT)

        ttk.Radiobutton(
            mode_row,
            text="Decrypt",
            variable=self.mode_var,
            value="decrypt",
            command=self.update_crypto_labels
        ).pack(side=tk.LEFT, padx=10)

        ttk.Button(
            mode_row,
            text="Вставить ввод",
            command=self.paste_input
        ).pack(side=tk.RIGHT)

        ttk.Button(
            mode_row,
            text="Очистить ввод",
            command=self.clear_input
        ).pack(side=tk.RIGHT, padx=5)

        self.input_label = ttk.Label(frame, text="Текст для шифрования:")
        self.input_label.pack(anchor=tk.W, pady=(8, 3))

        self.input_text = ScrolledText(frame, height=8, wrap=tk.WORD)
        self.input_text.pack(fill=tk.BOTH, expand=True)

        action_row = ttk.Frame(frame)
        action_row.pack(fill=tk.X, pady=8)

        self.action_button = ttk.Button(
            action_row,
            text="Зашифровать",
            command=self.process_crypto
        )
        self.action_button.pack(side=tk.LEFT)

        ttk.Button(
            action_row,
            text="Очистить всё",
            command=self.clear_all_crypto
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            action_row,
            text="Копировать результат",
            command=self.copy_output
        ).pack(side=tk.RIGHT)

        ttk.Button(
            action_row,
            text="Очистить результат",
            command=self.clear_output
        ).pack(side=tk.RIGHT, padx=5)

        ttk.Label(frame, text="Результат:").pack(anchor=tk.W, pady=(3, 3))

        self.output_text = ScrolledText(frame, height=8, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True)

    # --------------------------------------------------------

    def create_status_bar(self, parent):
        self.status_var = tk.StringVar(
            value="Выбери роль, затем сгенерируй ключ."
        )

        ttk.Label(
            parent,
            textvariable=self.status_var,
            anchor=tk.W
        ).pack(fill=tk.X, pady=(8, 0))

    # ========================================================
    # Session actions
    # ========================================================

    def invalidate_session(self):
        self.session = None
        self.verification_code_var.set("ключи ещё не выработаны")
        self.status_var.set("Роль изменена. Нужно заново выработать ключи AES.")

    # --------------------------------------------------------

    def generate_my_key(self):
        self.private_key = generate_private_key()
        self.my_public_b64 = get_public_key_b64(self.private_key)
        self.session = None

        self.verification_code_var.set("ключи ещё не выработаны")

        self.set_text(
            self.my_public_text,
            self.my_public_b64,
            readonly=True
        )

        try:
            fp = fingerprint_public_key(self.my_public_b64)
            self.fingerprint_var.set(f"Fingerprint моего public key: {fp}")
        except Exception:
            self.fingerprint_var.set("Fingerprint моего public key: ошибка")

        self.status_var.set(
            "Ключ сгенерирован. Отправь public key собеседнику."
        )

    # --------------------------------------------------------

    def derive_session(self):
        if self.private_key is None or not self.my_public_b64:
            messagebox.showwarning(
                "Нет моего ключа",
                "Сначала нажми «Сгенерировать мой ключ»."
            )
            return

        peer_public_b64 = self.peer_public_text.get("1.0", tk.END).strip()

        if not peer_public_b64:
            messagebox.showwarning(
                "Нет public key собеседника",
                "Вставь public key собеседника."
            )
            return

        my_role = self.role_var.get()

        try:
            session = derive_session_material(
                private_key=self.private_key,
                peer_public_b64=peer_public_b64,
                my_role=my_role
            )

            self.session = session

            verification_code = session["verification_code"]
            self.verification_code_var.set(verification_code)

            self.status_var.set(
                "Ключи AES выработаны. Сравни код проверки с собеседником."
            )

            messagebox.showinfo(
                "Ключи выработаны",
                "Ключи AES успешно выработаны.\n\n"
                f"Моя роль: {my_role}\n\n"
                f"Код проверки:\n{verification_code}\n\n"
                "Сравни этот код с собеседником по доверенному каналу.\n"
                "Если код не совпадает — использовать соединение нельзя."
            )

        except Exception as e:
            self.session = None
            self.verification_code_var.set("ошибка")

            messagebox.showerror(
                "Ошибка",
                f"Не удалось выработать ключи.\n\n{str(e)}"
            )

    # ========================================================
    # Crypto actions
    # ========================================================

    def process_crypto(self):
        if self.session is None:
            messagebox.showwarning(
                "Нет ключей AES",
                "Сначала выработай ключи AES через X25519."
            )
            return

        mode = self.mode_var.get()

        try:
            if mode == "encrypt":
                plaintext = self.input_text.get("1.0", "end-1c")

                if plaintext == "":
                    messagebox.showwarning(
                        "Пустой ввод",
                        "Введите текст для шифрования."
                    )
                    return

                result = encrypt_message(
                    session=self.session,
                    plaintext=plaintext
                )

            else:
                token = self.input_text.get("1.0", tk.END).strip()

                if not token:
                    messagebox.showwarning(
                        "Пустой ввод",
                        "Введите токен AECDH1 для расшифровки."
                    )
                    return

                result = decrypt_message(
                    session=self.session,
                    token=token
                )

            self.set_text(self.output_text, result, readonly=False)

        except Exception:
            messagebox.showerror(
                "Ошибка",
                "Операция не выполнена.\n\n"
                "Возможные причины:\n"
                "- неверный общий секрет;\n"
                "- код проверки не совпадал;\n"
                "- сообщение повреждено;\n"
                "- сообщение подменено;\n"
                "- неверная роль Alice/Bob;\n"
                "- неверный формат токена."
            )

    # ========================================================
    # UI helpers
    # ========================================================

    def update_crypto_labels(self):
        if self.mode_var.get() == "encrypt":
            self.input_label.config(text="Текст для шифрования:")
            self.action_button.config(text="Зашифровать")
        else:
            self.input_label.config(text="Токен AECDH1 для расшифровки:")
            self.action_button.config(text="Расшифровать")

    # --------------------------------------------------------

    def set_text(self, widget, value: str, readonly=False):
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, value)

        if readonly:
            widget.configure(state=tk.DISABLED)

    # --------------------------------------------------------

    def copy_to_clipboard(self, text: str, title="Буфер обмена"):
        if not text:
            messagebox.showinfo(title, "Нечего копировать.")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

        messagebox.showinfo(title, "Скопировано.")

    # --------------------------------------------------------

    def copy_my_public_key(self):
        if not self.my_public_b64:
            messagebox.showwarning(
                "Нет ключа",
                "Сначала сгенерируй public key."
            )
            return

        self.copy_to_clipboard(self.my_public_b64, "Public key")

    # --------------------------------------------------------

    def copy_verification_code(self):
        if self.session is None:
            messagebox.showwarning(
                "Нет кода проверки",
                "Сначала выработай ключи AES."
            )
            return

        self.copy_to_clipboard(
            self.session["verification_code"],
            "Код проверки"
        )

    # --------------------------------------------------------

    def copy_output(self):
        result = self.output_text.get("1.0", "end-1c")

        if not result:
            messagebox.showinfo("Результат", "Результат пуст.")
            return

        self.copy_to_clipboard(result, "Результат")

    # --------------------------------------------------------

    def paste_peer_public_key(self):
        try:
            data = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showinfo("Буфер обмена", "Буфер обмена пуст.")
            return

        self.peer_public_text.delete("1.0", tk.END)
        self.peer_public_text.insert(tk.END, data.strip())

    # --------------------------------------------------------

    def paste_input(self):
        try:
            data = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showinfo("Буфер обмена", "Буфер обмена пуст.")
            return

        self.input_text.insert(tk.END, data)

    # --------------------------------------------------------

    def clear_input(self):
        self.input_text.delete("1.0", tk.END)

    # --------------------------------------------------------

    def clear_output(self):
        self.output_text.delete("1.0", tk.END)

    # --------------------------------------------------------

    def clear_all_crypto(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    root = tk.Tk()
    app = AESECDHApp(root)
    root.mainloop()
