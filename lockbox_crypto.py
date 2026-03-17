from __future__ import annotations

import base64
import json
import os
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LOCKBOX_DIR_NAME = ".quantum_lockbox"
MASTER_KEY_FILE_NAME = "master_key.json"
LOCK_STATE_FILE_NAME = "lock_state.json"
MASTER_KEY_VERSION = 1
DEVICE_MASTER_KEY_VERSION = 2
PAYLOAD_VERSION = 1
DEFAULT_KEM_ALGORITHM = "Kyber768"
DEFAULT_MAX_FAILED_ATTEMPTS = 5
DEFAULT_WIPE_ON_LOCKOUT = True

_lockout_max_failed_attempts = DEFAULT_MAX_FAILED_ATTEMPTS
_lockout_wipe_on_lockout = DEFAULT_WIPE_ON_LOCKOUT
_data_dir_cache: Path | None = None


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _data_dir() -> Path:
    override = os.getenv("LOCKBOX_HOME")
    if override:
        return Path(override).expanduser()

    global _data_dir_cache
    if _data_dir_cache is not None:
        return _data_dir_cache

    legacy = Path.home() / LOCKBOX_DIR_NAME
    if os.name != "nt":
        _data_dir_cache = legacy
        return _data_dir_cache

    base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
    preferred = Path(base) / "QuantumLockbox" if base else legacy

    if legacy.exists() and (
        (legacy / MASTER_KEY_FILE_NAME).exists() or (legacy / LOCK_STATE_FILE_NAME).exists()
    ):
        if _can_write_dir(legacy):
            _data_dir_cache = legacy
            return _data_dir_cache
        if _can_write_dir(preferred):
            _migrate_legacy_storage(legacy, preferred)
            _data_dir_cache = preferred
            return _data_dir_cache
        _data_dir_cache = legacy
        return _data_dir_cache

    if _can_write_dir(preferred):
        _data_dir_cache = preferred
        return _data_dir_cache

    _data_dir_cache = legacy
    return _data_dir_cache


def lockbox_home() -> Path:
    return _data_dir()


def _migrate_legacy_storage(from_dir: Path, to_dir: Path) -> None:
    try:
        to_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return

    for name in (MASTER_KEY_FILE_NAME, LOCK_STATE_FILE_NAME):
        src = from_dir / name
        dst = to_dir / name
        if not src.exists() or dst.exists():
            continue
        try:
            _atomic_write_text(dst, src.read_text(encoding="utf-8"))
        except Exception:
            continue


def _can_write_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / f".probe.{uuid.uuid4().hex}.tmp"
        with open(probe, "x", encoding="utf-8") as f:
            f.write("x")
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _master_key_path() -> Path:
    return _data_dir() / MASTER_KEY_FILE_NAME


def _lock_state_path() -> Path:
    return _data_dir() / LOCK_STATE_FILE_NAME


def _best_effort_secure_permissions(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        return


def _atomic_write_text(path: Path, text: str) -> None:
    data_dir = path.parent
    data_dir.mkdir(parents=True, exist_ok=True)

    last_exc: Exception | None = None
    for attempt in range(6):
        tmp_path = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
        try:
            with open(tmp_path, "x", encoding="utf-8", newline="\n") as f:
                f.write(text)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass

            _best_effort_secure_permissions(tmp_path)
            os.replace(tmp_path, path)
            _best_effort_secure_permissions(path)
            return
        except FileExistsError as exc:
            last_exc = exc
        except PermissionError as exc:
            last_exc = exc
            time.sleep(0.05 * (attempt + 1))
        finally:
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Failed to write file atomically")


def _aad_master_key(kem_backend: str, kem_algorithm: str) -> bytes:
    return (
        f"QuantumLockbox|MasterKeyV{MASTER_KEY_VERSION}|{kem_backend}|{kem_algorithm}".encode(
            "utf-8"
        )
    )


def _aad_device_master_key(kem_backend: str, kem_algorithm: str) -> bytes:
    return (
        f"QuantumLockbox|DeviceMasterKeyV{DEVICE_MASTER_KEY_VERSION}|{kem_backend}|{kem_algorithm}".encode(
            "utf-8"
        )
    )


def _aad_payload(kem_backend: str, kem_algorithm: str) -> bytes:
    return (
        f"QuantumLockbox|PayloadV{PAYLOAD_VERSION}|{kem_backend}|{kem_algorithm}".encode("utf-8")
    )


def _dpapi_protect(data: bytes, *, entropy: bytes | None = None) -> bytes:
    if os.name != "nt":
        raise RuntimeError("DPAPI is only available on Windows")

    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    CryptProtectData = crypt32.CryptProtectData
    CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    CryptProtectData.restype = wintypes.BOOL

    LocalFree = kernel32.LocalFree
    LocalFree.argtypes = [ctypes.c_void_p]
    LocalFree.restype = ctypes.c_void_p

    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    ent_blob = None
    if entropy:
        ent_blob = DATA_BLOB(
            len(entropy),
            ctypes.cast(ctypes.create_string_buffer(entropy), ctypes.POINTER(ctypes.c_byte)),
        )
    out_blob = DATA_BLOB()

    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    ok = CryptProtectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob) if ent_blob is not None else None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        LocalFree(out_blob.pbData)


def _dpapi_unprotect(data: bytes, *, entropy: bytes | None = None) -> bytes:
    if os.name != "nt":
        raise RuntimeError("DPAPI is only available on Windows")

    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    CryptUnprotectData = crypt32.CryptUnprotectData
    CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    CryptUnprotectData.restype = wintypes.BOOL

    LocalFree = kernel32.LocalFree
    LocalFree.argtypes = [ctypes.c_void_p]
    LocalFree.restype = ctypes.c_void_p

    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    ent_blob = None
    if entropy:
        ent_blob = DATA_BLOB(
            len(entropy),
            ctypes.cast(ctypes.create_string_buffer(entropy), ctypes.POINTER(ctypes.c_byte)),
        )
    out_blob = DATA_BLOB()

    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    ok = CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob) if ent_blob is not None else None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        LocalFree(out_blob.pbData)


def configure_lockout(*, max_failed_attempts: int = DEFAULT_MAX_FAILED_ATTEMPTS, wipe_on_lockout: bool = True) -> None:
    global _lockout_max_failed_attempts, _lockout_wipe_on_lockout
    if max_failed_attempts < 1:
        raise ValueError("max_failed_attempts must be >= 1")
    _lockout_max_failed_attempts = int(max_failed_attempts)
    _lockout_wipe_on_lockout = bool(wipe_on_lockout)


def _default_lock_state() -> dict[str, Any]:
    return {"failed_attempts": 0, "locked": False}


def get_lock_state() -> dict[str, Any]:
    path = _lock_state_path()
    if not path.exists():
        return _default_lock_state()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return _default_lock_state()
        failed = int(raw.get("failed_attempts", 0))
        locked = bool(raw.get("locked", False))
        reason = raw.get("lock_reason")
        out: dict[str, Any] = {"failed_attempts": max(0, failed), "locked": locked}
        if reason is not None:
            out["lock_reason"] = str(reason)
        return out
    except Exception:
        return _default_lock_state()


def _write_lock_state(state: dict[str, Any]) -> None:
    path = _lock_state_path()
    _atomic_write_text(path, json.dumps(state, separators=(",", ":")))


def _reset_lock_state() -> None:
    _write_lock_state(_default_lock_state())


def _lock_and_optionally_wipe_master_key(*, lock_reason: str) -> None:
    state = get_lock_state()
    state["locked"] = True
    state["lock_reason"] = lock_reason
    _write_lock_state(state)

    if _lockout_wipe_on_lockout:
        try:
            _master_key_path().unlink(missing_ok=True)
        except OSError:
            pass


def _record_failed_attempt_and_check_lockout() -> bool:
    state = get_lock_state()
    if bool(state.get("locked", False)):
        return True

    failed = int(state.get("failed_attempts", 0)) + 1
    state["failed_attempts"] = failed
    _write_lock_state(state)

    if failed >= _lockout_max_failed_attempts:
        _lock_and_optionally_wipe_master_key(lock_reason="too_many_failed_attempts")
        return True
    return False


def _record_successful_unlock() -> None:
    state = get_lock_state()
    if int(state.get("failed_attempts", 0)) != 0 or bool(state.get("locked", False)):
        _reset_lock_state()



def _derive_wrap_key(master_phrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(master_phrase.encode("utf-8"))


def _hkdf_from_shared_secret(shared_secret: bytes, kem_backend: str, kem_algorithm: str) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_aad_payload(kem_backend, kem_algorithm),
    )
    return hkdf.derive(shared_secret)


def _normalize_kem_algorithm(name: str) -> str:
    raw = (name or "").strip()
    if not raw:
        raise ValueError("kem_algorithm must be non-empty")

    lowered = raw.lower()
    if lowered.startswith("kyber"):
        digits = "".join(ch for ch in lowered if ch.isdigit())
        if digits:
            return f"Kyber{digits}"
    return raw


def _select_kem_backend(requested: str | None) -> str:
    if requested:
        backend = requested.strip().lower()
        if backend in {"oqs", "pqcrypto"}:
            return backend
        raise ValueError("kem_backend must be either 'oqs' or 'pqcrypto'")

    try:
        import oqs

        return "oqs"
    except Exception:
        pass

    try:
        import pqcrypto

        return "pqcrypto"
    except Exception as exc:
        raise RuntimeError(
            "No PQC backend available. Install 'pyoqs' (preferred) or 'pqcrypto'."
        ) from exc


def _pqcrypto_kem_module(kem_algorithm: str):
    kem_algorithm = _normalize_kem_algorithm(kem_algorithm)
    from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024

    mapping = {
        "Kyber512": ml_kem_512,
        "Kyber768": ml_kem_768,
        "Kyber1024": ml_kem_1024,
    }
    try:
        return mapping[kem_algorithm]
    except KeyError as exc:
        raise ValueError(f"Unsupported pqcrypto kem_algorithm: {kem_algorithm}") from exc


@dataclass(frozen=True)
class MasterKey:
    kem_backend: str
    kem_algorithm: str
    public_key: bytes
    secret_key: bytes


def enabled_kem_algorithms() -> list[str]:
    try:
        import oqs

        return list(oqs.get_enabled_KEM_mechanisms())
    except Exception:
        return ["Kyber512", "Kyber768", "Kyber1024"]


def initialize_master_key(
    master_phrase: str,
    *,
    kem_algorithm: str = DEFAULT_KEM_ALGORITHM,
    kem_backend: str | None = None,
    overwrite: bool = False,
) -> MasterKey:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not master_phrase or not master_phrase.strip():
        raise ValueError("master_phrase must be non-empty")

    kem_algorithm = _normalize_kem_algorithm(kem_algorithm)
    kem_backend = _select_kem_backend(kem_backend)

    data_dir = _data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)

    path = _master_key_path()
    if path.exists() and not overwrite:
        raise FileExistsError(f"Master key already exists at {path}")

    if kem_backend == "oqs":
        import oqs

        with oqs.KeyEncapsulation(kem_algorithm) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
    else:
        kem = _pqcrypto_kem_module(kem_algorithm)
        public_key, secret_key = kem.generate_keypair()

    salt = os.urandom(16)
    wrap_key = _derive_wrap_key(master_phrase, salt)
    aesgcm = AESGCM(wrap_key)
    nonce = os.urandom(12)
    wrapped_secret_key = aesgcm.encrypt(
        nonce, secret_key, _aad_master_key(kem_backend, kem_algorithm)
    )

    payload: dict[str, Any] = {
        "version": MASTER_KEY_VERSION,
        "kem_backend": kem_backend,
        "kem_algorithm": kem_algorithm,
        "public_key_b64": _b64e(public_key),
        "salt_b64": _b64e(salt),
        "nonce_b64": _b64e(nonce),
        "wrapped_secret_key_b64": _b64e(wrapped_secret_key),
    }

    if overwrite and path.exists():
        try:
            path.unlink()
        except OSError:
            pass

    _atomic_write_text(path, json.dumps(payload, separators=(",", ":")))
    _reset_lock_state()
    return MasterKey(
        kem_backend=kem_backend,
        kem_algorithm=kem_algorithm,
        public_key=public_key,
        secret_key=secret_key,
    )


def initialize_device_master_key(
    *,
    kem_algorithm: str = DEFAULT_KEM_ALGORITHM,
    kem_backend: str | None = None,
    overwrite: bool = False,
) -> MasterKey:
    kem_algorithm = _normalize_kem_algorithm(kem_algorithm)
    kem_backend = _select_kem_backend(kem_backend)

    data_dir = _data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)

    path = _master_key_path()
    if path.exists() and not overwrite:
        raise FileExistsError(f"Master key already exists at {path}")

    if kem_backend == "oqs":
        import oqs

        with oqs.KeyEncapsulation(kem_algorithm) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
    else:
        kem = _pqcrypto_kem_module(kem_algorithm)
        public_key, secret_key = kem.generate_keypair()

    protected_secret_key = _dpapi_protect(
        secret_key, entropy=_aad_device_master_key(kem_backend, kem_algorithm)
    )

    payload: dict[str, Any] = {
        "version": DEVICE_MASTER_KEY_VERSION,
        "kem_backend": kem_backend,
        "kem_algorithm": kem_algorithm,
        "public_key_b64": _b64e(public_key),
        "dpapi_protected_secret_key_b64": _b64e(protected_secret_key),
    }

    if overwrite and path.exists():
        try:
            path.unlink()
        except OSError:
            pass

    _atomic_write_text(path, json.dumps(payload, separators=(",", ":")))
    _reset_lock_state()
    return MasterKey(
        kem_backend=kem_backend,
        kem_algorithm=kem_algorithm,
        public_key=public_key,
        secret_key=secret_key,
    )


def load_device_master_key() -> MasterKey:
    state = get_lock_state()
    if bool(state.get("locked", False)):
        raise PermissionError("Lockbox locked. Master key is unavailable.")

    path = _master_key_path()
    if not path.exists():
        raise FileNotFoundError(
            f"No master key found at {path}. Run initialize_device_master_key() first."
        )

    raw = json.loads(path.read_text(encoding="utf-8"))
    if int(raw.get("version", 0)) != DEVICE_MASTER_KEY_VERSION:
        raise ValueError("Unsupported device master key file version")

    kem_backend = str(raw.get("kem_backend") or "oqs").strip().lower()
    kem_algorithm = _normalize_kem_algorithm(str(raw["kem_algorithm"]))
    public_key = _b64d(str(raw["public_key_b64"]))
    protected_secret_key = _b64d(str(raw["dpapi_protected_secret_key_b64"]))

    secret_key = _dpapi_unprotect(
        protected_secret_key, entropy=_aad_device_master_key(kem_backend, kem_algorithm)
    )

    return MasterKey(
        kem_backend=kem_backend,
        kem_algorithm=kem_algorithm,
        public_key=public_key,
        secret_key=secret_key,
    )


def load_master_key(master_phrase: str) -> MasterKey:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    if not master_phrase or not master_phrase.strip():
        raise ValueError("master_phrase must be non-empty")

    state = get_lock_state()
    if bool(state.get("locked", False)):
        raise PermissionError("Lockbox locked. Master key is unavailable.")

    path = _master_key_path()
    if not path.exists():
        raise FileNotFoundError(
            f"No master key found at {path}. Run initialize_master_key() first."
        )

    raw = json.loads(path.read_text(encoding="utf-8"))
    version = int(raw.get("version", 0))
    if version == DEVICE_MASTER_KEY_VERSION:
        raise ValueError("This vault uses device key protection; no master phrase is used.")
    if version != MASTER_KEY_VERSION:
        raise ValueError("Unsupported master key file version")

    kem_backend = str(raw.get("kem_backend") or "oqs").strip().lower()
    kem_algorithm = _normalize_kem_algorithm(str(raw["kem_algorithm"]))
    public_key = _b64d(str(raw["public_key_b64"]))
    salt = _b64d(str(raw["salt_b64"]))
    nonce = _b64d(str(raw["nonce_b64"]))
    wrapped_secret_key = _b64d(str(raw["wrapped_secret_key_b64"]))

    wrap_key = _derive_wrap_key(master_phrase, salt)
    aesgcm = AESGCM(wrap_key)
    try:
        secret_key = aesgcm.decrypt(
            nonce, wrapped_secret_key, _aad_master_key(kem_backend, kem_algorithm)
        )
    except InvalidTag:
        locked = _record_failed_attempt_and_check_lockout()
        if locked:
            raise PermissionError("Lockbox locked. Master key wiped.") from None
        raise ValueError("Invalid master phrase") from None

    _record_successful_unlock()

    return MasterKey(
        kem_backend=kem_backend,
        kem_algorithm=kem_algorithm,
        public_key=public_key,
        secret_key=secret_key,
    )


def encrypt_text_local(plaintext: str) -> str:
    mk = load_device_master_key()
    return encrypt_text_with_public_key(
        plaintext,
        public_key=mk.public_key,
        kem_algorithm=mk.kem_algorithm,
        kem_backend=mk.kem_backend,
    )


def decrypt_text_local(ciphertext_package: str) -> str:
    mk = load_device_master_key()
    return decrypt_text_with_secret_key(
        ciphertext_package,
        secret_key=mk.secret_key,
        kem_algorithm=mk.kem_algorithm,
        kem_backend=mk.kem_backend,
    )


def encrypt_bytes_local(plaintext: bytes) -> str:
    mk = load_device_master_key()
    return encrypt_bytes_with_public_key(
        plaintext,
        public_key=mk.public_key,
        kem_algorithm=mk.kem_algorithm,
        kem_backend=mk.kem_backend,
    )


def decrypt_bytes_local(ciphertext_package: str) -> bytes:
    mk = load_device_master_key()
    return decrypt_bytes_with_secret_key(
        ciphertext_package,
        secret_key=mk.secret_key,
        kem_algorithm=mk.kem_algorithm,
        kem_backend=mk.kem_backend,
    )


def public_key_package(*, kem_backend: str, kem_algorithm: str, public_key: bytes) -> str:
    kem_algorithm = _normalize_kem_algorithm(kem_algorithm)
    return json.dumps(
        {
            "type": "QuantumLockboxPublicKey",
            "kem_backend": str(kem_backend).strip().lower(),
            "kem_algorithm": kem_algorithm,
            "public_key_b64": _b64e(public_key),
        },
        separators=(",", ":"),
    )


def secret_key_package(*, kem_backend: str, kem_algorithm: str, secret_key: bytes) -> str:
    kem_algorithm = _normalize_kem_algorithm(kem_algorithm)
    return json.dumps(
        {
            "type": "QuantumLockboxSecretKey",
            "kem_backend": str(kem_backend).strip().lower(),
            "kem_algorithm": kem_algorithm,
            "secret_key_b64": _b64e(secret_key),
        },
        separators=(",", ":"),
    )


def parse_public_key_package(package_json: str) -> tuple[str, str, bytes]:
    if package_json is None or not str(package_json).strip():
        raise ValueError("Public key package is empty")
    try:
        raw = json.loads(package_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Public key package is not valid JSON") from exc
    if str(raw.get("type")) != "QuantumLockboxPublicKey":
        raise ValueError("Not a QuantumLockboxPublicKey package")
    kem_backend = str(raw.get("kem_backend") or "").strip().lower()
    kem_algorithm = _normalize_kem_algorithm(str(raw.get("kem_algorithm") or ""))
    public_key = _b64d(str(raw.get("public_key_b64") or ""))
    if not kem_backend:
        raise ValueError("kem_backend missing")
    if not public_key:
        raise ValueError("public_key missing")
    return kem_backend, kem_algorithm, public_key


def parse_secret_key_package(package_json: str) -> tuple[str, str, bytes]:
    if package_json is None or not str(package_json).strip():
        raise ValueError("Secret key package is empty")
    try:
        raw = json.loads(package_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Secret key package is not valid JSON") from exc
    if str(raw.get("type")) != "QuantumLockboxSecretKey":
        raise ValueError("Not a QuantumLockboxSecretKey package")
    kem_backend = str(raw.get("kem_backend") or "").strip().lower()
    kem_algorithm = _normalize_kem_algorithm(str(raw.get("kem_algorithm") or ""))
    secret_key = _b64d(str(raw.get("secret_key_b64") or ""))
    if not kem_backend:
        raise ValueError("kem_backend missing")
    if not secret_key:
        raise ValueError("secret_key missing")
    return kem_backend, kem_algorithm, secret_key

def encrypt_text_with_master_phrase(
    master_phrase: str,
    plaintext: str,
) -> str:
    mk = load_master_key(master_phrase)
    return encrypt_text_with_public_key(
        plaintext,
        public_key=mk.public_key,
        kem_algorithm=mk.kem_algorithm,
        kem_backend=mk.kem_backend,
    )


def encrypt_text_with_public_key(
    plaintext: str,
    *,
    public_key: bytes,
    kem_algorithm: str = DEFAULT_KEM_ALGORITHM,
    kem_backend: str | None = None,
) -> str:
    if plaintext is None:
        raise ValueError("plaintext must be provided")

    return encrypt_bytes_with_public_key(
        plaintext.encode("utf-8"),
        public_key=public_key,
        kem_algorithm=kem_algorithm,
        kem_backend=kem_backend,
    )


def encrypt_bytes_with_public_key(
    plaintext: bytes,
    *,
    public_key: bytes,
    kem_algorithm: str = DEFAULT_KEM_ALGORITHM,
    kem_backend: str | None = None,
) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if plaintext is None:
        raise ValueError("plaintext must be provided")

    kem_algorithm = _normalize_kem_algorithm(kem_algorithm)
    kem_backend = _select_kem_backend(kem_backend)

    if kem_backend == "oqs":
        import oqs

        with oqs.KeyEncapsulation(kem_algorithm) as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(public_key)
    else:
        kem = _pqcrypto_kem_module(kem_algorithm)
        kem_ciphertext, shared_secret = kem.encrypt(public_key)

    aead_key = _hkdf_from_shared_secret(shared_secret, kem_backend, kem_algorithm)
    aesgcm = AESGCM(aead_key)
    nonce = os.urandom(12)
    aead_ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        _aad_payload(kem_backend, kem_algorithm),
    )

    package: dict[str, Any] = {
        "version": PAYLOAD_VERSION,
        "kem_backend": kem_backend,
        "kem_algorithm": kem_algorithm,
        "kem_ciphertext_b64": _b64e(kem_ciphertext),
        "nonce_b64": _b64e(nonce),
        "aead_ciphertext_b64": _b64e(aead_ciphertext),
    }

    return json.dumps(package, separators=(",", ":"))


def decrypt_text_with_master_phrase(master_phrase: str, ciphertext_package: str) -> str:
    mk = load_master_key(master_phrase)
    return decrypt_text_with_secret_key(
        ciphertext_package,
        secret_key=mk.secret_key,
        kem_algorithm=mk.kem_algorithm,
        kem_backend=mk.kem_backend,
    )


def decrypt_text_with_secret_key(
    ciphertext_package: str,
    *,
    secret_key: bytes,
    kem_algorithm: str = DEFAULT_KEM_ALGORITHM,
    kem_backend: str | None = None,
) -> str:
    return decrypt_bytes_with_secret_key(
        ciphertext_package,
        secret_key=secret_key,
        kem_algorithm=kem_algorithm,
        kem_backend=kem_backend,
    ).decode("utf-8")


def decrypt_bytes_with_secret_key(
    ciphertext_package: str,
    *,
    secret_key: bytes,
    kem_algorithm: str = DEFAULT_KEM_ALGORITHM,
    kem_backend: str | None = None,
) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = json.loads(ciphertext_package)
    if int(raw.get("version", 0)) != PAYLOAD_VERSION:
        raise ValueError("Unsupported payload version")

    payload_backend = str(raw.get("kem_backend") or "oqs").strip().lower()
    payload_algorithm = _normalize_kem_algorithm(str(raw["kem_algorithm"]))
    kem_algorithm = _normalize_kem_algorithm(kem_algorithm)
    kem_backend = _select_kem_backend(kem_backend)

    if payload_backend != kem_backend:
        raise ValueError("KEM backend mismatch between payload and master key")
    if payload_algorithm != kem_algorithm:
        raise ValueError("KEM algorithm mismatch between payload and master key")

    kem_ciphertext = _b64d(str(raw["kem_ciphertext_b64"]))
    nonce = _b64d(str(raw["nonce_b64"]))
    aead_ciphertext = _b64d(str(raw["aead_ciphertext_b64"]))

    if kem_backend == "oqs":
        import oqs

        with oqs.KeyEncapsulation(kem_algorithm, secret_key) as kem:
            shared_secret = kem.decap_secret(kem_ciphertext)
    else:
        kem = _pqcrypto_kem_module(kem_algorithm)
        shared_secret = kem.decrypt(secret_key, kem_ciphertext)

    aead_key = _hkdf_from_shared_secret(shared_secret, kem_backend, kem_algorithm)
    aesgcm = AESGCM(aead_key)
    return aesgcm.decrypt(nonce, aead_ciphertext, _aad_payload(kem_backend, kem_algorithm))
