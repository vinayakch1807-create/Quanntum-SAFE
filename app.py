from __future__ import annotations

import json
import os
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import streamlit as st

import lockbox_crypto


st.set_page_config(page_title="Quantum-Safe Digital Lockbox", page_icon="🔐", layout="wide")


st.markdown(
    """
<style>
  :root {
    --bg: #070A0F;
    --panel: rgba(10, 18, 30, 0.72);
    --border: rgba(40, 255, 180, 0.25);
    --grid: rgba(0, 220, 255, 0.08);
    --neon: #20ffb4;
    --blue: #00dcff;
    --text: #d7faff;
    --muted: rgba(215, 250, 255, 0.65);
    --danger: #ff4d6d;
  }

  html, body, [data-testid="stAppViewContainer"] {
    background:
      radial-gradient(1200px 800px at 20% 10%, rgba(32, 255, 180, 0.12), transparent 60%),
      radial-gradient(900px 700px at 80% 20%, rgba(0, 220, 255, 0.10), transparent 55%),
      linear-gradient(180deg, #05070B 0%, var(--bg) 100%);
    color: var(--text);
  }

  [data-testid="stHeader"] { background: transparent; }

  .vault-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 16px 16px 8px 16px;
    box-shadow: 0 0 0 1px rgba(0, 220, 255, 0.06), 0 14px 40px rgba(0, 0, 0, 0.50);
    backdrop-filter: blur(10px);
  }

  .vault-title {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: 1.2px;
    margin: 0 0 8px 0;
  }

  .vault-subtitle {
    color: var(--muted);
    margin: 0 0 18px 0;
  }

  .badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    border: 1px solid rgba(0, 220, 255, 0.22);
    color: rgba(0, 220, 255, 0.90);
    background: rgba(0, 220, 255, 0.06);
    font-size: 12px;
    letter-spacing: 0.6px;
  }

  .gridline {
    background-image:
      linear-gradient(to right, var(--grid) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid) 1px, transparent 1px);
    background-size: 42px 42px;
    border-radius: 14px;
    padding: 14px;
  }

  .stButton > button {
    border: 1px solid rgba(32, 255, 180, 0.35);
    background: rgba(32, 255, 180, 0.08);
    color: var(--text);
    border-radius: 12px;
    padding: 0.6rem 1rem;
  }

  .stButton > button:hover {
    border-color: rgba(0, 220, 255, 0.45);
    background: rgba(0, 220, 255, 0.10);
  }

  [data-testid="stSidebar"] {
    background: rgba(7, 10, 15, 0.65);
    border-right: 1px solid rgba(0, 220, 255, 0.08);
  }

  textarea, input {
    color: var(--text) !important;
  }

  [data-testid="stTextArea"] textarea {
    background: rgba(4, 8, 14, 0.88) !important;
    border: 1px solid rgba(0, 220, 255, 0.18) !important;
    border-radius: 14px !important;
    box-shadow:
      inset 0 0 0 1px rgba(32, 255, 180, 0.08),
      0 10px 28px rgba(0, 0, 0, 0.55) !important;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace !important;
    letter-spacing: 0.2px !important;
    line-height: 1.35 !important;
  }

  [data-testid="stTextArea"] textarea:focus {
    outline: none !important;
    border-color: rgba(32, 255, 180, 0.45) !important;
    box-shadow:
      0 0 0 1px rgba(32, 255, 180, 0.35),
      0 0 0 6px rgba(32, 255, 180, 0.08),
      0 18px 48px rgba(0, 0, 0, 0.60) !important;
  }

  [data-testid="stTextArea"] label {
    color: rgba(215, 250, 255, 0.82) !important;
    letter-spacing: 0.6px !important;
  }

  [data-testid="stTextArea"] textarea::placeholder {
    color: rgba(215, 250, 255, 0.35) !important;
  }

  [data-testid="stTextArea"] textarea::-webkit-scrollbar {
    width: 10px;
  }
  [data-testid="stTextArea"] textarea::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.25);
    border-radius: 999px;
  }
  [data-testid="stTextArea"] textarea::-webkit-scrollbar-thumb {
    background: linear-gradient(180deg, rgba(0, 220, 255, 0.35), rgba(32, 255, 180, 0.35));
    border-radius: 999px;
    border: 2px solid rgba(0, 0, 0, 0.25);
  }
</style>
""",
    unsafe_allow_html=True,
)


def _master_key_status() -> tuple[bool, str]:
    path = lockbox_crypto.lockbox_home() / lockbox_crypto.MASTER_KEY_FILE_NAME
    if not path.exists():
        return False, f"Not found: {path}"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        version = int(raw.get("version", 0))
        backend = str(raw.get("kem_backend") or "oqs")
        alg = str(raw.get("kem_algorithm") or "")
        return True, f"Found: {path} | v{version} | {backend} | {alg}"
    except Exception:
        return True, f"Found: {path} | unreadable metadata"


def _wipe_local_storage() -> None:
    base = lockbox_crypto.lockbox_home()
    for name in (lockbox_crypto.MASTER_KEY_FILE_NAME, lockbox_crypto.LOCK_STATE_FILE_NAME):
        try:
            (base / name).unlink(missing_ok=True)
        except OSError:
            pass


with st.sidebar:
    st.markdown("### Simple Setup")
    mode_options = ["This PC vault", "Website/Server key"] if os.name == "nt" else ["Website/Server key"]
    mode = st.radio(
        "Mode",
        options=mode_options,
        index=0,
        label_visibility="collapsed",
    )
    st.caption(f"Storage: {lockbox_crypto.lockbox_home()}")

    algorithms = lockbox_crypto.enabled_kem_algorithms()
    default_index = algorithms.index("Kyber768") if "Kyber768" in algorithms else 0
    kem_algorithm = st.selectbox("Algorithm", options=algorithms, index=default_index)
    kem_backend = st.selectbox("Backend", options=["Auto", "oqs", "pqcrypto"], index=0)

    col_a, col_b = st.columns(2)
    with col_a:
        status_clicked = st.button("Status", use_container_width=True)
    with col_b:
        wipe_clicked = st.button("Wipe", use_container_width=True)

    if status_clicked:
        ok, msg = _master_key_status()
        if ok:
            st.info(msg)
        else:
            st.warning(msg)

    if wipe_clicked:
        _wipe_local_storage()
        st.success("Local lockbox wiped.")


st.markdown(
    """
<div class="gridline">
  <div class="vault-card">
    <div class="vault-title">QUANTUM-SAFE DIGITAL LOCKBOX</div>
    <div class="vault-subtitle">PQC KEM + AES-GCM • Local vault or encrypt for your own server</div>
    <div class="badge">CYBER VAULT INTERFACE</div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

tabs = st.tabs(["Encrypt", "Decrypt", "Files", "Keys"])

with tabs[3]:
    st.markdown("## Keys")

    selected_backend = None if kem_backend == "Auto" else kem_backend

    if mode == "This PC vault":
        col_a, col_b = st.columns(2)
        with col_a:
            create_clicked = st.button("Create vault keypair", use_container_width=True)
        with col_b:
            overwrite_clicked = st.button("Recreate (overwrite)", use_container_width=True)

        if create_clicked or overwrite_clicked:
            try:
                lockbox_crypto.initialize_device_master_key(
                    kem_algorithm=kem_algorithm,
                    kem_backend=selected_backend,
                    overwrite=bool(overwrite_clicked),
                )
                st.success("Vault keypair created on this PC.")
            except Exception as exc:
                st.error(str(exc))

        try:
            mk = lockbox_crypto.load_device_master_key()
            st.success(f"Ready • {mk.kem_backend} • {mk.kem_algorithm}")
            st.text_area(
                "Public key (share with your server/build system)",
                value=lockbox_crypto.public_key_package(
                    kem_backend=mk.kem_backend, kem_algorithm=mk.kem_algorithm, public_key=mk.public_key
                ),
                height=180,
            )
            st.text_area(
                "Secret key (keep private)",
                value=lockbox_crypto.secret_key_package(
                    kem_backend=mk.kem_backend, kem_algorithm=mk.kem_algorithm, secret_key=mk.secret_key
                ),
                height=180,
            )
        except Exception as exc:
            st.warning(str(exc))

    else:
        st.text_area(
            "Server public key package",
            key="server_public_key_pkg",
            height=180,
            placeholder='Paste JSON with {"type":"QuantumLockboxPublicKey",...}',
        )
        st.text_area(
            "Server secret key package (only if you own it)",
            key="server_secret_key_pkg",
            height=180,
            placeholder='Paste JSON with {"type":"QuantumLockboxSecretKey",...}',
        )

        try:
            kem_b, kem_a, _pk = lockbox_crypto.parse_public_key_package(
                st.session_state.get("server_public_key_pkg", "")
            )
            st.success(f"Public key loaded • {kem_b} • {kem_a}")
        except Exception:
            st.info("Paste a server public key package to encrypt for your website/server.")

with tabs[2]:
    st.markdown("## Files")

    st.markdown("### Encrypt files")
    server_pk_ready = bool(str(st.session_state.get("server_public_key_pkg", "")).strip())
    server_sk_ready = bool(str(st.session_state.get("server_secret_key_pkg", "")).strip())

    files = st.file_uploader(
        "Add files from your computer",
        accept_multiple_files=True,
        label_visibility="collapsed",
    )
    encrypt_files_clicked = st.button(
        "Encrypt selected files",
        use_container_width=True,
        disabled=(mode != "This PC vault" and not server_pk_ready),
    )
    if mode != "This PC vault" and not server_pk_ready:
        st.info("Paste the server public key package in Keys tab first.")
    if encrypt_files_clicked:
        try:
            if not files:
                raise ValueError("Select at least one file")

            items: list[dict[str, object]] = []
            for f in files:
                data = f.getvalue()
                if mode == "This PC vault":
                    ct = lockbox_crypto.encrypt_bytes_local(data)
                else:
                    kem_b, kem_a, pk = lockbox_crypto.parse_public_key_package(
                        st.session_state.get("server_public_key_pkg", "")
                    )
                    ct = lockbox_crypto.encrypt_bytes_with_public_key(
                        data, public_key=pk, kem_backend=kem_b, kem_algorithm=kem_a
                    )
                items.append(
                    {
                        "name": f.name,
                        "type": f.type or "",
                        "size": int(len(data)),
                        "ciphertext": ct,
                    }
                )

            out = json.dumps({"type": "QuantumLockboxFiles", "items": items}, separators=(",", ":"))
            st.session_state["files_package"] = out
            st.success("Files encrypted.")
        except Exception as exc:
            st.error(str(exc))

    st.text_area(
        "Encrypted files package (JSON)",
        value=st.session_state.get("files_package", ""),
        height=220,
        placeholder="Encrypted files package will appear here...",
    )
    if st.session_state.get("files_package"):
        st.download_button(
            "Download encrypted package",
            data=st.session_state["files_package"].encode("utf-8"),
            file_name="lockbox_files.qlb.json",
            mime="application/json",
            use_container_width=True,
        )

    st.markdown("### Decrypt files")
    enc_pkg_file = st.file_uploader(
        "Upload encrypted package (.json)",
        type=["json"],
        key="files_pkg_upload",
        label_visibility="collapsed",
    )
    decrypt_files_clicked = st.button(
        "Decrypt uploaded package",
        use_container_width=True,
        disabled=(mode != "This PC vault" and not server_sk_ready),
    )
    if mode != "This PC vault" and not server_sk_ready:
        st.info("Paste the server secret key package in Keys tab first.")
    if decrypt_files_clicked:
        try:
            if enc_pkg_file is None:
                raise ValueError("Upload an encrypted package first")
            raw_bytes = enc_pkg_file.getvalue()
            if not raw_bytes:
                raise ValueError("Uploaded package is empty")
            try:
                raw = json.loads(raw_bytes.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError("Uploaded package is not valid JSON") from exc
            if str(raw.get("type")) != "QuantumLockboxFiles":
                raise ValueError("Not a QuantumLockboxFiles package")
            items = raw.get("items")
            if not isinstance(items, list) or not items:
                raise ValueError("No items in package")

            buf = BytesIO()
            with ZipFile(buf, "w", compression=ZIP_DEFLATED) as zf:
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name") or "file.bin")
                    ct = str(item.get("ciphertext") or "")
                    if mode == "This PC vault":
                        data = lockbox_crypto.decrypt_bytes_local(ct)
                    else:
                        kem_b, kem_a, sk = lockbox_crypto.parse_secret_key_package(
                            st.session_state.get("server_secret_key_pkg", "")
                        )
                        data = lockbox_crypto.decrypt_bytes_with_secret_key(
                            ct, secret_key=sk, kem_backend=kem_b, kem_algorithm=kem_a
                        )
                    zf.writestr(name, data)

            st.session_state["decrypted_zip"] = buf.getvalue()
            st.success("Files decrypted.")
        except Exception as exc:
            st.error(str(exc))

    if st.session_state.get("decrypted_zip"):
        st.download_button(
            "Download decrypted files (ZIP)",
            data=st.session_state["decrypted_zip"],
            file_name="lockbox_decrypted.zip",
            mime="application/zip",
            use_container_width=True,
        )


with tabs[0]:
    st.markdown("## Encrypt")
    plaintext = st.text_area(
        "Input text",
        height=220,
        placeholder="Paste secrets or config values here...",
    )
    encrypt_clicked = st.button("Encrypt", use_container_width=True)
    if encrypt_clicked:
        try:
            if mode == "This PC vault":
                ciphertext = lockbox_crypto.encrypt_text_local(plaintext)
            else:
                kem_b, kem_a, pk = lockbox_crypto.parse_public_key_package(
                    st.session_state.get("server_public_key_pkg", "")
                )
                ciphertext = lockbox_crypto.encrypt_text_with_public_key(
                    plaintext, public_key=pk, kem_backend=kem_b, kem_algorithm=kem_a
                )
            st.session_state["ciphertext"] = ciphertext
            st.success("Encrypted.")
        except Exception as exc:
            st.error(str(exc))

    st.text_area(
        "Ciphertext (JSON package)",
        value=st.session_state.get("ciphertext", ""),
        height=220,
        placeholder="Ciphertext will appear here...",
    )


with tabs[1]:
    st.markdown("## Decrypt")
    ciphertext_in = st.text_area(
        "Ciphertext (JSON package)",
        value=st.session_state.get("ciphertext", ""),
        height=220,
        placeholder="Paste the JSON ciphertext package here...",
    )
    decrypt_clicked = st.button("Decrypt", use_container_width=True)
    if decrypt_clicked:
        try:
            if mode == "This PC vault":
                recovered = lockbox_crypto.decrypt_text_local(ciphertext_in)
            else:
                kem_b, kem_a, sk = lockbox_crypto.parse_secret_key_package(
                    st.session_state.get("server_secret_key_pkg", "")
                )
                recovered = lockbox_crypto.decrypt_text_with_secret_key(
                    ciphertext_in, secret_key=sk, kem_backend=kem_b, kem_algorithm=kem_a
                )
            st.session_state["recovered_plaintext"] = recovered
            st.success("Decrypted.")
        except Exception as exc:
            st.error(str(exc))

    st.text_area(
        "Recovered plaintext",
        value=st.session_state.get("recovered_plaintext", ""),
        height=220,
        placeholder="Recovered text will appear here...",
    )
