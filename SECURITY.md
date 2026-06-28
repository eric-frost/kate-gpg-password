# Security

This plugin handles secrets. The notes below describe what it does, its threat
model, and its known limitations so you can decide whether it fits your needs.

## Reporting a vulnerability

Please report security issues privately by email rather than opening a public
issue. (Replace with your preferred contact before publishing.)

## What it does

- **New / GPG files**: encryption is delegated to the `gpg` (GnuPG) CLI using
  `--symmetric --cipher-algo AES256 --armor`, which applies a salted, iterated
  String-to-Key (S2K) derivation and an integrity-protected (MDC/AEAD) packet.
  This is the recommended format.
- **Passphrase handling**: the passphrase is sent to `gpg` on **stdin**
  (`--passphrase-fd 0`), prepended as the first line before the data. It is never
  placed on the command line (so it can't appear in `ps`/`/proc`) and never
  written to a temporary file. `--no-symkey-cache` prevents `gpg-agent` from
  caching the symmetric passphrase.
- **Plaintext is never written to the target file.** On save, the plugin
  encrypts the document and swaps the ASCII-armored ciphertext into the editor
  buffer *before* Kate writes (`aboutToSave`), so Kate's own atomic save persists
  ciphertext on every save path (Ctrl+S, the close-with-unsaved-changes prompt,
  Save All, session autosave). Immediately after the write
  (`documentSavedOrUploaded`) the plugin restores the plaintext into the buffer so
  you keep editing normally. If encryption fails (e.g. `gpg` missing), the save is
  refused and the previous ciphertext is kept rather than ever writing plaintext.
- **Diagnostics are off by default.** Set `KATE_GPG_PASSWORD_DEBUG=1` to enable a
  debug log; it is written to the per-user runtime dir (`$XDG_RUNTIME_DIR`, mode
  0700) and **never contains plaintext or passphrases** — only sizes and status.

## Known limitations

1. **Notepad3 / NotepadCrypt import is weak — legacy compatibility only.** That
   format derives its key as unsalted, single-pass `SHA-256(passphrase)` and uses
   AES-256-CBC with **no message authentication**. This is fast to brute-force and
   offers no tamper detection. The plugin **reads** these files but never writes
   them back: saving an imported Notepad3 file migrates it to the stronger GPG
   format. **Never create new secrets in the Notepad3 format.**

2. **Kate's swap file can persist plaintext while you edit.** Kate continuously
   writes the editor buffer — here, your decrypted *plaintext* — to a crash-recovery
   swap file. No KTextEditor plugin can prevent this; it is a Kate-wide setting.
   It is closable with a one-time configuration change — see
   [Closing the Kate swap-file leak](#closing-the-kate-swap-file-leak).

3. **Plaintext and passphrases live in process memory** as Qt strings and are not
   securely wiped. Qt's implicit sharing makes reliable zeroization impractical.
   Memory may also reach swap; use an encrypted swap partition.

4. **`gpg` is resolved via `PATH`.** On a normally configured desktop this is the
   system `gpg`. In an environment with an attacker-controlled `PATH`, a malicious
   `gpg` could be invoked.

5. **A passphrase containing a newline** will be truncated at the first newline
   (it is passed as the first stdin line). Avoid newlines in passphrases.

## Closing the Kate swap-file leak

### The issue

For crash recovery, Kate continuously writes the open editor buffer to a *swap
file* and re-syncs it on a timer (every 15 s by default). While you have a
decrypted document open, that buffer is your **plaintext**, so the plaintext is
written to disk even though the file itself is encrypted. With Kate's default
setting the swap file is a sibling of your document — `~/secret.gpg` produces
`~/.secret.gpg.kate-swp` (mode `0600`, owner-only) — and it persists until the
document is closed cleanly.

This is **not specific to this plugin and cannot be fixed by any plugin**: the
swap file is a global Kate setting with no per-document API. The GPG plugin
bundled with Kate exposes plaintext to the swap file in exactly the same way. So
it must be addressed once, in Kate's configuration, for all files.

### Fix 1 — Redirect the swap file to RAM (keeps crash recovery)

Point Kate's swap directory at a `tmpfs` (RAM-backed) location, so the swap file
lives in memory and never touches persistent disk:

- **GUI:** Settings → Configure Kate → Open/Save → Advanced → *Swap file mode* →
  store swap files in a single directory, and set that directory to a tmpfs path
  (e.g. `/run/user/<your-uid>/kate-swap`, or `/tmp`).
- **Or `~/.config/katerc`:**
  ```ini
  [KTextEditor Document]
  Swap File Mode=2
  Swap Directory=/run/user/1000/kate-swap
  ```
  (replace `1000` with your UID — `id -u`.)

Residual risk: the plaintext still exists in RAM-backed tmpfs (readable by you and
root, and it can be paged to the system swap *partition* under memory pressure).
Use an **encrypted swap partition** to close that last gap.

### Fix 2 — Disable the swap file entirely (simplest)

No swap file is ever written:

- **GUI:** the same dialog → *Swap file mode* → disable.
- **Or `~/.config/katerc`:**
  ```ini
  [KTextEditor Document]
  Swap File Mode=0
  ```

Cost: you lose Kate's crash recovery for **all** files, not just encrypted ones.

Either change takes effect on the next **Kate restart** (or immediately if applied
through the GUI dialog).

## Cryptographic summary

| Aspect | GPG format (default) | Notepad3 (import only) |
|---|---|---|
| Cipher | AES-256 (OpenPGP) | AES-256-CBC |
| Key derivation | Salted, iterated S2K | Unsalted SHA-256, single pass |
| Integrity | Yes (MDC/AEAD) | None |
| IV/nonce source | GnuPG | N/A (read-only; migrates to GPG on save) |
| Recommended for new data | **Yes** | **No** |
