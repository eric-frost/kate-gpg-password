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
- **Encrypted bytes are written directly to disk** after Kate's save, replacing
  the plaintext Kate would otherwise write, which also avoids line-ending
  mangling of the ASCII armor.
- **Diagnostics are off by default.** Set `KATE_GPG_PASSWORD_DEBUG=1` to enable a
  debug log; it is written to the per-user runtime dir (`$XDG_RUNTIME_DIR`, mode
  0700) and **never contains plaintext or passphrases** — only sizes and status.

## Known limitations

1. **Notepad3 / NotepadCrypt import is weak — legacy compatibility only.** That
   format derives its key as unsalted, single-pass `SHA-256(passphrase)` and uses
   AES-256-CBC with **no message authentication**. This is fast to brute-force and
   offers no tamper detection. The plugin supports it only to read/update existing
   files; **never create new secrets in this format** — use the default GPG format.

2. **The save path writes plaintext to disk first, then overwrites it with
   ciphertext.** On save, Kate writes the plaintext buffer to the file, and the
   plugin then re-encrypts and overwrites it (on `documentSavedOrUploaded`). This
   leaves a window in which plaintext exists on disk, and the overwrite does not
   guarantee the original plaintext blocks are unrecoverable from the underlying
   storage. If the re-encryption step is interrupted (crash, power loss) or the
   document is in a conflicted state (e.g. Kate's "file changed on disk" prompt),
   the file can remain **plaintext on disk**. Mitigations: keep your home/notes on
   an encrypted filesystem, save once and deliberately, and resolve any
   "file changed on disk" dialog with care. Hardening the save path so plaintext
   is never written to disk is a known TODO.

3. **Kate swap files may persist decrypted text.** Kate writes a crash-recovery
   swap file (e.g. `.<name>.kate-swp`) that can contain unsaved buffer
   contents — which here is *plaintext*. There is no clean per-document API to
   disable it. To avoid leaving plaintext on disk, disable swap files in
   **Settings → Configure Kate → Open/Save → Advanced → Backup & Swap** (set swap
   file to *Disabled*), ideally on an encrypted home/partition.

4. **Plaintext and passphrases live in process memory** as Qt strings and are not
   securely wiped. Qt's implicit sharing makes reliable zeroization impractical.
   Memory may also reach swap; use an encrypted swap partition.

5. **`gpg` is resolved via `PATH`.** On a normally configured desktop this is the
   system `gpg`. In an environment with an attacker-controlled `PATH`, a malicious
   `gpg` could be invoked.

6. **A passphrase containing a newline** will be truncated at the first newline
   (it is passed as the first stdin line). Avoid newlines in passphrases.

## Cryptographic summary

| Aspect | GPG format (default) | Notepad3 (import only) |
|---|---|---|
| Cipher | AES-256 (OpenPGP) | AES-256-CBC |
| Key derivation | Salted, iterated S2K | Unsalted SHA-256, single pass |
| Integrity | Yes (MDC/AEAD) | None |
| IV/nonce source | GnuPG | OS CSPRNG (`QRandomGenerator::system`) |
| Recommended for new data | **Yes** | **No** |
