# Contributing

Thanks for your interest in the Kate Simple GPG Plugin.

## Goal

Provide a seamless, **password-based symmetric** encryption workflow for Kate /
KTextEditor — no key management, just a passphrase. Files are ASCII-armored
OpenPGP so they interoperate with GnuPG and Encrypted Notepad II on Android.
This is intentionally simpler than Kate's built-in (key-centric) GPG plugin.

## Building

```bash
cmake -S . -B build -G Ninja
cmake --build build
sudo cmake --install build
```

Dependencies: Qt 6.6+, KF6 (CoreAddons, I18n, TextEditor, XmlGui, WidgetsAddons,
Parts), Extra CMake Modules, OpenSSL, and the `gpg` CLI at runtime.

## Architecture

- `kategpgpassword.{hpp,cpp}` — the whole plugin: a `KTextEditor::Plugin`
  plus a per-mainwindow `KXMLGUIClient` view.
- **Decrypt on open**: `documentUrlChanged` → `maybeDecryptDocument` reads the
  raw bytes from disk (not Kate's buffer, so binary GPG files work), prompts for a
  password, decrypts in memory, and swaps the buffer once Kate's load finishes
  (`KParts::ReadOnlyPart::completed`, with a timer fallback).
- **Encrypt on save**: `aboutToSave` captures plaintext; `documentSavedOrUploaded`
  encrypts and writes the ciphertext directly to disk, overwriting Kate's
  plaintext save (this also avoids ASCII-armor line-ending mangling). The editor
  buffer keeps showing plaintext.
- **GPG** is invoked via the `gpg` CLI (not GPGME, to avoid pinentry complexity).
  The passphrase goes over stdin (`--passphrase-fd 0`); see `SECURITY.md`.
- **Notepad3** legacy format is implemented directly with OpenSSL (`AES-256-CBC`);
  detection is by the `0x01020304` preamble. Import-only — see `SECURITY.md`.

## Debugging

Diagnostics are off by default. Run Kate with `KATE_GPG_PASSWORD_DEBUG=1` to write a
log to `$XDG_RUNTIME_DIR/kate-gpg-password.log` (never contains plaintext or
passphrases).

## Manual test (round-trip)

1. Create a note, **File → Set Encryption Password**, save as `test.gpg`.
2. Confirm on disk it's ASCII-armored: `gpg -d test.gpg` should prompt and print
   your text.
3. Close and reopen `test.gpg` in Kate, enter the password, edit, save, reopen.

## Code style / licensing

- New source files need SPDX headers:
  `// SPDX-FileCopyrightText: <year> <you>` and `// SPDX-License-Identifier: MIT`.
- Keep the project [REUSE](https://reuse.software/)-compliant: `uvx reuse lint`.
- Contributions are accepted under the MIT license.
