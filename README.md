# Kate Simple GPG Plugin

Transparent **password-based (symmetric) encryption** for [Kate](https://kate-editor.org/) and other KTextEditor apps. Open an encrypted file, type a password, edit it like any other document, and it's re-encrypted on save. No keyrings, no key management — just a password.

Files are written as ASCII-armored OpenPGP (AES-256), so they're **compatible with [Encrypted Notepad II](https://play.google.com/store/apps/details?id=org.scoutant.enpad) on Android** — edit the same encrypted note on your phone and your desktop.

> **Note:** Kate ships its own GPG plugin since 25.12, which is *key-centric* (encrypt to OpenPGP recipients/keys). This plugin is deliberately different: **symmetric password only**, plus legacy Notepad3 import. Pick whichever matches your workflow.

![Opening an encrypted .gpg in Kate: enter the password, the plaintext appears, then edit it like any document](docs/demo.gif)

## Features

- Transparent decrypt on open for `.gpg` / `.pgp` files, or any file starting with `-----BEGIN PGP MESSAGE-----`.
- Re-encrypts on normal Save / Save As — the editor keeps showing plaintext; only the file on disk is encrypted. Encryption happens **before** Kate writes, so plaintext is never written to the target file on any save path.
- **File → Set Encryption Password** to turn any plaintext document into an encrypted one.
- Symmetric OpenPGP, ASCII-armored, AES-256 — interoperable with GnuPG (`gpg -d file.gpg`) and Encrypted Notepad II.
- **Legacy import** of Notepad3 / NotepadCrypt encrypted files (read-only; saving migrates the file to the stronger GPG format). See the security notes — the Notepad3 format is weak.

## Requirements

- Kate / KTextEditor (KF6) and Qt 6.6+
- The `gpg` (GnuPG) command-line tool on `PATH`
- Build: CMake, Extra CMake Modules (ECM), KF6 dev packages, OpenSSL dev

## Build & install

```bash
cmake -S . -B build -G Ninja
cmake --build build
sudo cmake --install build
```

Restart Kate, then enable it in **Settings → Configure Kate → Plugins → GPG Password Files**.

On Ubuntu/Debian the build dependencies are roughly:

```bash
sudo apt install cmake ninja-build extra-cmake-modules \
  libkf6texteditor-dev libkf6xmlgui-dev libkf6i18n-dev \
  libkf6coreaddons-dev libkf6widgetsaddons-dev libssl-dev
```

## Security

This is encryption software — please read [SECURITY.md](SECURITY.md) before trusting it with real secrets. Highlights:

- New files use OpenPGP symmetric encryption (AES-256, salted+iterated S2K) via `gpg`.
- The passphrase is passed to `gpg` over stdin (never argv or a temp file) and symmetric passphrase caching is disabled.
- **Notepad3 import is legacy-compatibility only**: its key derivation is unsalted single-pass SHA-256 and the format has no integrity check. Files are read-only — saving rewrites them as GPG. Don't use the Notepad3 format for new notes.
- Kate may write a crash-recovery swap file containing decrypted text. See SECURITY.md for the mitigation.

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Eric Frost. The project is [REUSE](https://reuse.software/)-compliant.
