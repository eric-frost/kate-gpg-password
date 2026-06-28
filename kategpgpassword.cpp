// SPDX-FileCopyrightText: 2026 Eric Frost
// SPDX-License-Identifier: MIT

#include "kategpgpassword.hpp"

#include <KActionCollection>
#include <KLocalizedString>
#include <KPasswordDialog>
#include <KPluginFactory>
#include <KTextEditor/Document>
#include <KTextEditor/View>
#include <KParts/ReadOnlyPart>
#include <KMessageWidget>
#include <KXMLGUIFactory>

#include <QAction>
#include <QCheckBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QProcess>
#include <QStandardPaths>
#include <QVBoxLayout>

#include <QTimer>
#include <QUrl>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstring>

namespace
{
constexpr quint32 Notepad3Preamble = 0x01020304;
constexpr quint32 Notepad3FileKeyFormat = 1;
constexpr quint32 Notepad3MasterKeyFormat = 2;
constexpr int Notepad3PreambleSize = 8;
constexpr int AesBlockSize = 16;
constexpr int KeyBytes = 32;
}

K_PLUGIN_FACTORY_WITH_JSON(KateGpgPasswordFactory, "kategpgpassword.json", registerPlugin<KateGpgPasswordPlugin>();)

KateGpgPasswordPlugin::KateGpgPasswordPlugin(QObject *parent, const QList<QVariant> &)
    : KTextEditor::Plugin(parent)
{
}

QObject *KateGpgPasswordPlugin::createView(KTextEditor::MainWindow *mainWindow)
{
    return new KateGpgPasswordView(this, mainWindow);
}

KateGpgPasswordView::KateGpgPasswordView(KateGpgPasswordPlugin *, KTextEditor::MainWindow *mainWindow)
    : QObject(mainWindow)
    , m_mainWindow(mainWindow)
{
    KXMLGUIClient::setComponentName(QStringLiteral("kategpgpassword"), i18n("GPG Password Files"));
    setXMLFile(QStringLiteral("ui.rc"));

    QAction *setPassword = actionCollection()->addAction(QStringLiteral("simple_gpg_set_password"));
    setPassword->setText(i18n("Set Encryption Password"));
    connect(setPassword, &QAction::triggered, this, &KateGpgPasswordView::setPasswordForActiveDocument);

    QAction *clearPassword = actionCollection()->addAction(QStringLiteral("simple_gpg_clear_password"));
    clearPassword->setText(i18n("Clear Encryption Password"));
    connect(clearPassword, &QAction::triggered, this, &KateGpgPasswordView::clearPasswordForActiveDocument);

    connect(mainWindow, &KTextEditor::MainWindow::viewCreated, this, [this](KTextEditor::View *view) {
        if (view && view->document()) {
            connectDocument(view->document());
        }
    });

    for (KTextEditor::View *view : mainWindow->views()) {
        if (view && view->document()) {
            connectDocument(view->document());
        }
    }

    if (m_mainWindow && m_mainWindow->guiFactory()) {
        m_mainWindow->guiFactory()->addClient(this);
    }
}

KateGpgPasswordView::~KateGpgPasswordView()
{
    if (m_mainWindow && m_mainWindow->guiFactory()) {
        m_mainWindow->guiFactory()->removeClient(this);
    }
}

KTextEditor::Document *KateGpgPasswordView::activeDocument() const
{
    KTextEditor::View *view = m_mainWindow ? m_mainWindow->activeView() : nullptr;
    return view ? view->document() : nullptr;
}

void KateGpgPasswordView::connectDocument(KTextEditor::Document *doc)
{
    // Connect each document exactly once. We dedup explicitly rather than via
    // Qt::UniqueConnection because Qt 6.10 makes UniqueConnection with a lambda a
    // fatal error (it is only valid with pointer-to-member slots).
    if (!doc || m_connectedDocs.contains(doc)) {
        return;
    }
    m_connectedDocs.insert(doc);

    connect(doc, &KTextEditor::Document::aboutToSave, this, &KateGpgPasswordView::encryptBeforeSave);
    connect(doc, &KTextEditor::Document::documentSavedOrUploaded, this, &KateGpgPasswordView::restoreAfterSave);
    connect(doc, &KTextEditor::Document::aboutToClose, this, [this](KTextEditor::Document *closingDoc) {
        m_states.remove(closingDoc);
        m_connectedDocs.remove(closingDoc);
    });
    connect(doc, &KTextEditor::Document::documentUrlChanged, this, [this](KTextEditor::Document *changedDoc) {
        QTimer::singleShot(0, this, [this, changedDoc] { maybeDecryptDocument(changedDoc); });
    });
    connect(doc, &QObject::destroyed, this, [this](QObject *obj) {
        auto *gone = static_cast<KTextEditor::Document *>(obj);
        m_states.remove(gone);
        m_connectedDocs.remove(gone);
    });
    QTimer::singleShot(0, this, [this, doc] { maybeDecryptDocument(doc); });
}

void KateGpgPasswordView::maybeDecryptDocument(KTextEditor::Document *doc)
{
    logLine(QStringLiteral("maybeDecryptDocument url=%1 stateKnown=%2").arg(doc ? doc->url().toString() : QStringLiteral("<null>")).arg(doc && m_states.contains(doc)));
    if (!doc || m_states.contains(doc)) {
        return;
    }
    const QByteArray raw = readRawDocument(doc);
    logLine(QStringLiteral("raw bytes=%1 probableEncrypted=%2").arg(raw.size()).arg(isProbablyEncrypted(doc, raw)));
    if (!isProbablyEncrypted(doc, raw)) {
        return;
    }

    QString password;
    if (!askPassword(i18n("Password for encrypted file"), &password)) {
        return;
    }

    QString plaintext;
    QString errorText;
    EncryptionFormat format = isNotepad3Encrypted(raw) ? EncryptionFormat::Notepad3 : EncryptionFormat::Gpg;
    Notepad3State notepad3State;
    const bool decrypted = (format == EncryptionFormat::Notepad3)
        ? decryptNotepad3Bytes(raw, password, &plaintext, &notepad3State, &errorText)
        : decryptBytes(raw, password, &plaintext, &errorText);
    if (!decrypted) {
        const QString message = (format == EncryptionFormat::Notepad3)
            ? i18n("Notepad3 decrypt failed: %1", errorText)
            : i18n("GPG decrypt failed: %1", errorText);
        logLine(message);
        showMessage(message, QStringLiteral("Error"));
        QMessageBox::critical(nullptr, i18n("Encrypted file decrypt failed"), message);
        return;
    }

    DocumentState state;
    state.encrypted = true;
    state.format = format;
    state.password = password;
    state.pendingPlaintext = plaintext;
    state.notepad3 = notepad3State;
    // Remember the on-disk GPG armor so a later failed re-encrypt never has to fall
    // back to writing plaintext. Notepad3 files migrate to GPG on first save, so they
    // start with no GPG ciphertext.
    if (format == EncryptionFormat::Gpg) {
        state.lastCiphertext = QString::fromUtf8(raw);
    }
    m_states.insert(doc, state);

    // Lambda that applies the pending plaintext once Kate has finished loading.
    auto applyPlaintext = [this, doc]() {
        if (!m_states.contains(doc)) {
            return;
        }
        DocumentState &st = m_states[doc];
        if (st.pendingPlaintext.isEmpty()) {
            return;
        }
        const QString pt = st.pendingPlaintext;
        st.pendingPlaintext.clear();
        logLine(QStringLiteral("applying setText plaintextChars=%1 readWrite=%2")
                    .arg(pt.size())
                    .arg(doc->isReadWrite()));

        // Binary GPG files may cause Kate to set the document read-only.
        // Force read-write mode so setText actually works.
        if (!doc->isReadWrite()) {
            doc->setReadWrite(true);
            logLine(QStringLiteral("forced setReadWrite(true), now readWrite=%1").arg(doc->isReadWrite()));
        }

        // Clear and replace using the editing transaction API for reliability.
        doc->setText(pt);

        // Verify it took effect; if not, try clear + insertText.
        if (doc->text() != pt) {
            logLine(QStringLiteral("setText did not take effect, trying clear+insertText"));
            doc->clear();
            auto *iface = qobject_cast<KTextEditor::Document *>(doc);
            if (iface) {
                iface->insertText(KTextEditor::Cursor(0, 0), pt);
            }
        }

        doc->setModified(false);
        doc->setEncoding(QStringLiteral("UTF-8"));
        // The buffer now holds plaintext; saves may safely re-encrypt it.
        st.plaintextApplied = true;
        // Never log plaintext content; only its length, to avoid leaking secrets to the debug log.
        logLine(QStringLiteral("setText done, docChars=%1").arg(doc->text().size()));

        // Dismiss any encoding warning bars Kate may have shown for the binary data.
        // Delayed because Kate's post-load pipeline can re-show warnings after our setText.
        KTextEditor::View *view = m_mainWindow ? m_mainWindow->activeView() : nullptr;
        if (view) {
            QWidget *container = view->parentWidget();
            if (container) {
                QTimer::singleShot(1000, container, [container]() {
                    const auto widgets = container->findChildren<KMessageWidget *>();
                    for (KMessageWidget *w : widgets) {
                        w->animatedHide();
                    }
                });
            }
        }
    };

    // Connect to KParts::ReadOnlyPart::completed() — fires when the document
    // has truly finished loading from disk. This prevents Kate's load pipeline
    // from overwriting our setText.
    auto conn = std::make_shared<QMetaObject::Connection>();
    *conn = connect(doc, QOverload<>::of(&KParts::ReadOnlyPart::completed), this,
                    [applyPlaintext, conn]() {
                        QObject::disconnect(*conn);
                        applyPlaintext();
                    });

    // Fallback: if completed() already fired before we connected, apply after a delay.
    QTimer::singleShot(500, this, [applyPlaintext]() {
        applyPlaintext();
    });

    logLine(QStringLiteral("decrypted ok, format=%1 queued buffer update. plaintextChars=%2")
                .arg(format == EncryptionFormat::Notepad3 ? QStringLiteral("Notepad3") : QStringLiteral("GPG"))
                .arg(plaintext.size()));
    showMessage(i18n("Encrypted file decrypted in memory."));
}

void KateGpgPasswordView::setPasswordForActiveDocument()
{
    KTextEditor::Document *doc = activeDocument();
    if (!doc) {
        showMessage(i18n("No active document."), QStringLiteral("Error"));
        return;
    }
    if (!gpgAvailable()) {
        showMessage(i18n("gpg was not found in PATH; cannot enable encryption."), QStringLiteral("Error"));
        return;
    }
    connectDocument(doc);
    QString password;
    if (!askNewEncryptionPassword(&password)) {
        return;
    }
    DocumentState &state = m_states[doc];
    state.encrypted = true;
    state.password = password;
    // The buffer already holds the user's plaintext, so saves may encrypt it.
    state.plaintextApplied = true;
    state.format = EncryptionFormat::Gpg;
    doc->setModified(true);
    showMessage(i18n("Encryption password set. Normal Save will write encrypted text."));
}

void KateGpgPasswordView::clearPasswordForActiveDocument()
{
    KTextEditor::Document *doc = activeDocument();
    if (!doc) {
        return;
    }
    m_states.remove(doc);
    doc->setModified(true);
    showMessage(i18n("Encryption password cleared for this document."));
}

void KateGpgPasswordView::encryptBeforeSave(KTextEditor::Document *doc)
{
    if (!doc || !m_states.contains(doc)) {
        return;
    }
    DocumentState &state = m_states[doc];
    if (!state.encrypted || state.password.isEmpty()) {
        return;
    }
    // 1. Decrypt has not been applied yet: the buffer still holds the on-disk
    // ciphertext, so let Kate write it back unchanged. Never re-encrypt ciphertext
    // (this also closes the open-then-save-during-settle "nested armor" window).
    if (!state.plaintextApplied) {
        return;
    }

    // 2. Notepad3 is import-only — its binary container cannot round-trip through a
    // text buffer. Migrate the document to GPG (salted, integrity-protected) on save.
    if (state.format == EncryptionFormat::Notepad3) {
        showMessage(i18n("Legacy Notepad3 file will be saved as GPG-encrypted (AES-256)."));
        state.format = EncryptionFormat::Gpg;
    }

    // 3. Encrypt the current plaintext and swap it into the buffer BEFORE Kate
    // writes, so Kate's own atomic save persists ciphertext. Plaintext is never
    // serialized to the real file on any save path (Ctrl+S, close prompt, Save All).
    const QString plaintext = doc->text();
    QByteArray ciphertext;
    QString errorText;
    if (encryptToBytes(plaintext, state.password, &ciphertext, &errorText)) {
        state.lastCiphertext = QString::fromUtf8(ciphertext);
        state.plaintext = plaintext;
        state.saveFailed = false;
        state.bufferSwapped = true;
        doc->setText(state.lastCiphertext);
        logLine(QStringLiteral("encryptBeforeSave: swapped buffer to ciphertext chars=%1").arg(state.lastCiphertext.size()));
        return;
    }

    // 4. Encryption failed. Never let Kate write plaintext: if we have a previous
    // ciphertext, write that instead (the edit is not persisted and the document is
    // kept modified). Only a brand-new, never-saved document with a broken gpg can
    // reach the fall-through, and gpg presence is checked before encryption is enabled.
    logLine(QStringLiteral("encryptBeforeSave: encrypt failed: %1").arg(errorText));
    showMessage(i18n("Encrypt failed, changes NOT saved: %1", errorText), QStringLiteral("Error"));
    if (!state.lastCiphertext.isEmpty()) {
        state.plaintext = plaintext;
        state.saveFailed = true;
        state.bufferSwapped = true;
        doc->setText(state.lastCiphertext);
    }
}

void KateGpgPasswordView::restoreAfterSave(KTextEditor::Document *doc, bool)
{
    if (!doc || !m_states.contains(doc)) {
        return;
    }
    DocumentState &state = m_states[doc];
    if (!state.bufferSwapped) {
        return;
    }
    state.bufferSwapped = false;

    // Kate has written the ciphertext to disk; restore the editable plaintext view.
    // On a failed encrypt keep the document modified so the user knows it is unsaved.
    const bool failed = state.saveFailed;
    const QString plaintext = state.plaintext;
    state.plaintext.clear();
    state.saveFailed = false;
    doc->setText(plaintext);
    doc->setModified(failed);
    doc->setEncoding(QStringLiteral("UTF-8"));
    if (!failed) {
        showMessage(i18n("Saved encrypted."));
    }
    logLine(QStringLiteral("restoreAfterSave: restored plaintext view, failed=%1").arg(failed));
}

bool KateGpgPasswordView::askPassword(const QString &title, QString *password)
{
    KPasswordDialog dialog(nullptr, KPasswordDialog::ShowKeepPassword);
    dialog.setWindowTitle(title);
    dialog.setPrompt(i18n("Password:"));
    if (dialog.exec() != QDialog::Accepted) {
        return false;
    }
    *password = dialog.password();
    return !password->isEmpty();
}

bool KateGpgPasswordView::askNewEncryptionPassword(QString *password)
{
    QDialog dialog(nullptr);
    dialog.setWindowTitle(i18n("Set encryption password"));

    auto *layout = new QVBoxLayout(&dialog);
    auto *form = new QFormLayout();
    auto *passwordEdit = new QLineEdit(&dialog);
    auto *confirmEdit = new QLineEdit(&dialog);
    auto *hidePassword = new QCheckBox(i18n("Hide password"), &dialog);
    auto *message = new QLabel(&dialog);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);

    passwordEdit->setEchoMode(QLineEdit::Normal);
    confirmEdit->setEchoMode(QLineEdit::Password);
    confirmEdit->setVisible(false);
    message->setVisible(false);
    message->setWordWrap(true);
    message->setStyleSheet(QStringLiteral("color: #da4453;"));

    form->addRow(i18n("Password:"), passwordEdit);
    form->addRow(i18n("Confirm password:"), confirmEdit);
    layout->addLayout(form);
    layout->addWidget(hidePassword);
    layout->addWidget(message);
    layout->addWidget(buttons);

    const auto updateHiddenMode = [passwordEdit, confirmEdit, hidePassword]() {
        const bool hidden = hidePassword->isChecked();
        passwordEdit->setEchoMode(hidden ? QLineEdit::Password : QLineEdit::Normal);
        confirmEdit->setVisible(hidden);
        if (!hidden) {
            confirmEdit->clear();
        }
    };
    connect(hidePassword, &QCheckBox::toggled, &dialog, updateHiddenMode);

    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&]() {
        message->hide();
        const QString value = passwordEdit->text();
        if (value.isEmpty()) {
            message->setText(i18n("Password cannot be empty."));
            message->show();
            return;
        }
        if (hidePassword->isChecked() && value != confirmEdit->text()) {
            message->setText(i18n("Passwords do not match."));
            message->show();
            confirmEdit->selectAll();
            confirmEdit->setFocus();
            return;
        }
        *password = value;
        dialog.accept();
    });

    passwordEdit->setFocus();
    return dialog.exec() == QDialog::Accepted && !password->isEmpty();
}

QByteArray KateGpgPasswordView::readRawDocument(KTextEditor::Document *doc) const
{
    if (!doc || !doc->url().isLocalFile()) {
        return {};
    }
    QFile file(doc->url().toLocalFile());
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    return file.readAll();
}

bool KateGpgPasswordView::isProbablyEncrypted(KTextEditor::Document *doc, const QByteArray &raw) const
{
    if (!doc) {
        return false;
    }
    const QString name = doc->url().fileName().toLower();
    if (name.endsWith(QStringLiteral(".gpg")) || name.endsWith(QStringLiteral(".pgp"))) {
        return true;
    }
    return raw.startsWith("-----BEGIN PGP MESSAGE-----") || isNotepad3Encrypted(raw);
}

bool KateGpgPasswordView::isNotepad3Encrypted(const QByteArray &raw) const
{
    if (raw.size() < Notepad3PreambleSize + AesBlockSize) {
        return false;
    }
    const quint32 magic = readLe32(raw, 0);
    const quint32 format = readLe32(raw, 4);
    return magic == Notepad3Preamble && (format == Notepad3FileKeyFormat || format == Notepad3MasterKeyFormat);
}

bool KateGpgPasswordView::runGpg(const QStringList &args, const QByteArray &input, const QString &password, QByteArray *output, QString *errorText) const
{
    // Build stdin: passphrase line + actual data.
    // GPG reads the passphrase from FD 0 (first line) then the data from the rest.
    const QByteArray passBytes = password.toUtf8() + '\n';
    const QByteArray stdinData = passBytes + input;

    logLine(QStringLiteral("starting gpg args=%1 inputBytes=%2 passLen=%3")
                .arg(args.join(QLatin1Char(' ')))
                .arg(input.size())
                .arg(password.size()));

    QProcess process;
    process.setProgram(QStringLiteral("gpg"));
    process.setArguments(args);
    process.start();
    if (!process.waitForStarted(5000)) {
        *errorText = process.errorString();
        logLine(QStringLiteral("gpg failed to start: %1").arg(*errorText));
        return false;
    }

    process.write(stdinData);
    process.closeWriteChannel();
    if (!process.waitForFinished(30000)) {
        process.kill();
        process.waitForFinished(1000);
        *errorText = QStringLiteral("gpg timed out");
        logLine(*errorText);
        return false;
    }
    *output = process.readAllStandardOutput();
    const QByteArray stderrBytes = process.readAllStandardError();
    logLine(QStringLiteral("gpg exitStatus=%1 exitCode=%2 stdoutBytes=%3 stderr=%4")
                .arg(process.exitStatus())
                .arg(process.exitCode())
                .arg(output->size())
                .arg(QString::fromUtf8(stderrBytes).trimmed()));
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        *errorText = QString::fromUtf8(stderrBytes).trimmed();
        return false;
    }
    return true;
}

bool KateGpgPasswordView::decryptBytes(const QByteArray &ciphertext, const QString &password, QString *plaintext, QString *errorText) const
{
    QByteArray output;
    const QStringList args = {QStringLiteral("--batch"), QStringLiteral("--yes"), QStringLiteral("--pinentry-mode"), QStringLiteral("loopback"), QStringLiteral("--passphrase-fd"), QStringLiteral("0"), QStringLiteral("--no-symkey-cache"), QStringLiteral("--decrypt")};
    if (!runGpg(args, ciphertext, password, &output, errorText)) {
        return false;
    }
    *plaintext = QString::fromUtf8(output);
    return true;
}

bool KateGpgPasswordView::encryptToBytes(const QString &plaintext, const QString &password, QByteArray *ciphertext, QString *errorText) const
{
    const QStringList args = {QStringLiteral("--batch"), QStringLiteral("--yes"), QStringLiteral("--pinentry-mode"), QStringLiteral("loopback"), QStringLiteral("--passphrase-fd"), QStringLiteral("0"), QStringLiteral("--no-symkey-cache"), QStringLiteral("--armor"), QStringLiteral("--symmetric"), QStringLiteral("--cipher-algo"), QStringLiteral("AES256")};
    if (!runGpg(args, plaintext.toUtf8(), password, ciphertext, errorText)) {
        return false;
    }
    return true;
}

bool KateGpgPasswordView::decryptNotepad3Bytes(const QByteArray &ciphertext, const QString &password, QString *plaintext, Notepad3State *state, QString *errorText) const
{
    if (!isNotepad3Encrypted(ciphertext)) {
        *errorText = QStringLiteral("not a Notepad3 encrypted file");
        return false;
    }

    const quint32 format = readLe32(ciphertext, 4);
    int offset = Notepad3PreambleSize;
    const QByteArray fileIv = ciphertext.mid(offset, AesBlockSize);
    offset += AesBlockSize;

    Notepad3State localState;
    QByteArray fileKey = sha256(notepad3PassphraseBytes(password));

    if (format == Notepad3MasterKeyFormat) {
        if (ciphertext.size() < offset + AesBlockSize + KeyBytes + AesBlockSize) {
            *errorText = QStringLiteral("short Notepad3 master-key header");
            return false;
        }
        localState.masterIv = ciphertext.mid(offset, AesBlockSize);
        offset += AesBlockSize;
        localState.encryptedFileKey = ciphertext.mid(offset, KeyBytes);
        offset += KeyBytes;

        QByteArray recoveredKey;
        QString masterError;
        if (aes256CbcCrypt(localState.encryptedFileKey, fileKey, localState.masterIv, false, false, &recoveredKey, &masterError)
            && recoveredKey.size() == KeyBytes) {
            QByteArray candidatePlaintext;
            if (aes256CbcCrypt(ciphertext.mid(offset), recoveredKey, fileIv, false, true, &candidatePlaintext, errorText)) {
                localState.fileKey = recoveredKey;
                *plaintext = QString::fromUtf8(candidatePlaintext);
                *state = localState;
                return true;
            }
        }
        // Fall back to the normal file passphrase; this preserves master header on save.
    }

    QByteArray plaintextBytes;
    if (!aes256CbcCrypt(ciphertext.mid(offset), fileKey, fileIv, false, true, &plaintextBytes, errorText)) {
        *errorText = errorText->isEmpty() ? QStringLiteral("wrong password or corrupt Notepad3 file") : *errorText;
        return false;
    }

    localState.fileKey = fileKey;
    *plaintext = QString::fromUtf8(plaintextBytes);
    *state = localState;
    return true;
}

QByteArray KateGpgPasswordView::notepad3PassphraseBytes(const QString &password) const
{
    QByteArray bytes;
    bytes.reserve(password.size() * 2);
    for (const QChar ch : password) {
        const ushort value = ch.unicode();
        const char low = static_cast<char>(value & 0xff);
        const char high = static_cast<char>((value >> 8) & 0xff);
        if (low != 0) {
            bytes.append(low);
        }
        if (high != 0) {
            bytes.append(high);
        }
    }
    return bytes;
}

QByteArray KateGpgPasswordView::sha256(const QByteArray &bytes) const
{
    QByteArray digest(SHA256_DIGEST_LENGTH, Qt::Uninitialized);
    SHA256(reinterpret_cast<const unsigned char *>(bytes.constData()), bytes.size(), reinterpret_cast<unsigned char *>(digest.data()));
    return digest;
}

bool KateGpgPasswordView::aes256CbcCrypt(const QByteArray &input, const QByteArray &key, const QByteArray &iv, bool encrypt, bool padding, QByteArray *output, QString *errorText) const
{
    if (key.size() != KeyBytes || iv.size() != AesBlockSize) {
        *errorText = QStringLiteral("invalid AES key or IV size");
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        *errorText = QStringLiteral("could not allocate AES context");
        return false;
    }

    bool ok = false;
    QByteArray result(input.size() + AesBlockSize, Qt::Uninitialized);
    int outLen1 = 0;
    int outLen2 = 0;
    const int initOk = EVP_CipherInit_ex(ctx,
                                         EVP_aes_256_cbc(),
                                         nullptr,
                                         reinterpret_cast<const unsigned char *>(key.constData()),
                                         reinterpret_cast<const unsigned char *>(iv.constData()),
                                         encrypt ? 1 : 0);
    if (initOk == 1 && EVP_CIPHER_CTX_set_padding(ctx, padding ? 1 : 0) == 1
        && EVP_CipherUpdate(ctx,
                            reinterpret_cast<unsigned char *>(result.data()),
                            &outLen1,
                            reinterpret_cast<const unsigned char *>(input.constData()),
                            input.size()) == 1
        && EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(result.data()) + outLen1, &outLen2) == 1) {
        result.resize(outLen1 + outLen2);
        *output = result;
        ok = true;
    } else {
        *errorText = QStringLiteral("AES-CBC %1 failed").arg(encrypt ? QStringLiteral("encrypt") : QStringLiteral("decrypt"));
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

quint32 KateGpgPasswordView::readLe32(const QByteArray &bytes, int offset) const
{
    const auto b0 = static_cast<quint32>(static_cast<unsigned char>(bytes[offset]));
    const auto b1 = static_cast<quint32>(static_cast<unsigned char>(bytes[offset + 1]));
    const auto b2 = static_cast<quint32>(static_cast<unsigned char>(bytes[offset + 2]));
    const auto b3 = static_cast<quint32>(static_cast<unsigned char>(bytes[offset + 3]));
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

bool KateGpgPasswordView::gpgAvailable() const
{
    return !QStandardPaths::findExecutable(QStringLiteral("gpg")).isEmpty();
}

void KateGpgPasswordView::logLine(const QString &text) const
{
    // Diagnostics are OFF by default. Enable with KATE_GPG_PASSWORD_DEBUG=1.
    // 1. Bail out unless explicitly enabled.
    static const bool enabled = !qEnvironmentVariableIsEmpty("KATE_GPG_PASSWORD_DEBUG");
    if (!enabled) {
        return;
    }
    // 2. Prefer the per-user runtime dir ($XDG_RUNTIME_DIR, 0700) over shared /tmp,
    // which is world-readable and vulnerable to predictable-name symlink attacks.
    static const QString path = []() {
        QString dir = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
        if (dir.isEmpty()) {
            dir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
        }
        return dir + QStringLiteral("/kate-gpg-password.log");
    }();
    QFile log(path);
    if (!log.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        return;
    }
    const QString line = QStringLiteral("[%1] %2\n").arg(QDateTime::currentDateTime().toString(Qt::ISODateWithMs), text);
    log.write(line.toUtf8());
}

void KateGpgPasswordView::showMessage(const QString &text, const QString &type)
{
    if (!m_mainWindow) {
        return;
    }
    QVariantMap message;
    message[QStringLiteral("text")] = text;
    message[QStringLiteral("type")] = type;
    m_mainWindow->showMessage(message);
}

#include "kategpgpassword.moc"
