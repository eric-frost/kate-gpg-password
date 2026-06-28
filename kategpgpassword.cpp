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
#include <QRandomGenerator>
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
    if (!doc) {
        return;
    }
    connect(doc, &KTextEditor::Document::aboutToSave, this, &KateGpgPasswordView::encryptBeforeSave, Qt::UniqueConnection);
    connect(doc, &KTextEditor::Document::documentSavedOrUploaded, this, &KateGpgPasswordView::restoreAfterSave, Qt::UniqueConnection);
    connect(doc, &KTextEditor::Document::aboutToClose, this, [this](KTextEditor::Document *closingDoc) {
        m_states.remove(closingDoc);
    }, Qt::UniqueConnection);
    connect(doc, &KTextEditor::Document::documentUrlChanged, this, [this](KTextEditor::Document *changedDoc) {
        QTimer::singleShot(0, this, [this, changedDoc] { maybeDecryptDocument(changedDoc); });
    }, Qt::UniqueConnection);
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
    connectDocument(doc);
    QString password;
    if (!askNewEncryptionPassword(&password)) {
        return;
    }
    DocumentState &state = m_states[doc];
    state.encrypted = true;
    state.password = password;
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
    // Just record that we need to encrypt after Kate finishes writing.
    state.plaintext = doc->text();
    state.restoring = true;
    logLine(QStringLiteral("encryptBeforeSave: captured plaintext chars=%1").arg(state.plaintext.size()));
}

void KateGpgPasswordView::restoreAfterSave(KTextEditor::Document *doc, bool)
{
    if (!doc || !m_states.contains(doc)) {
        return;
    }
    DocumentState &state = m_states[doc];
    if (!state.restoring) {
        return;
    }
    state.restoring = false;

    const QString filePath = doc->url().toLocalFile();
    if (filePath.isEmpty()) {
        logLine(QStringLiteral("restoreAfterSave: no local file path, skipping encrypt"));
        return;
    }

    QByteArray ciphertext;
    QString errorText;
    const bool encrypted = (state.format == EncryptionFormat::Notepad3)
        ? encryptNotepad3Bytes(state.plaintext, state.notepad3, &ciphertext, &errorText)
        : encryptToBytes(state.plaintext, state.password, &ciphertext, &errorText);
    if (!encrypted) {
        logLine(QStringLiteral("restoreAfterSave: encrypt failed: %1").arg(errorText));
        showMessage(i18n("Encrypt failed: %1", errorText), QStringLiteral("Error"));
        return;
    }

    // Write encrypted bytes directly to disk, overwriting Kate's plaintext save.
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        logLine(QStringLiteral("restoreAfterSave: could not open file for writing: %1").arg(file.errorString()));
        showMessage(i18n("Could not write encrypted file: %1", file.errorString()), QStringLiteral("Error"));
        return;
    }
    file.write(ciphertext);
    file.close();

    logLine(QStringLiteral("restoreAfterSave: wrote %1 encrypted bytes to %2").arg(ciphertext.size()).arg(filePath));
    showMessage(i18n("Saved encrypted (%1 bytes).", ciphertext.size()));

    // Keep the document showing plaintext and not modified.
    doc->setModified(false);
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

bool KateGpgPasswordView::encryptNotepad3Bytes(const QString &plaintext, const Notepad3State &state, QByteArray *ciphertext, QString *errorText) const
{
    if (state.fileKey.size() != KeyBytes) {
        *errorText = QStringLiteral("missing Notepad3 file key");
        return false;
    }

    const QByteArray fileIv = randomBytes(AesBlockSize);
    QByteArray payload;
    if (!aes256CbcCrypt(plaintext.toUtf8(), state.fileKey, fileIv, true, true, &payload, errorText)) {
        return false;
    }

    ciphertext->clear();
    appendLe32(ciphertext, Notepad3Preamble);
    const bool hasMasterHeader = state.masterIv.size() == AesBlockSize && state.encryptedFileKey.size() == KeyBytes;
    appendLe32(ciphertext, hasMasterHeader ? Notepad3MasterKeyFormat : Notepad3FileKeyFormat);
    ciphertext->append(fileIv);
    if (hasMasterHeader) {
        ciphertext->append(state.masterIv);
        ciphertext->append(state.encryptedFileKey);
    }
    ciphertext->append(payload);
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

QByteArray KateGpgPasswordView::randomBytes(int size) const
{
    // Use QRandomGenerator::system() (the OS CSPRNG, e.g. getrandom/dev-urandom)
    // rather than global(), which is only a securely-seeded PRNG — IVs must be
    // unpredictable for AES-CBC.
    QByteArray bytes(size, Qt::Uninitialized);
    QRandomGenerator *gen = QRandomGenerator::system();
    int i = 0;
    for (; i + 4 <= size; i += 4) {
        const quint32 v = gen->generate();
        memcpy(bytes.data() + i, &v, sizeof(v));
    }
    if (i < size) {
        const quint32 v = gen->generate();
        memcpy(bytes.data() + i, &v, size - i);
    }
    return bytes;
}

quint32 KateGpgPasswordView::readLe32(const QByteArray &bytes, int offset) const
{
    const auto b0 = static_cast<quint32>(static_cast<unsigned char>(bytes[offset]));
    const auto b1 = static_cast<quint32>(static_cast<unsigned char>(bytes[offset + 1]));
    const auto b2 = static_cast<quint32>(static_cast<unsigned char>(bytes[offset + 2]));
    const auto b3 = static_cast<quint32>(static_cast<unsigned char>(bytes[offset + 3]));
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

void KateGpgPasswordView::appendLe32(QByteArray *bytes, quint32 value) const
{
    bytes->append(static_cast<char>(value & 0xff));
    bytes->append(static_cast<char>((value >> 8) & 0xff));
    bytes->append(static_cast<char>((value >> 16) & 0xff));
    bytes->append(static_cast<char>((value >> 24) & 0xff));
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
