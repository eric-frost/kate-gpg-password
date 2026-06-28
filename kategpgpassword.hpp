// SPDX-FileCopyrightText: 2026 Eric Frost
// SPDX-License-Identifier: MIT

#pragma once

#include <KTextEditor/MainWindow>
#include <KTextEditor/Plugin>
#include <KXMLGUIClient>

#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QSet>
#include <QVariant>
#include <QString>

#include <memory>

namespace KTextEditor
{
class Document;
class View;
}

class KateGpgPasswordPlugin : public KTextEditor::Plugin
{
    Q_OBJECT
public:
    explicit KateGpgPasswordPlugin(QObject *parent, const QList<QVariant> & = QList<QVariant>());
    QObject *createView(KTextEditor::MainWindow *mainWindow) override;
};

class KateGpgPasswordView : public QObject, public KXMLGUIClient
{
    Q_OBJECT
public:
    explicit KateGpgPasswordView(KateGpgPasswordPlugin *plugin, KTextEditor::MainWindow *mainWindow);
    ~KateGpgPasswordView() override;

private Q_SLOTS:
    void setPasswordForActiveDocument();
    void clearPasswordForActiveDocument();
    void connectDocument(KTextEditor::Document *doc);
    void maybeDecryptDocument(KTextEditor::Document *doc);
    void encryptBeforeSave(KTextEditor::Document *doc);
    void restoreAfterSave(KTextEditor::Document *doc, bool saveAs);

private:
    enum class EncryptionFormat {
        Gpg,
        Notepad3,
    };

    struct Notepad3State {
        QByteArray fileKey;
        QByteArray masterIv;
        QByteArray encryptedFileKey;
    };

    struct DocumentState {
        bool encrypted = false;
        bool plaintextApplied = false;  // decrypt applied to the buffer (or a new doc whose buffer is already plaintext)
        bool bufferSwapped = false;     // aboutToSave swapped the buffer to ciphertext; restore plaintext after the write
        bool saveFailed = false;        // last encrypt failed; keep the document modified after restoring the view
        EncryptionFormat format = EncryptionFormat::Gpg;
        QString password;
        QString plaintext;              // transient: stashed only across a single save swap
        QString pendingPlaintext;
        QString lastCiphertext;         // last ciphertext read/written, so a failed encrypt never leaves plaintext on disk
        Notepad3State notepad3;
    };

    KTextEditor::Document *activeDocument() const;
    bool askPassword(const QString &title, QString *password);
    bool askNewEncryptionPassword(QString *password);
    bool isProbablyEncrypted(KTextEditor::Document *doc, const QByteArray &raw) const;
    bool isNotepad3Encrypted(const QByteArray &raw) const;
    QByteArray readRawDocument(KTextEditor::Document *doc) const;
    bool runGpg(const QStringList &args, const QByteArray &input, const QString &password, QByteArray *output, QString *errorText) const;
    bool decryptBytes(const QByteArray &ciphertext, const QString &password, QString *plaintext, QString *errorText) const;
    bool encryptToBytes(const QString &plaintext, const QString &password, QByteArray *ciphertext, QString *errorText) const;
    bool decryptNotepad3Bytes(const QByteArray &ciphertext, const QString &password, QString *plaintext, Notepad3State *state, QString *errorText) const;
    QByteArray notepad3PassphraseBytes(const QString &password) const;
    QByteArray sha256(const QByteArray &bytes) const;
    bool aes256CbcCrypt(const QByteArray &input, const QByteArray &key, const QByteArray &iv, bool encrypt, bool padding, QByteArray *output, QString *errorText) const;
    quint32 readLe32(const QByteArray &bytes, int offset) const;
    bool gpgAvailable() const;
    void logLine(const QString &text) const;
    void showMessage(const QString &text, const QString &type = QStringLiteral("Information"));

    KTextEditor::MainWindow *m_mainWindow = nullptr;
    QHash<KTextEditor::Document *, DocumentState> m_states;
    QSet<KTextEditor::Document *> m_connectedDocs;
};
