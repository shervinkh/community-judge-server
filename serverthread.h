/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef SERVERTHREAD_H
#define SERVERTHREAD_H

#include <QObject>
#include <QByteArray>
#include <QDataStream>
#include "database.h"

class QTcpSocket;
class QSslCertificate;
class QSslKey;
class Problem;
class TcpServer;
class Database;
class QFile;
enum class StatCode;

class ServerThread : public QObject
{
    Q_OBJECT
private:
    static const int FILE_BUFFER_SIZE;
    static const int SCOREBOARD_CONFIG_PAGE_LENGTH;
    static const int USER_RECORD_PAGE_LENGTH;

    QTcpSocket *serverSocket;

    bool isSsl;
    QSslCertificate *cert;
    QSslKey *key;

    Database *database;
    TcpServer *tcpServer;

    QByteArray receivedData;
    QDataStream client;
    QDataStream *clientRequest;

    int socketDescriptor;
    int length;

    bool registeredIP;
    bool registeredUser;

    void handleRegisterRequest();
    void handleSubmission();
    void handleResultRequest();
    void handleCompilerLogRequest();
    void handleCodeViewRequest();
    void handleChangePassword();
    void handleChangePublicState();
    void handleDeleteSubmission();
    void handleViewProfile();
    void handleSubmissionPurge();
    void handlePurgeFiles();
    void handleGiveDescription();
    void handleUserRecord();

    //Management
    bool validateProblem(const Problem &prob);
    void handleProblemManagement(StatCode stat);
    void handleUserManagement(StatCode stat);
    void handleScorePlan(StatCode stat);
    void handleConfig(StatCode stat);
    void handleNews(StatCode stat);
    void handleContestManagement(StatCode stat);
    void handleScoreboard(StatCode stat);


    //Result
    void sendSingleStatCode(StatCode stat);

    bool isAdmin;
    QString username;
    qint64 uid;
    bool isActive;

    //GiveDescFile
    QFile *descFile;
    qint64 descFileSize;
    qint64 descFileWritten;

signals:
    void newSubmit();
    void done();

public:
    explicit ServerThread(Database *datab, TcpServer *ts, int socket, bool ssl,
                          QSslCertificate *crt, QSslKey *ky, QObject *parent = Q_NULLPTR);

public slots:
    void run();
    void disconnectSocket();

private slots:
    void readData();
    void cleanup();
    void sendDescFileFragment();
};

#endif // SERVERTHREAD_H
