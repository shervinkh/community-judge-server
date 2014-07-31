#ifndef TCPSERVER_H
#define TCPSERVER_H

#include <QTcpServer>
#include <QSet>
#include "database.h"

class QSslCertificate;
class QSslKey;
class Database;

#if QT_VERSION >= 0x050000
#define INCOMING_CONNECTION_PARAMETER_TYPE qintptr
#else
#define INCOMING_CONNECTION_PARAMETER_TYPE int
#endif

class TcpServer : public QTcpServer
{
    Q_OBJECT
private:
    Database *database;

    QSet<QHostAddress> peers;
    QSet<QString> users;

    bool isSsl;
    QSslCertificate *cert;
    QSslKey *key;

signals:
    void newSubmit();

public:
    explicit TcpServer(Database *datab, quint16 port, bool ssl, QObject *parent = Q_NULLPTR);

    bool registerIP(QHostAddress addr);
    void unregisterIP(QHostAddress addr);
    bool registerUser(const QString &user);
    void unregisterUser(const QString &user);

protected:
    void incomingConnection(INCOMING_CONNECTION_PARAMETER_TYPE handle);
};

#endif // TCPSERVER_H
