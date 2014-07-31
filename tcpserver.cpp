/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#include "tcpserver.h"
#include "serverthread.h"
#include <QThread>
#include <QFile>
#include <QtNetwork>
#include "config.h"

TcpServer::TcpServer(Database *datab, quint16 port, bool ssl, QObject *parent) :
    QTcpServer(parent), database(datab), isSsl(ssl)
{
    if (isSsl)
    {
        QFile certFile("server.crt"), keyFile("server.key");
        if (!certFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly))
            qFatal("For starting in ssl mode server.crt and server.key files should be present"
                   " and accessible in the executable directory");
        cert = new QSslCertificate(&certFile);
        key = new QSslKey(&keyFile, QSsl::Rsa);
        if (cert->isNull() || key->isNull())
            qFatal("Invalid SSL key or certificate");
    }

    if (!listen(QHostAddress::Any, port))
        qFatal(QString("Could not open port %1.").arg(port).toLocal8Bit());

    qDebug() << QString("Server Started. (Version: %1 - %2)").arg(Config::version()).arg(Config::versionDate());
}


void TcpServer::incomingConnection(INCOMING_CONNECTION_PARAMETER_TYPE handle)
{
    ServerThread *thread = new ServerThread(database, this, handle, isSsl, cert, key);
    QThread *th = new QThread;
    thread->moveToThread(th);

    connect(thread, SIGNAL(newSubmit()), this, SIGNAL(newSubmit()));
    connect(thread, SIGNAL(done()), thread, SLOT(deleteLater()));
    connect(thread, SIGNAL(destroyed()), th, SLOT(quit()));
    connect(th, SIGNAL(finished()), th, SLOT(deleteLater()));
    connect(th, SIGNAL(started()), thread, SLOT(run()));
    connect(this, SIGNAL(destroyed()), th, SLOT(quit()));

    th->start();
}

bool TcpServer::registerIP(QHostAddress addr)
{
    if (peers.contains(addr))
        return false;
    else
    {
        peers.insert(addr);
        return true;
    }
}

void TcpServer::unregisterIP(QHostAddress addr)
{
    peers.remove(addr);
}

bool TcpServer::registerUser(const QString &user)
{
    if (users.contains(user))
        return false;
    else
    {
        users.insert(user);
        return true;
    }
}

void TcpServer::unregisterUser(const QString &user)
{
    users.remove(user);
}
