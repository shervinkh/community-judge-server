/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#include <QCoreApplication>
#include <QtCore>
#include <QThread>
#include "judger.h"
#include "tcpserver.h"
#include "signalhandler.h"
#include "database.h"
#include "submissionresult.h"
#include "config.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    if (QCoreApplication::arguments().length() < 3)
        qFatal("Please specify listening port and (ssl/tcp) mode.");

    QString serverMode = QCoreApplication::arguments()[2].toLower();
    if (serverMode != "tcp" && serverMode != "ssl")
        qFatal("Server mode (second argument) should be either tcp or ssl");

    bool ok;
    quint16 port = QCoreApplication::arguments()[1].toInt(&ok);

    if (!ok || port < 1)
        qFatal("Invalid port.");

    SignalHandler SH;
    Database database;
    
    QThread judgeThread;
    Judger judger(&database);
    judger.moveToThread(&judgeThread);
    QObject::connect(&judgeThread, SIGNAL(started()), &judger, SLOT(schedule()));
    judgeThread.start();

    TcpServer server(&database, port, (serverMode == "ssl"));
    QObject::connect(&server, SIGNAL(newSubmit()), &judger, SLOT(scheduleJudge()));
    
    int res = a.exec();
    judgeThread.quit();
    judgeThread.wait();
    
    return res;
}
