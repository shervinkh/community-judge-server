/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef SIGNALHANDLER_H
#define SIGNALHANDLER_H

#include <QObject>
#include "database.h"

class QSocketNotifier;

class SignalHandler : public QObject
{
    Q_OBJECT
private:
    static int sigintFd[2];
    static int sigtermFd[2];

    QSocketNotifier *snInt;
    QSocketNotifier *snTerm;

public:
    explicit SignalHandler(QObject *parent = Q_NULLPTR);

    // Signal handlers
    static void intSignalHandler(int);
    static void termSignalHandler(int);
    
public slots:
    // Qt Signal Handlers
    void handleSigInt();
    void handleSigTerm();
};

#endif // SIGNALHANDLER_H
