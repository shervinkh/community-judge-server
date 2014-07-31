/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef JUDGER_H
#define JUDGER_H

#include <QObject>
#include <QList>
#include "problem.h"
#include "database.h"

class QProcess;
class QMutex;
class QThread;
class Database;

class Judger : public QObject
{
    Q_OBJECT
private:

    Database *database;

    QList<QThread *> idleThreads;
    QList<QThread *> runningThreads;

public:
    explicit Judger(Database *db, QObject *parent = Q_NULLPTR);

private slots:
    void phase2();

public slots:
    void judge();
    void score();
    void scheduleJudge();
    void scheduleScore();
    void schedule();
};

#endif // JUDGER_H
