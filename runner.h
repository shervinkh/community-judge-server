/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef RUNNER_H
#define RUNNER_H

#include <QObject>
#include <QElapsedTimer>
#include "problem.h"
#include "database.h"

class QFile;
class Database;

class Runner : public QObject
{
    Q_OBJECT
public:
    enum TestState {AC, WA, TLML, RE};

private:
    QElapsedTimer timer;

    Database *database;
    Problem prblm;
    qint64 subid;
    qint64 uid;

    bool correct;
    int counter;
    qint64 maxT, maxM;
    bool realTimer;

    int numCorrects;
    QList<qint8> fullRes;

    void runNextTest();
    void testCompleted(StatCode result);

public:
    explicit Runner(Database *db, qint64 sid, QObject *parent = Q_NULLPTR);

public slots:
    void run();

signals:
    void finished();

private slots:
    void compileDone(int exitCode);
    void runDone(int exitCode);
    void testDone(int exitCode);
    void errorOccured(QProcess::ProcessError);
    void afterJudge();
};

#endif // RUNNER_H
