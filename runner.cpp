/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#include <QtCore>
#include "runner.h"
#include "config.h"

Runner::Runner(Database *db, qint64 sid, QObject *parent) :
    QObject(parent), database(db), subid(sid), counter(0), maxT(0), maxM(0), numCorrects(0)
{
    uid = database->giveUidForSubmit(sid);
    prblm = database->giveProblemForSubmission(sid);
    realTimer = database->config()->getConfig("real_timer").toBool();
    correct = false;
    connect(this, SIGNAL(finished()), this, SLOT(afterJudge()));
}

void Runner::run()
{
    QString srcFile = QString("submits/%1.cpp").arg(subid);
    QString execFile = QString("submits/%1.out").arg(subid);
    QString logFile = QString("submits/%1.log").arg(subid);

    QStringList args;
    args << srcFile << "-o" << execFile << "-O2" << "-Wall";

    QProcess *proc = new QProcess;
    proc->setStandardOutputFile(logFile);
    proc->setStandardErrorFile(logFile);
    connect(proc, SIGNAL(finished(int)), this, SLOT(compileDone(int)));
    connect(proc, SIGNAL(error(QProcess::ProcessError)), this, SLOT(errorOccured(QProcess::ProcessError)));
    proc->start("g++", args, QIODevice::NotOpen);
}

void Runner::compileDone(int exitCode)
{
    sender()->deleteLater();
    if (exitCode)
    {
        database->updateSubmitStatus(subid, StatCode::CompileError, 0, 0, 0);
        emit finished();
    }
    else
    {
        database->updateSubmitStatus(subid, StatCode::Running, 0, 0, 0);
        runNextTest();
    }
}

void Runner::testCompleted(StatCode result)
{
    if (prblm.isComplete())
    {
        fullRes.append(static_cast<qint8>(result));
        if (result == StatCode::Correct)
            numCorrects++;
        runNextTest();
    }
    else
    {
        if (result == StatCode::Correct)
            runNextTest();
        else
        {
            database->updateSubmitStatus(subid, result, counter - 1, maxT, maxM);
            emit finished();
        }
    }
}

void Runner::runNextTest()
{
    if (counter == prblm.numTests())
    {
        if (prblm.isComplete() && numCorrects != prblm.numTests())
        {
            QByteArray fullResData;
            QDataStream DS(&fullResData, QIODevice::Append);
            DS.setVersion(QDataStream::Qt_4_8);
            DS << fullRes;
            database->updateSubmitStatus(subid, StatCode::CompleteResult, numCorrects, maxT, maxM, fullResData.toBase64());
        }
        else
        {
            database->updateSubmitStatus(subid, StatCode::Correct, counter, maxT, maxM);
            correct = true;
        }

        emit finished();
        return;
    }

    counter++;
    QString execFile = QString("submits/%1.out").arg(subid);
    QString inputFile = QString("problems/%1/%2.in").arg(prblm.folder()).arg(counter);

    QStringList args;
    qint64 newMemLimit = (prblm.memoryLimit() + database->config()->getConfig("max_library_size").toInt()) * 1000;
    qint64 newTimeLimit = (prblm.timeLimit() + 999) / 1000;
    args << "run.sh" << QString::number(newTimeLimit) << QString::number(newMemLimit) << execFile << inputFile << QString::number(subid);

    QProcess *proc = new QProcess;
    connect(proc, SIGNAL(finished(int)), this, SLOT(runDone(int)));
    connect(proc, SIGNAL(error(QProcess::ProcessError)), this, SLOT(errorOccured(QProcess::ProcessError)));

    if (realTimer)
        timer.start();

    proc->start("bash", args);
}

void Runner::runDone(int exitCode)
{
    qint64 timeE = realTimer ? timer.elapsed() : 0;

    int actualExitCode;
    qint64 tim, mem;

    QTextStream TS(qobject_cast<QProcess *>(sender())->readAllStandardError());
    TS >> actualExitCode >> tim >> mem;
    sender()->deleteLater();

    maxM = qMax(maxM, mem);
    if (realTimer)
        maxT = qMax(maxT, timeE);
    else
        maxT = qMax(maxT, tim / 1000);

    if (exitCode == 0)
    {
        if (maxM > prblm.memoryLimit() || maxT > prblm.timeLimit())
            testCompleted(StatCode::ResourceLimit);
        else
        {
            if (actualExitCode == 0)
            {
                QStringList args;
                args << QString("problems/%1/%2.in").arg(prblm.folder()).arg(counter) <<
                        QString("problems/%1/%2.out").arg(prblm.folder()).arg(counter) << QString("tmp/output%1").arg(subid);

                QString testerExec = QString("problems/%1/tester.out").arg(prblm.folder());

                QProcess *proc = new QProcess;
                connect(proc, SIGNAL(finished(int)), this, SLOT(testDone(int)));
                connect(proc, SIGNAL(error(QProcess::ProcessError)), this, SLOT(errorOccured(QProcess::ProcessError)));
                proc->start(testerExec, args);
            }
            else if (actualExitCode == 1)
                testCompleted(StatCode::ResourceLimit);
            else if (actualExitCode == 2)
                testCompleted(StatCode::RunError);
            else
                testCompleted(StatCode::ServerError);
        }
    }
    else
        testCompleted(StatCode::ServerError);
}

void Runner::testDone(int exitCode)
{
    sender()->deleteLater();
    if (exitCode)
        testCompleted(StatCode::WrongAnswer);
    else
        testCompleted(StatCode::Correct);
}

void Runner::errorOccured(QProcess::ProcessError)
{
    testCompleted(StatCode::ServerError);
}

void Runner::afterJudge()
{
    QFile::remove(QString("tmp/output%1").arg(subid));
}
