/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#include "judger.h"
#include "runner.h"
#include "database.h"
#include "config.h"
#include <QtCore>

Judger::Judger(Database *db, QObject *parent) :
    QObject(parent), database(db)
{
    database->fixBrokenSubmissions();
}

void Judger::judge()
{
    if (database->config()->getConfig("judge_enabled").toBool() &&
            runningThreads.size() < database->config()->getConfig("judge_threads").toInt())
    {
        qint64 current = database->firstSubmissionInQueue();
        if (current != -1)
        {
            Runner *runner = new Runner(database, current);

            if (idleThreads.isEmpty())
            {
                QThread *thr = new QThread;
                connect(thr, SIGNAL(finished()), this, SLOT(phase2()));
                idleThreads.append(thr);
            }

            QThread *thr = idleThreads.takeFirst();
            runner->moveToThread(thr);
            connect(runner, SIGNAL(finished()), runner, SLOT(deleteLater()));
            connect(runner, SIGNAL(destroyed()), thr, SLOT(quit()));
            connect(thr, SIGNAL(started()), runner, SLOT(run()));
            connect(this, SIGNAL(destroyed()), thr, SLOT(quit()));
            runningThreads.append(thr);
            database->markAsRunning(current);
            thr->start();
            scheduleJudge();
        }
    }
}

void Judger::score()
{
    qint64 id = database->givePendingScore();
    if (id != -1)
    {
        database->processScore(id);
        scheduleScore();
    }
}

void Judger::phase2()
{
    QThread *thr = qobject_cast<QThread *>(sender());
    int index = runningThreads.indexOf(thr);
    runningThreads.removeAt(index);

    if (runningThreads.size() + idleThreads.size() >= database->config()->getConfig("judge_threads").toInt())
        thr->deleteLater();
    else
        idleThreads.append(thr);

    schedule();
}

void Judger::scheduleJudge()
{
    QTimer::singleShot(0, this, SLOT(judge()));
}

void Judger::scheduleScore()
{
    QTimer::singleShot(0, this, SLOT(score()));
}

void Judger::schedule()
{
    scheduleJudge();
    scheduleScore();
}
