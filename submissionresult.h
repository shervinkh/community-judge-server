/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef SUBMISSIONRESULT_H
#define SUBMISSIONRESULT_H

#include <QString>
#include <QDataStream>
#include "database.h"

class SubmissionResult
{
private:
    qint64 sid;
    QString uname;
    QString pname;
    qint64 dateTime;
    StatCode status;
    int numTest;
    int totTest;
    qint64 maxTime;
    qint64 maxMem;
    QList<qint8> fullResult;
    bool isPub;
    qreal scoreDff;

public:
    SubmissionResult() {}
    SubmissionResult(qint64 subid, const QString &un, const QString &pn, qint64 dt, StatCode stat,
                     int nt, int tt, qint64 mt, qint64 mm, const QList<qint8> &ls, bool pub, qreal scoreD)
        : sid(subid), uname(un), pname(pn), dateTime(dt), status(stat), numTest(nt), totTest(tt), maxTime(mt),
          maxMem(mm), fullResult(ls), isPub(pub), scoreDff(scoreD) {}

    qint64 submitID() const {return sid;}
    QString username() const {return uname;}
    QString probName() const {return pname;}
    qint64 date() const {return dateTime;}
    StatCode judgeStatus() const {return status;}
    int numTests() const {return numTest;}
    int totalTests() const {return totTest;}
    qint64 maximumTime() const {return maxTime;}
    qint64 maximumMemory() const {return maxMem;}
    const QList<qint8> &completeResult() const {return fullResult;}
    bool isPublic() const {return isPub;}
    qreal scoreDiff() const {return scoreDff;}

    SubmissionResult invertedPublicState() const
    {
        SubmissionResult ret(*this);
        ret.isPub = !ret.isPub;
        return ret;
    }

    SubmissionResult deleteScore() const
    {
        SubmissionResult tmp(*this);
        tmp.scoreDff = -1;
        return tmp;
    }

    friend QDataStream &operator>>(QDataStream &DS, SubmissionResult &in)
    {
        int tmp;
        DS >> in.sid >> in.uname >> in.pname >> in.dateTime >> tmp >> in.numTest >> in.totTest
           >> in.maxTime >> in.maxMem >> in.isPub >> in.scoreDff;
        in.status = static_cast<StatCode>(tmp);
        if (in.status == StatCode::CompleteResult)
            DS >> in.fullResult;
        return DS;
    }

    friend QDataStream & operator<<(QDataStream &DS, const SubmissionResult &in)
    {
        DS << in.sid << in.uname << in.pname << in.dateTime << static_cast<int>(in.status) << in.numTest
           << in.totTest << in.maxTime << in.maxMem << in.isPub << in.scoreDff;
        if (in.status == StatCode::CompleteResult)
            DS << in.fullResult;
        return DS;
    }
};

#endif // SUBMISSIONRESULT_H
