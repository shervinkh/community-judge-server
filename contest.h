/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef CONTEST_H
#define CONTEST_H

#include <QString>
#include <QDateTime>

class Contest
{
private:
    qint64 id;
    QString nam;
    QString dsc;
    bool enbld;
    QDateTime regStart;
    QDateTime regEnd;
    QDateTime conStart;
    QDateTime conEnd;
    bool aftView;
    bool aftSub;

public:
    Contest() {}
    Contest(qint64 _id, const QString &nm, const QString &dc, bool enab, const QDateTime &rs,
            const QDateTime &re, const QDateTime &cs, const QDateTime &ce, bool av, bool as)
        : id(_id), nam(nm), dsc(dc), enbld(enab), regStart(rs), regEnd(re), conStart(cs),
          conEnd(ce), aftView(av), aftSub(as) {}

    qint64 ID() const {return id;}
    QString name() const {return nam;}
    QString description() const {return dsc;}
    bool enabled() const {return enbld;}
    QDateTime registerStart() const {return regStart;}
    QDateTime registerEnd() const {return regEnd;}
    QDateTime contestStart() const {return conStart;}
    QDateTime contestEnd() const {return conEnd;}
    bool afterContestView() const {return aftView;}
    bool afterContestSubmit() const {return aftSub;}

    friend QDataStream & operator>>(QDataStream &DS, Contest &in)
    {
        DS >> in.id >> in.nam >> in.dsc >> in.enbld >> in.regStart >> in.regEnd
           >> in.conStart >> in.conEnd >> in.aftView >> in.aftSub;
        return DS;
    }

    friend QDataStream & operator<<(QDataStream &DS, const Contest &in)
    {
        DS << in.id << in.nam << in.dsc << in.enbld << in.regStart << in.regEnd
           << in.conStart << in.conEnd << in.aftView << in.aftSub;
        return DS;
    }
};

#endif // CONTEST_H
