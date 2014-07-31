/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef SCORES_H
#define SCORES_H

#include <QDataStream>
#include <QString>

class ScorePlan
{
private:
    qint64 id;
    QString nam;
    qreal p1;
    qreal p2;
    qreal convTo;
    qreal mul;

    qreal give(qreal in)
    {
        in = qMin(in, 10000.0);
        qreal num = convTo * in + 2 * (1 - convTo);
        return num / in;
    }

public:
    ScorePlan() {}
    ScorePlan(qint64 _id, QString _nam, qreal _p1, qreal _p2, qreal _convTo, qreal _mul) :
        id(_id), nam(_nam), p1(_p1), p2(_p2), convTo(_convTo), mul(_mul) {}

    void init(qreal _penalty1, qreal _penalty2, qreal cTo, qreal mult)
    {
        p1 = _penalty1;
        p2 = _penalty2;
        convTo = cTo;
        mul = mult;
    }

    qint64 ID() const {return id;}
    QString name() const {return nam;}
    qreal penalty1() const {return p1;}
    qreal penalty2() const {return p2;}
    qreal convergeTo() const {return convTo;}
    qreal multiplier() const {return mul;}

    qreal query(qreal val1, qreal val2)
    {
        return give(pow(val1, p1) + pow(val2, p2)) * mul;
    }

    friend QDataStream & operator<<(QDataStream &DS, const ScorePlan &in)
    {
        DS << in.id << in.nam << in.p1 << in.p2 << in.convTo << in.mul;
        return DS;
    }

    friend QDataStream & operator>>(QDataStream &DS, ScorePlan &in)
    {
        DS >> in.id >> in.nam >> in.p1 >> in.p2 >> in.convTo >> in.mul;
        return DS;
    }
};

#endif // SCORES_H
