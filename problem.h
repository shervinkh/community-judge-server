/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef PROBLEM_H
#define PROBLEM_H

#include <QString>
#include <QDataStream>

class QDataStream;

class Problem
{
private:
    qint64 id;
    QString nam;
    QString dsc;
    int nTest;
    qint64 TLimit;
    qint64 MLimit;
    bool isCompl;
    bool enabled;
    QString scoreP;
    QString contst;
    QString descFile;
    QString foldr;
    int pubsubs;
    int othrssubs;

public:
    Problem() {}
    Problem(qint64 _id, const QString &nm, const QString &dc, int nt, qint64 tl, qint64 ml, bool comple,
            bool enbl, const QString &sc, const QString &cont, const QString &df, const QString &fldr, int ps, int os)
        : id(_id), nam(nm), dsc(dc), nTest(nt), TLimit(tl), MLimit(ml), isCompl(comple), enabled(enbl)
        , scoreP(sc), contst(cont), descFile(df), foldr(fldr), pubsubs(ps), othrssubs(os) {}

    qint64 ID() const {return id;}
    QString name() const {return nam;}
    QString description() const {return dsc;}
    int numTests() const {return nTest;}
    qint64 timeLimit() const {return TLimit;}
    qint64 memoryLimit() const {return MLimit;}
    bool isComplete() const {return isCompl;}
    bool isEnabled() const {return enabled;}
    QString scorePlan() const {return scoreP;}
    QString contest() const {return contst;}
    QString descriptionFile() const {return descFile;}
    QString folder() const {return foldr;}
    int publicSubmissions() const {return pubsubs;}
    int othersSubmissions() const {return othrssubs;}

    friend QDataStream & operator>>(QDataStream &DS, Problem &in)
    {
        DS >> in.id >> in.nam >> in.dsc >> in.nTest >> in.TLimit >> in.MLimit >> in.isCompl
           >> in.enabled >> in.scoreP >> in.contst >> in.descFile >> in.foldr >> in.pubsubs >> in.othrssubs;
        return DS;
    }

    friend QDataStream & operator<<(QDataStream &DS, const Problem &in)
    {
        DS << in.id << in.nam << in.dsc << in.nTest << in.TLimit << in.MLimit << in.isCompl
           << in.enabled << in.scoreP << in.contst << in.descFile << in.foldr << in.pubsubs << in.othrssubs;
        return DS;
    }
};

#endif // PROBLEM_H
