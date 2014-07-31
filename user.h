/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef USER_H
#define USER_H

#include <QObject>
#include <QDateTime>

class User
{
private:
    QString nam;
    QString desc;
    QDateTime joind;
    bool enabld;
    qint64 subs;
    qint64 cors;
    bool isAdm;
    qreal scre;

public:
    User() {}
    User(const QString &_nam, const QString &_desc, const QDateTime &_joind, bool _enabld, qint64 _subs, qint64 _cors, bool _isAdm, qreal _scre)
        : nam(_nam), desc(_desc), joind(_joind), enabld(_enabld), subs(_subs), cors(_cors), isAdm(_isAdm), scre(_scre) {}

    QString name() const {return nam;}
    QString description() const {return desc;}
    bool enabled() const {return enabld;}
    qint64 numSubmits() const {return subs;}
    qint64 numCorrects() const {return cors;}
    bool isAdmin() const {return isAdm;}
    qreal score() const {return scre;}
    QDateTime joinDate() const {return joind;}

    User deleteScore() const
    {
        User tmp(*this);
        tmp.scre = -1;
        return tmp;
    }

    friend QDataStream & operator<<(QDataStream &DS, const User &in)
    {
        DS << in.nam << in.desc << in.joind << in.enabld << in.subs << in.cors << in.isAdm << in.scre;
        return DS;
    }

    friend QDataStream & operator>>(QDataStream &DS, User &in)
    {
        DS >> in.nam >> in.desc >> in.joind >> in.enabld >> in.subs >> in.cors >> in.isAdm >> in.scre;
        return DS;
    }
};

#endif // USER_H
