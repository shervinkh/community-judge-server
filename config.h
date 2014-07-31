/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef CONFIG_H
#define CONFIG_H

#include <QMap>
#include <QVariant>

typedef QMap<QString, QVariant> DataTable;

class Config
{
private:
    static const QString ver;
    static const QString verDate;

    DataTable config;

public:
    Config() {}

    void load(const DataTable &DT) {config = DT;}
    DataTable get() const {return config;}
    QVariant getConfig(const QString &str) {return config[str];}

    static QString version() {return ver;}
    static QString versionDate() {return verDate;}
};

#endif // CONFIG_H
