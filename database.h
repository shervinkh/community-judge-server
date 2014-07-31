/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#ifndef DATABASE_H
#define DATABASE_H

enum class StatCode : int
{
    RegisterationRequest, LoginRequest, SubmissionRequest, ResultRequest, CompilerLogRequest, ChangePasswordRequest,
    ViewCodeRequest,
    InternalDatabaseError,
    UserOK, NoSuchUser, UserNotApproved, InvalidPassword, AdminOK,
    OperationSuccessful, NotAuthorized, IncompatibleVersion,
    AlreadyExists,
    NoSuchProblem, SlowDown, InternalFileOperationError,
    Disabled, InQueue, Running, ServerError, ResourceLimit, RunError, WrongAnswer, Correct, CompileError, CompleteResult,
    ProblemManagementQuery, ProblemManagementDetails, ProblemManagementEdit, ProblemManagementRemove,
    ProblemManagementRejudge, ProblemNotEnoughData,
    ScorePlanQuery, ScorePlanDetails, ScorePlanEdit, ScorePlanRemove,
    UserQuery, UserChangeAdmin, UserChangeActivation, RenameUser, UserDelete, UserChangeDescription, NotTheOnlyAdmin,
    ChangePublicState, DeleteSubmission, ViewProfile, GetConfig, SetConfig,
    NotAvailable, SubmissionPurge, PurgeFiles, GiveDescription, GetNews, EditNews, RemoveNews,
    CannotViewSubmission, ContestUserQuery, ContestListQuery, ContestDetails, CurrentContests, RegisterContest, ContestEdit, ContestRemove,
    AlreadyRegistered, CannotProcessAtThisTime, ScoreboardConfig, ScoreboardEdit, ScoreboardMetaData, Scoreboard, UserRecord
};

#if QT_VERSION < 0x050000
#ifndef NULL
#define NULL 0
#endif
#define Q_NULLPTR NULL
#endif

#include <QtSql>
#include <QList>
#include "submissionresult.h"
#include "problem.h"
#include "score.h"
#include "user.h"
#include "contest.h"

class QMutex;
class Config;

#if QT_VERSION >= 0x050000
#include <QException>
#define EXCEPTION_CLASS QException
#else
#include <qtconcurrentexception.h>
#define EXCEPTION_CLASS QtConcurrent::Exception
#endif

class DatabaseException : public EXCEPTION_CLASS
{
public:
    void raise() const { throw *this; }
    DatabaseException *clone() const { return new DatabaseException(*this); }
};

class FileOperationException : public EXCEPTION_CLASS
{
public:
    void raise() const { throw *this; }
    FileOperationException *clone() const { return new FileOperationException(*this); }
};

class NotAuthorizedException : public EXCEPTION_CLASS
{
public:
    void raise() const { throw *this; }
    NotAuthorizedException *clone() const { return new NotAuthorizedException(*this); }
};

typedef QMap<QString, QVariant> DataTable;

class ConditionalQuery
{
private:
    const QString query;
    QString conds;
    QList<QVariant> vals;
    bool hasAny;
    QSqlDatabase &db;

    void addPrefix()
    {
        if (hasAny)
            conds += " AND ";
        else
        {
            conds += "WHERE ";
            hasAny = true;
        }
    }

public:
    ConditionalQuery(QSqlDatabase &_db, const QString &_query, bool _hasAny = false)
        : query(_query), hasAny(_hasAny), db(_db) {}

    void addCond(const QString &cond, const QVariant &val)
    {
        addPrefix();
        conds += QString("%1").arg(cond);
        if (!val.isNull())
        {
            conds += "?";
            vals.append(val);
        }
    }

    void addCustomCond(const QString &txt, const QVariant &val)
    {
        addPrefix();
        conds += txt;
        vals.append(val);
    }

    QSqlQuery resultQuery() const
    {
        QSqlQuery q(db);
        q.prepare(query.arg(conds));

        foreach (QVariant val, vals)
            q.addBindValue(val);

        return q;
    }
};

class Database
{
private:
    QSqlDatabase db;
    Config *conf;
    QMutex *mutex;
    QMutex *mutex2;

    void execute(QSqlQuery &query);

public:
    Database();
    ~Database();

    //Some Functions For Get Basic Data
    qint64 getpid(const QString &name);
    qint64 getuid(const QString &uname);
    Problem giveProblemForSubmission(qint64 sid);
    qint64 giveUidForSubmit(qint64 sid);

    //Some Basic Functions
    StatCode userStat(const QString &username, const QByteArray &password = "");
    int numPendingSubmits(qint64 uid);
    qint64 firstSubmissionInQueue();
    Config * config() {return conf;}

    //Important Functions
    qint64 makeNewSubmit(qint64 uid, qint64 pid);
    void updateSubmitStatus(qint64 sid, StatCode status, int last_test, qint64 max_time, qint64 max_memory, QByteArray fullRes = QByteArray());
    void registerUser(const QString &username, const QByteArray &password, const QString description);
    QList<SubmissionResult> giveSubmits(const DataTable &DT);
    void fixBrokenSubmissions();
    void markAsRunning(qint64 sid);

    //Management Functions
    void changePassword(const QString &uname, const QByteArray &pass);
    void publicize(qint64 sid, bool state);
    void deleteSubmission(qint64 id);
    bool hasCorrect(qint64 pid, qint64 uid);
    bool submissionAuth(qint64 sid, qint64 uid);

    //Problem Management
    QList<QString> problemQuery(int mode, const QString &constr, bool user, const QString &contst);
    StatCode addProblem(const Problem &prob);
    StatCode editProblem(const Problem &prob);
    Problem problemDetails(QString name);
    void removeProblem(qint64 pid);
    void rejudgeProblem(qint64 pid);
    bool canViewProblem(const QString &name, qint64 uid);
    bool canSubmitProblem(const QString &name, qint64 uid);

    //Score Profile Management
    qint64 getScoreID(QString name);
    QList<QString> scorePlanQuery();
    ScorePlan scorePlanDetails(QString name);
    StatCode addScorePlan(const ScorePlan &in);
    StatCode editScorePlan(const ScorePlan &in);
    void removeScorePlan(QString name, qint64 id, qint64 replace_id);

    //User Management
    bool isAdmin(qint64 id);
    QList<User> userQuery(const DataTable &DT);
    StatCode changeAdminState(const QString &name, bool state);
    void changeActivationState(const QString &name, bool state);
    void deleteUser(qint64 id);
    void changeDescription(const QString &name, const QString &desc);
    StatCode renameUser(const QString &old, const QString &cur);

    //Score System
    void removeProblemScore(qint64 pid);
    ScorePlan giveScorePlan(qint64 pid);
    void recomputeScore(qint64 uid);
    void recomputeContestScore(qint64 cid, qint64 uid);
    void processScore(qint64 sid);
    qint64 givePendingScore();

    //Config System
    void setConfigs(DataTable &DT);
    DataTable loadConfigs();

    //Submission Purge
    void submissionPurge(const DataTable &DT);
    void purgeFiles();

    //Scoreboard
    QList<DataTable> scoreboardConfig(qint64 start, int cnt);
    void scoreboardEdit(const DataTable &DT);
    QList<DataTable> scoreboardMetaData();
    bool isScoreboardAvailable(qint64 cid, int type);
    QList<DataTable> scoreboard(qint64 id, int type, qint64 page);

    //News
    QList<DataTable> getNews();
    qint64 addNews(const DataTable &in);
    void editNews(const DataTable &in);
    void removeNews(qint64 id);

    //Contest Management
    QList<Contest> contestUserQuery(int mode, const QString &constr);
    QList<QString> contestListQuery(int mode, const QString &constr, bool onlyreal);
    StatCode addContest(const Contest &con);
    StatCode editContest(const Contest &con);
    void removeContest(qint64 cid);
    qint64 getContestID(const QString &name);
    QList<QString> currentContests(qint64 uid);
    bool canViewContest(qint64 cid, qint64 uid);
    bool canSubmitContest(qint64 cid, qint64 uid);
    StatCode registerUserInContest(qint64 cid, qint64 uid);
    Contest contestDetails(qint64 cid);

    //User Record
    QList<DataTable> userRecord(qint64 uid, qint64 start, int count);

    //Install & Update
    void installTables();
};

#endif // DATABASE_H
