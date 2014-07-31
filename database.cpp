/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#include "database.h"
#include "config.h"
#include <QMutex>
#include <QThread>
#include <QDateTime>
#include <limits>

Database::Database()
{
    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("cj.db");

    if (!db.open())
        qFatal("Error: Could not open database");

    mutex = new QMutex;
    mutex2 = new QMutex;

    QSqlQuery query(db);
    query.prepare("SELECT version FROM cj_info");

    try
    {
        execute(query);
        if (!query.next())
            DatabaseException().raise();

    }
    catch (const DatabaseException &)
    {
        installTables();
    }

    if (query.isValid())
    {
        QString dbVersion = query.value(0).toString();
        if (dbVersion != Config::version())
            qFatal("Cannot convert your database to current version");
    }

    conf = new Config;
    conf->load(loadConfigs());
}

Database::~Database()
{
    delete mutex;
    delete conf;
}

void Database::execute(QSqlQuery &query)
{
    QMutexLocker mutexLocker(mutex);

    if (!query.exec())
    {
        qDebug() << "Database error: " << query.executedQuery() << ' ' << query.lastError().text();
        DatabaseException().raise();
    }
}

qint64 Database::getpid(const QString &name)
{
    QSqlQuery query(db);
    query.prepare("SELECT id FROM cj_problems WHERE name=:name");
    query.bindValue(":name", name);
    execute(query);

    if (query.next())
        return query.value(0).toLongLong();
    else
        return -1;
}

qint64 Database::getuid(const QString &uname)
{
    QSqlQuery query(db);
    query.prepare("SELECT id FROM cj_users WHERE username=:username");
    query.bindValue(":username", uname);
    execute(query);

    if (query.next())
        return query.value(0).toLongLong();
    else
        return -1;
}

StatCode Database::userStat(const QString &username, const QByteArray &password)
{
    QSqlQuery query(db);
    query.prepare("SELECT password, approved, is_admin FROM cj_users WHERE username=:username");
    query.bindValue(":username", username);
    execute(query);

    if (query.next())
    {
        if (query.value(1).toBool())
        {
            if (query.value(0) == password)
            {
                if (query.value(2).toBool())
                    return StatCode::AdminOK;
                else
                    return StatCode::UserOK;
            }
            else
                return StatCode::InvalidPassword;
        }
        else
            return StatCode::UserNotApproved;
    }

    return StatCode::NoSuchUser;
}

void Database::publicize(qint64 sid, bool state)
{
    QSqlQuery query(db);
    query.prepare("UPDATE cj_submits SET is_public=:state WHERE id=:sid");
    query.bindValue(":state", static_cast<int>(state));
    query.bindValue(":sid", sid);
    execute(query);
}

int Database::numPendingSubmits(qint64 uid)
{
    QSqlQuery query(db);
    query.prepare("SELECT COUNT(*) FROM cj_submits WHERE id=:uid AND (status=:pending OR status=:disabled)");
    query.bindValue(":uid", uid);
    query.bindValue(":pending", static_cast<int>(StatCode::InQueue));
    query.bindValue(":disabled", static_cast<int>(StatCode::Disabled));
    execute(query);

    query.next();
    return query.value(0).toInt();
}

qint64 Database::makeNewSubmit(qint64 uid, qint64 pid)
{
    qint64 currentTime = (QDateTime::currentMSecsSinceEpoch() / 1000) * 1000;

    QSqlQuery query(db);
    query.prepare("INSERT INTO cj_submits (uid, pid, date_and_time, status, last_test, max_time, max_memory, is_public, score_diff) "
                  "VALUES (:uid, :pid, :datetime, :disabled, 0, 0, 0, 0, -2)");
    query.bindValue(":uid", uid);
    query.bindValue(":pid", pid);
    query.bindValue(":datetime", currentTime);
    query.bindValue(":pending", static_cast<int>(StatCode::Disabled));
    execute(query);

    return query.lastInsertId().toLongLong();
}

void Database::updateSubmitStatus(qint64 sid, StatCode status, int last_test, qint64 max_time, qint64 max_memory, QByteArray fullRes)
{
    QSqlQuery query(db);
    query.prepare("UPDATE cj_submits SET status=:status, last_test=:last_test, max_time=:max_time, max_memory=:max_memory"
                  ", full_result=:full_result WHERE id=:sid");
    query.bindValue(":status", static_cast<int>(status));
    query.bindValue(":last_test", last_test);
    query.bindValue(":max_time", max_time);
    query.bindValue(":max_memory", max_memory);
    query.bindValue(":full_result", fullRes);
    query.bindValue(":sid", sid);
    execute(query);
}

void Database::registerUser(const QString &username, const QByteArray &password, const QString description)
{
    QSqlQuery query(db);
    query.prepare("INSERT INTO cj_users (username, password, description, join_date, approved, num_submits, num_corrects, is_admin) "
                  "VALUES (:username, :password, :description, :join_date, :state, 0, 0, 0)");
    query.bindValue(":username", username);
    query.bindValue(":password", password);
    query.bindValue(":description", description);
    query.bindValue(":join_date", QDateTime::currentMSecsSinceEpoch());
    query.bindValue(":state", config()->getConfig("registered_enabled").toInt());
    execute(query);

    qint64 uid = query.lastInsertId().toLongLong();

    query.prepare("INSERT INTO cj_contests_data (cid, uid, score, num_submits, num_corrects) "
                  "VALUES (-1, :uid, 0, 0, 0)");
    query.bindValue(":uid", uid);
    execute(query);
}

QList<SubmissionResult> Database::giveSubmits(const DataTable &DT)
{
    QString qu("SELECT S.id, U.username, P.name, S.date_and_time, S.status, S.last_test, S.max_time, S.max_memory, "
               "S.full_result, S.is_public, P.num_tests, S.score_diff FROM cj_submits AS S INNER JOIN cj_problems AS P "
               "ON S.pid=P.id INNER JOIN cj_users AS U ON S.uid=U.id %1 ORDER BY S.id DESC");

    if (DT.contains("count"))
        qu += QString(" LIMIT %1").arg(DT["count"].toInt());

    ConditionalQuery CQ(db, qu);
    CQ.addCond("S.status!=", static_cast<int>(StatCode::Disabled));
    CQ.addCond("P.enabled=", 1);

    if (DT.contains("from"))
        CQ.addCond("U.username LIKE ", DT["from"]);
    if (DT.contains("problem"))
        CQ.addCond("P.name LIKE ", DT["problem"]);
    if (DT.contains("public"))
        CQ.addCond("S.is_public=", DT["public"]);
    if (DT.contains("correct"))
        CQ.addCond("S.status=", static_cast<int>(StatCode::Correct));
    if (DT.contains("id"))
        CQ.addCond("S.id=", DT["id"]);

    QSqlQuery query = CQ.resultQuery();
    execute(query);

    QList<SubmissionResult> result;
    while (query.next())
    {
        qint64 subid = query.value(0).toLongLong();
        QString uname = query.value(1).toString();
        QString pname = query.value(2).toString();
        qint64 dateTime = query.value(3).toLongLong();
        StatCode status = static_cast<StatCode>(query.value(4).toInt());
        int last_test = query.value(5).toInt();
        qint64 max_time = query.value(6).toLongLong();
        qint64 max_mem = query.value(7).toLongLong();
        QList<qint8> ls;

        if (status == StatCode::CompleteResult)
        {
            QDataStream DS(QByteArray::fromBase64(query.value(8).toByteArray()));
            DS.setVersion(QDataStream::Qt_4_8);
            DS >> ls;
        }

        bool isOff = query.value(9).toBool();
        int tot_tests = query.value(10).toInt();
        qreal scd = query.value(11).toDouble();

        result.append(SubmissionResult(subid, uname, pname, dateTime, status, last_test, tot_tests, max_time, max_mem, ls, isOff, scd));
    }

    return result;
}

qint64 Database::firstSubmissionInQueue()
{
    QSqlQuery query(db);
    query.prepare("SELECT S.id FROM cj_submits AS S INNER JOIN cj_problems AS P ON S.pid=P.id "
                  "WHERE S.status=:pending AND P.enabled=1 ORDER BY S.id ASC LIMIT 1");
    query.bindValue(":pending", static_cast<int>(StatCode::InQueue));
    execute(query);

    if (query.next())
        return query.value(0).toLongLong();
    else
        return -1;
}

Problem Database::giveProblemForSubmission(qint64 sid)
{
    QSqlQuery query(db);
    query.prepare("SELECT P.name "
                  "FROM cj_problems AS P INNER JOIN cj_submits AS S ON P.id=S.pid "
                  "WHERE S.id=:sid");
    query.bindValue(":sid", sid);
    execute(query);

    if (query.next())
        return problemDetails(query.value(0).toString());
    else
        return Problem();
}

qint64 Database::giveUidForSubmit(qint64 sid)
{
    QSqlQuery query(db);
    query.prepare("SELECT uid FROM cj_submits WHERE id=:sid");
    query.bindValue(":sid", sid);
    execute(query);

    if (query.next())
        return query.value(0).toLongLong();
    else
        DatabaseException().raise();
}

//Management Division
void Database::changePassword(const QString &uname, const QByteArray &pass)
{
    QSqlQuery query(db);
    query.prepare("UPDATE cj_users SET password=:password WHERE username=:username");
    query.bindValue(":password", pass);
    query.bindValue(":username", uname);
    execute(query);
}

//Problem Management
QList<QString> Database::problemQuery(int mode, const QString &constr, bool user, const QString &contst)
{
    QList<QString> ans;

    QString initial("SELECT P.name FROM cj_problems AS P INNER JOIN cj_contests AS C ON P.cid=C.id %1");

    if (mode == 0)
        initial += QString(" ORDER BY P.id DESC LIMIT %1").arg(constr.toInt());
    else if (mode != 1)
        return ans;

    ConditionalQuery CQ(db, initial);
    if (mode == 1)
        CQ.addCond("P.name LIKE ", constr);
    if (user)
        CQ.addCond("P.enabled=", 1);
    if (!contst.isEmpty())
        CQ.addCond("C.name=", contst);

    QSqlQuery query = CQ.resultQuery();

    execute(query);
    while (query.next())
        ans.append(query.value(0).toString());

    return ans;
}

Problem Database::problemDetails(QString name)
{
    QSqlQuery query(db);
    query.prepare("SELECT P.id, P.name, P.desc, P.num_tests, P.time_limit, P.memory_limit, P.complete_judge, "
                  "P.enabled, S.name, P.desc_file, P.folder, P.public_subs, P.others_subs, C.name "
                  "FROM cj_problems AS P INNER JOIN cj_score_plans AS S ON P.score_plan=S.id "
                  "INNER JOIN cj_contests AS C ON P.cid=C.id WHERE P.name=:name");
    query.bindValue(":name", name);
    execute(query);

    if (query.next())
    {
        qint64 id = query.value(0).toLongLong();
        QString name = query.value(1).toString();
        QString desc = query.value(2).toString();
        int numT = query.value(3).toInt();
        qint64 tl = query.value(4).toLongLong();
        qint64 ml = query.value(5).toLongLong();
        bool isComp = query.value(6).toBool();
        bool isEnbl = query.value(7).toBool();
        QString score_plan = query.value(8).toString();
        QString desc_file = query.value(9).toString();
        QString folder = query.value(10).toString();
        int pubs = query.value(11).toInt();
        int oths = query.value(12).toInt();
        QString cont = query.value(13).toString();
        return Problem(id, name, desc, numT, tl, ml, isComp, isEnbl, score_plan, cont, desc_file, folder, pubs, oths);
    }
    else
        return Problem();
}

StatCode Database::addProblem(const Problem &prob)
{
    qint64 sc_id = getScoreID(prob.scorePlan());
    qint64 cid = getContestID(prob.contest());
    if (sc_id == -1 || cid == -2)
        NotAuthorizedException().raise();

    QSqlQuery query(db);
    query.prepare("INSERT OR IGNORE INTO cj_problems (name, desc, num_tests, time_limit, memory_limit, complete_judge, "
                  "enabled, score_plan, num_corrects, desc_file, folder, public_subs, others_subs, cid) "
                  "VALUES (:name, :desc, :num_tests, :time_limit, :memory_limit, :complete_judge, :enabled, :score_plan, "
                  "0, :desc_file, :folder, :public_subs, :others_subs, :cid)");
    query.bindValue(":name", prob.name());
    query.bindValue(":desc", prob.description());
    query.bindValue(":num_tests", prob.numTests());
    query.bindValue(":time_limit", prob.timeLimit());
    query.bindValue(":memory_limit", prob.memoryLimit());
    query.bindValue(":complete_judge", static_cast<int>(prob.isComplete()));
    query.bindValue(":enabled", static_cast<int>(prob.isEnabled()));
    query.bindValue(":score_plan", sc_id);
    query.bindValue(":desc_file", prob.descriptionFile());
    query.bindValue(":folder", prob.folder());
    query.bindValue(":public_subs", prob.publicSubmissions());
    query.bindValue(":others_subs", prob.othersSubmissions());
    query.bindValue(":cid", cid);

    execute(query);

    if (query.numRowsAffected())
        return StatCode::OperationSuccessful;
    else
        return StatCode::AlreadyExists;
}

StatCode Database::editProblem(const Problem &prob)
{
    qint64 sc_id = getScoreID(prob.scorePlan());
    qint64 cid = getContestID(prob.contest());
    if (sc_id == -1 || cid == -2)
        NotAuthorizedException().raise();

    QSqlQuery query(db);
    query.prepare("UPDATE OR IGNORE cj_problems SET name=:name, desc=:desc, num_tests=:num_tests, time_limit=:time_limit, "
                  "memory_limit=:memory_limit, complete_judge=:complete_judge, enabled=:enabled, score_plan=:score_plan, "
                  "desc_file=:desc_file, folder=:folder, public_subs=:public_subs, others_subs=:others_subs, cid=:cid WHERE id=:id");
    query.bindValue(":name", prob.name());
    query.bindValue(":desc", prob.description());
    query.bindValue(":num_tests", prob.numTests());
    query.bindValue(":time_limit", prob.timeLimit());
    query.bindValue(":memory_limit", prob.memoryLimit());
    query.bindValue(":complete_judge", static_cast<int>(prob.isComplete()));
    query.bindValue(":enabled", static_cast<int>(prob.isEnabled()));
    query.bindValue(":score_plan", sc_id);
    query.bindValue(":desc_file", prob.descriptionFile());
    query.bindValue(":folder", prob.folder());
    query.bindValue(":id", prob.ID());
    query.bindValue(":public_subs", prob.publicSubmissions());
    query.bindValue(":others_subs", prob.othersSubmissions());
    query.bindValue(":cid", cid);
    execute(query);

    if (query.numRowsAffected())
        return StatCode::OperationSuccessful;
    else
        return StatCode::AlreadyExists;
}

void Database::removeProblem(qint64 pid)
{
    QMutexLocker mutexLocker(mutex2);

    QSqlQuery query(db);
    query.prepare("DELETE FROM cj_submits WHERE pid=:pid");
    query.bindValue(":pid", pid);
    execute(query);

    query.prepare("DELETE FROM cj_problems WHERE id=:pid");
    query.bindValue(":pid", pid);
    execute(query);

    removeProblemScore(pid);
}

void Database::rejudgeProblem(qint64 pid)
{
    QMutexLocker mutexLocker(mutex2);

    removeProblemScore(pid);

    QSqlQuery query(db);
    query.prepare("UPDATE cj_submits SET status=:pending, score_diff=-2, last_test=0 WHERE pid=:pid AND status!=:disabled");
    query.bindValue(":pending", static_cast<int>(StatCode::InQueue));
    query.bindValue(":pid", pid);
    query.bindValue(":disabled", static_cast<int>(StatCode::Disabled));
    execute(query);

    query.prepare("UPDATE cj_problems SET num_corrects=0 WHERE id=:pid");
    query.bindValue(":pid", pid);
    execute(query);
}

QList<QString> Database::scorePlanQuery()
{
    QSqlQuery query(db);
    query.prepare("SELECT name FROM cj_score_plans");
    QList<QString> ans;

    execute(query);
    while (query.next())
        ans.append(query.value(0).toString());

    return ans;
}

ScorePlan Database::scorePlanDetails(QString name)
{
    QSqlQuery query(db);
    query.prepare("SELECT id, name, penalty1, penalty2, converge_to, multiplier FROM cj_score_plans "
                  "WHERE name=:name");
    query.bindValue(":name", name);
    execute(query);

    if (query.next())
    {
        qint64 ID = query.value(0).toLongLong();
        QString name = query.value(1).toString();
        qreal p1 = query.value(2).toDouble();
        qreal p2 = query.value(3).toDouble();
        qreal cTo = query.value(4).toDouble();
        qreal mul = query.value(5).toDouble();

        return ScorePlan(ID, name, p1, p2, cTo, mul);
    }
    else
        return ScorePlan();
}

StatCode Database::addScorePlan(const ScorePlan &in)
{
    QSqlQuery query(db);
    query.prepare("INSERT OR IGNORE INTO cj_score_plans (name, penalty1, penalty2, converge_to, multiplier) "
                  "VALUES (:name, :penalty1, :penalty2, :converge_to, :multiplier)");
    query.bindValue(":name", in.name());
    query.bindValue(":penalty1", in.penalty1());
    query.bindValue(":penalty2", in.penalty2());
    query.bindValue(":converge_to", in.convergeTo());
    query.bindValue(":multiplier", in.multiplier());

    execute(query);

    if (query.numRowsAffected())
        return StatCode::OperationSuccessful;
    else
        return StatCode::AlreadyExists;
}

StatCode Database::editScorePlan(const ScorePlan &in)
{
    QSqlQuery query(db);
    query.prepare("UPDATE OR IGNORE cj_score_plans SET name=:name, penalty1=:penalty1, penalty2=:penalty2, converge_to=:converge_to"
                  ", multiplier=:multiplier WHERE id=:id");
    query.bindValue(":name", in.name());
    query.bindValue(":penalty1", in.penalty1());
    query.bindValue(":penalty2", in.penalty2());
    query.bindValue(":converge_to", in.convergeTo());
    query.bindValue(":multiplier", in.multiplier());
    query.bindValue(":id", in.ID());

    execute(query);

    if (query.numRowsAffected())
        return StatCode::OperationSuccessful;
    else
        return StatCode::AlreadyExists;
}

void Database::removeScorePlan(QString name, qint64 id, qint64 replace_id)
{
    QSqlQuery replaceQuery(db);
    replaceQuery.prepare("UPDATE cj_problems SET score_plan=:replace_id WHERE score_plan=:id");
    replaceQuery.bindValue(":replace_id", replace_id);
    replaceQuery.bindValue(":id", id);
    execute(replaceQuery);

    QSqlQuery query(db);
    query.prepare("DELETE FROM cj_score_plans WHERE name=:name");
    query.bindValue(":name", name);
    execute(query);
}

qint64 Database::getScoreID(QString name)
{
    QSqlQuery query(db);
    query.prepare("SELECT id FROM cj_score_plans WHERE name=:name");
    query.bindValue(":name", name);

    execute(query);

    if (query.next())
        return query.value(0).toLongLong();
    else
        return -1;
}

QList<User> Database::userQuery(const DataTable &DT)
{
    QString qu("SELECT username, description, join_date, approved, num_submits, num_corrects, is_admin, score "
               "FROM cj_users %1 ORDER BY ");

    if (DT["order"] == "id")
        qu += "id";
    else if (DT["order"] == "name")
        qu += "username";
    else if (DT["order"] == "score")
        qu += "score";
    else if (DT["order"] == "#corrects")
        qu += "num_corrects";
    else if (DT["order"] == "#submits")
        qu += "num_submits";
    else
        NotAuthorizedException().raise();

    qu += " ";

    if (DT["order_type"] == "asc" || DT["order_type"] == "desc")
        qu += DT["order_type"].toString().toUpper();
    else
        NotAuthorizedException().raise();

    if (DT.contains("count"))
        qu += QString(" LIMIT %1").arg(DT["count"].toInt());

    ConditionalQuery CQ(db, qu);

    if (DT.contains("username"))
        CQ.addCond("username LIKE ", DT["username"].toString());
    if (DT.contains("enabled"))
        CQ.addCond("approved=", DT["enabled"].toInt());

    QSqlQuery query = CQ.resultQuery();
    execute(query);

    QList<User> result;
    while (query.next())
    {
        QString uname = query.value(0).toString();
        QString desc = query.value(1).toString();
        QDateTime joind = QDateTime::fromMSecsSinceEpoch(query.value(2).toLongLong());
        bool enabled = query.value(3).toBool();
        qint64 numSubs = query.value(4).toLongLong();
        qint64 numCors = query.value(5).toLongLong();
        bool isAdm = query.value(6).toBool();
        qreal scre = query.value(7).toDouble();

        result.append(User(uname, desc, joind, enabled, numSubs, numCors, isAdm, scre));
    }

    return result;
}

StatCode Database::changeAdminState(const QString &name, bool state)
{
    if (state == false)
    {
        QSqlQuery query(db);
        query.prepare("SELECT count(*) FROM cj_users WHERE is_admin=1");

        execute(query);

        query.next();
        if (query.value(0).toInt() < 2)
            return StatCode::NotTheOnlyAdmin;
    }

    QSqlQuery query(db);
    query.prepare("UPDATE cj_users SET is_admin=:state WHERE username=:username");
    query.bindValue(":state", static_cast<int>(state));
    query.bindValue(":username", name);
    execute(query);

    return StatCode::OperationSuccessful;
}

void Database::changeActivationState(const QString &name, bool state)
{
    if (state == false && isAdmin(getuid(name)))
        NotAuthorizedException().raise();

    QSqlQuery query(db);
    query.prepare("UPDATE cj_users SET approved=:state WHERE username=:username");
    query.bindValue(":state", static_cast<int>(state));
    query.bindValue(":username", name);
    execute(query);
}

void Database::deleteUser(qint64 id)
{
    if (isAdmin(id))
        NotAuthorizedException().raise();

    QSqlQuery query(db);
    query.prepare("DELETE FROM cj_users WHERE id=:id");
    query.bindValue(":id", id);
    execute(query);

    query.prepare("DELETE FROM cj_submits WHERE uid=:id");
    query.bindValue(":id", id);
    execute(query);

    query.prepare("DELETE FROM cj_scores_data WHERE uid=:id");
    query.bindValue(":id", id);
    execute(query);

    query.prepare("DELETE FROM cj_contests_data WHERE uid=:id");
    query.bindValue(":id", id);
    execute(query);
}

void Database::changeDescription(const QString &name, const QString &desc)
{
    QSqlQuery query(db);
    query.prepare("UPDATE cj_users SET description=:description WHERE username=:username");
    query.bindValue(":description", desc);
    query.bindValue(":username", name);
    execute(query);
}

StatCode Database::renameUser(const QString &old, const QString &cur)
{
    QSqlQuery query(db);
    query.prepare("UPDATE OR IGNORE cj_users SET username=:new WHERE username=:old");
    query.bindValue(":new", cur);
    query.bindValue(":old", old);
    execute(query);

    if (query.numRowsAffected())
        return StatCode::OperationSuccessful;
    else
        return StatCode::AlreadyExists;
}

bool Database::isAdmin(qint64 id)
{
    QSqlQuery query(db);
    query.prepare("SELECT is_admin FROM cj_users WHERE id=:id");
    query.bindValue(":id", id);
    execute(query);

    return query.next() && query.value(0).toBool();
}

ScorePlan Database::giveScorePlan(qint64 pid)
{
    QSqlQuery query(db);
    query.prepare("SELECT S.name FROM cj_problems"
                  " AS P INNER JOIN cj_score_plans AS S ON P.score_plan=S.id WHERE p.id=:pid");
    query.bindValue(":pid", pid);
    execute(query);

    if (query.next())
        return scorePlanDetails(query.value(0).toString());
    else
        return ScorePlan();
}

void Database::recomputeScore(qint64 uid)
{
    QSqlQuery query(db);
    query.prepare("SELECT SUM(score), SUM(num_submits) FROM cj_contests_data WHERE uid=:uid");
    query.bindValue(":uid", uid);
    execute(query);

    if (query.next())
    {
        qreal score = query.value(0).toDouble();
        qint64 num_submits = query.value(1).toLongLong();

        query.prepare("SELECT COUNT(*) FROM (SELECT COUNT(*) FROM cj_scores_data "
                      "WHERE uid=:uid AND correct_attempt=1 GROUP BY pid)");
        query.bindValue(":uid", uid);
        execute(query);

        if (query.next())
        {
            qint64 num_corrects = query.value(0).toLongLong();

            query.prepare("UPDATE cj_users SET score=:score, num_submits=:num_submits, num_corrects=:num_corrects WHERE id=:uid");
            query.bindValue(":score", score);
            query.bindValue(":num_submits", num_submits);
            query.bindValue(":num_corrects", num_corrects);
            query.bindValue(":uid", uid);
            execute(query);
        }
    }
}

void Database::recomputeContestScore(qint64 cid, qint64 uid)
{
    QSqlQuery query(db);
    query.prepare("SELECT SUM(max_score), SUM(num_attempts) FROM cj_scores_data WHERE uid=:uid AND cid=:cid");
    query.bindValue(":uid", uid);
    query.bindValue(":cid", cid);
    execute(query);

    if (query.next())
    {
        qreal score = query.value(0).toDouble();
        qint64 num_submits = query.value(1).toLongLong();

        query.prepare("SELECT COUNT(*) FROM cj_scores_data WHERE uid=:uid AND cid=:cid AND correct_attempt=1");
        query.bindValue(":uid", uid);
        query.bindValue(":cid", cid);

        execute(query);
        if (query.next())
        {
            qint64 num_corrects = query.value(0).toLongLong();

            query.prepare("INSERT OR IGNORE INTO cj_contests_data (cid, uid, score, num_submits, num_corrects) "
                          "VALUES(:cid, :uid, 0, 0, 0)");
            query.bindValue(":uid", uid);
            query.bindValue(":cid", cid);
            execute(query);

            query.prepare("UPDATE cj_contests_data SET score=:score, num_submits=:num_submits, num_corrects=:num_corrects WHERE uid=:uid AND cid=:cid");
            query.bindValue(":score", score);
            query.bindValue(":num_submits", num_submits);
            query.bindValue(":num_corrects", num_corrects);
            query.bindValue(":uid", uid);
            query.bindValue(":cid", cid);
            execute(query);
        }
    }
}

void Database::processScore(qint64 sid)
{
    QMutexLocker mutexLocker(mutex2);

    QSqlQuery query(db);
    query.prepare("SELECT S.uid, S.pid, S.last_test, P.num_tests, P.complete_judge, P.cid, S.date_and_time FROM cj_submits AS S "
                  "INNER JOIN cj_problems AS P ON S.pid=P.id WHERE S.id=:sid");
    query.bindValue(":sid", sid);
    execute(query);
    if (!query.next())
        return;

    qint64 uid = query.value(0).toLongLong();
    qint64 pid = query.value(1).toLongLong();
    qint64 lastTest = query.value(2).toLongLong();
    qint64 num_tests = query.value(3).toLongLong();
    bool completeJudge = query.value(4).toBool();
    qint64 cid = query.value(5).toLongLong();
    qint64 datetime = query.value(6).toLongLong();

    if (cid != -1)
    {
        Contest con = contestDetails(cid);
        if (datetime < con.contestStart().toMSecsSinceEpoch()
            || datetime > con.contestEnd().toMSecsSinceEpoch())
            cid = -1;
    }

    bool correct = (lastTest == num_tests);
    qreal ration = (completeJudge ? (static_cast<qreal>(lastTest) / num_tests) : correct);

    query.prepare("INSERT OR IGNORE INTO cj_scores_data (uid, pid, num_attempts, correct_attempt, max_score, cid) "
                  "VALUES(:uid, :pid, 0, 0, 0, :cid)");
    query.bindValue(":uid", uid);
    query.bindValue(":pid", pid);
    query.bindValue(":cid", cid);
    execute(query);

    qreal delta = 0;

    query.prepare("SELECT num_corrects FROM cj_problems WHERE id=:pid");
    query.bindValue(":pid", pid);
    execute(query);
    if (query.next())
    {
        qint64 rank = query.value(0).toLongLong() + 1;

        query.prepare("SELECT SUM(num_attempts), SUM(correct_attempt), SUM(max_score) FROM cj_scores_data WHERE uid=:uid AND pid=:pid");
        query.bindValue(":uid", uid);
        query.bindValue(":pid", pid);
        execute(query);
        query.next();

        qint64 attempt = query.value(0).toLongLong() + 1;
        qint64 cors = query.value(1).toLongLong();
        qreal mscore = query.value(2).toDouble();
        qreal newScore = mscore;

        if (config()->getConfig("score_system").toBool())
        {
            ScorePlan plan = giveScorePlan(pid);
            newScore = qMax(mscore, plan.query(attempt, rank) * ration);
            delta = newScore - mscore;
        }

        query.prepare("UPDATE cj_scores_data SET num_attempts=num_attempts+1, "
                      "max_score=max_score+:delta WHERE uid=:uid AND pid=:pid AND cid=:cid");
        query.bindValue(":delta", delta);
        query.bindValue(":uid", uid);
        query.bindValue(":pid", pid);
        query.bindValue(":cid", cid);
        execute(query);

        if (correct)
        {
            if (cors == 0)
            {
                query.prepare("UPDATE cj_problems SET num_corrects=num_corrects+1 WHERE id=:pid");
                query.bindValue(":pid", pid);
                execute(query);
            }

            query.prepare("UPDATE cj_scores_data SET correct_attempt=1 "
                          "WHERE uid=:uid AND pid=:pid AND cid=:cid");
            query.bindValue(":uid", uid);
            query.bindValue(":pid", pid);
            query.bindValue(":cid", cid);
            execute(query);
        }
    }

    query.prepare("UPDATE cj_submits SET score_diff=:score_diff WHERE id=:sid");
    query.bindValue(":score_diff", delta);
    query.bindValue(":sid", sid);
    execute(query);

    recomputeContestScore(cid, uid);
    recomputeScore(uid);
}

qint64 Database::givePendingScore()
{
    QSqlQuery query(db);

    if (config()->getConfig("score_system").toBool())
    {
        query.prepare("SELECT id, status FROM cj_submits WHERE score_diff=-2 AND status!=:disabled ORDER BY id ASC LIMIT 1");
        query.bindValue(":disabled", static_cast<int>(StatCode::Disabled));
    }
    else
    {
        query.prepare("SELECT id FROM cj_submits WHERE score_diff=-2 AND status!=:disabled AND status!=:pending "
                      "AND status!=:running ORDER BY id ASC LIMIT 1");
        query.bindValue(":disabled", static_cast<int>(StatCode::Disabled));
        query.bindValue(":pending", static_cast<int>(StatCode::InQueue));
        query.bindValue(":running", static_cast<int>(StatCode::Running));
    }

    execute(query);
    if (query.next())
    {
        if (query.value(1).toInt() != static_cast<int>(StatCode::InQueue)
                && query.value(1).toInt() != static_cast<int>(StatCode::Running))
            return query.value(0).toLongLong();
        else
            return -1;
    }
    else
        return -1;
}

void Database::fixBrokenSubmissions()
{
    QSqlQuery query(db);
    query.prepare("UPDATE cj_submits SET status=:pending WHERE status=:running");
    query.bindValue(":pending", static_cast<int>(StatCode::InQueue));
    query.bindValue(":running", static_cast<int>(StatCode::Running));
    execute(query);
}

void Database::removeProblemScore(qint64 pid)
{
    QSqlQuery query(db);
    query.prepare("SELECT uid FROM cj_scores_data WHERE pid=:pid");
    query.bindValue(":pid", pid);
    execute(query);

    QList<qint64> users;
    while (query.next())
        users.append(query.value(0).toLongLong());

    query.prepare("SELECT cid FROM cj_problems WHERE id=:pid");
    query.bindValue(":pid", pid);
    execute(query);
    qint64 cid = -1;
    if (query.next())
        cid = query.value(0).toLongLong();

    query.prepare("DELETE FROM cj_scores_data WHERE pid=:pid");
    query.bindValue(":pid", pid);
    execute(query);

    foreach (qint64 id, users)
    {
        if (cid != -1)
            recomputeContestScore(cid, id);

        recomputeContestScore(-1, id);
        recomputeScore(id);
    }
}

void Database::setConfigs(DataTable &DT)
{
    if (DT.isEmpty())
        return;

    if (DT.contains("judge_threads") && DT["judge_threads"].toInt() < 1)
    {
        int num = QThread::idealThreadCount();
        DT["judge_threads"] = qMax(1, num);
    }

    QString query = "UPDATE cj_config SET ";

    QMapIterator<QString, QVariant> iter(DT);
    while (iter.hasNext())
    {
        iter.next();
        query += iter.key() + "=?";
        if (iter.hasNext())
            query += ", ";
    }

    QSqlQuery quer(db);
    quer.prepare(query);
    iter.toFront();
    while (iter.hasNext())
    {
        iter.next();
        quer.addBindValue(iter.value());
    }
    execute(quer);
}

DataTable Database::loadConfigs()
{
    DataTable DT;

    QList<QString> columns;
    QSqlRecord rec = db.record("cj_config");
    for (int i = 0; i < rec.count(); i++)
        columns.append(rec.fieldName(i));

    QString q1 = "SELECT ";
    QListIterator<QString> iter(columns);
    while (iter.hasNext())
    {
        q1 += iter.next();
        if (iter.hasNext())
            q1 += ", ";
    }

    QSqlQuery query(db);
    query.prepare(q1 + " FROM cj_config");
    execute(query);

    if (query.next())
        for (int i = 0; i < columns.size(); i++)
            DT[columns[i]] = query.value(i);

    if (DT["judge_threads"].toInt() < 1)
    {
        int num = QThread::idealThreadCount();
        DT["judge_threads"] = qMax(1, num);
    }

    return DT;
}

void Database::deleteSubmission(qint64 id)
{
    QSqlQuery query(db);
    query.prepare("DELETE FROM cj_submits WHERE id=:sid");
    query.bindValue(":sid", id);
    execute(query);
}

void Database::submissionPurge(const DataTable &DT)
{
    QString lastx("SELECT t1.id FROM cj_submits AS t1 INNER JOIN cj_submits AS t2 ON t1.uid=t2.uid AND t1.pid=t2.pid"
                  " AND t1.id <= t2.id GROUP BY t1.uid, t1.pid, t1.id HAVING COUNT(*) <= ?");
    QString lastCorx("SELECT t1.id FROM cj_submits AS t1 INNER JOIN cj_submits AS t2 ON t1.uid=t2.uid AND t1.pid=t2.pid"
                     " AND t1.id <= t2.id AND t1.status=%1 AND t2.status=%1 GROUP BY t1.uid, t1.pid, t1.id HAVING COUNT(*) <= ?");
    QString username("SELECT S.id FROM cj_submits AS S INNER JOIN cj_users AS U ON S.uid=U.id WHERE U.username LIKE ?");
    QString problem("SELECT S.id FROM cj_submits AS S INNER JOIN cj_problems AS P ON S.pid=P.id WHERE P.name LIKE ?");

    QString qu("DELETE FROM cj_submits %1");
    ConditionalQuery CQ(db, qu);
    if (DT.contains("username"))
        CQ.addCustomCond(QString("id IN (%1)").arg(username), DT["username"]);
    if (DT.contains("problem"))
        CQ.addCustomCond(QString("id IN (%1)").arg(problem), DT["problem"]);
    if (DT.contains("lastx"))
        CQ.addCustomCond(QString("id NOT IN (%1)").arg(lastx), DT["lastx"].toLongLong());
    if (DT.contains("lastcorx"))
        CQ.addCustomCond(QString("id NOT IN (%1)").arg(lastCorx).arg(static_cast<int>(StatCode::Correct)), DT["lastcorx"].toLongLong());
    if (DT.contains("newerthan"))
        CQ.addCond("date_and_time<", DT["newerthan"].toLongLong());
    if (DT.contains("olderthan"))
        CQ.addCond("date_and_time>", DT["olderthan"].toLongLong());
    if (DT["noncompletes"].toBool())
        CQ.addCond("full_result IS NOT NULL", QVariant());
    if (DT["completes"].toBool())
        CQ.addCond("full_result IS NULL", QVariant());
    if (DT["nonpublics"].toBool())
        CQ.addCond("is_public=", 1);
    if (DT["publics"].toBool())
        CQ.addCond("is_public=", 0);
    if (DT["nonzero"].toBool())
        CQ.addCond("score_diff=", 0);

    QSqlQuery query = CQ.resultQuery();
    execute(query);
}

void Database::purgeFiles()
{
    QDir dir("submits");

    QStringList filter;
    filter << "*.cpp";

    QStringList files = dir.entryList(filter);
    for (int i = 0; i < files.size(); i++)
        files[i] = files[i].mid(0, files[i].length() - 4);

    QSet<QString> subs;
    QSqlQuery query(db);
    query.prepare("SELECT id FROM cj_submits");
    execute(query);
    while (query.next())
        subs.insert(query.value(0).toString());

    QSet<QString> finalSet = files.toSet() - subs;
    files.clear();
    foreach (const QString &str, finalSet)
    {
        QFile::remove("submits/" + str + ".cpp");
        QFile::remove("submits/" + str + ".log");
        QFile::remove("submits/" + str + ".out");
    }
}

void Database::markAsRunning(qint64 sid)
{
    QSqlQuery query(db);
    query.prepare("UPDATE cj_submits SET status=:running WHERE id=:sid");
    query.bindValue(":running", static_cast<int>(StatCode::Running));
    query.bindValue(":sid", sid);
    execute(query);
}

QList<DataTable> Database::scoreboardConfig(qint64 start, int cnt)
{
    QSqlQuery query(db);
    query.prepare("SELECT SB.cid, C.name, SB.type, SB.maximum, SB.page, SB.color_data FROM cj_scoreboard_config AS SB "
                  "INNER JOIN cj_contests AS C ON SB.cid=C.id ORDER BY SB.cid ASC LIMIT :start, :count");
    query.bindValue(":start", start);
    query.bindValue(":count", cnt);
    execute(query);

    QList<DataTable> ret;
    while (query.next())
    {
        DataTable DT;
        DT["id"] = query.value(0).toLongLong();
        DT["name"] = query.value(1).toString();
        DT["type"] = query.value(2).toInt();
        DT["max"] = query.value(3).toLongLong();
        DT["page"] = query.value(4).toInt();
        DT["color"] = query.value(5).toBool();
        ret.append(DT);
    }

    return ret;
}

void Database::scoreboardEdit(const DataTable &DT)
{
    QSqlQuery query(db);
    query.prepare("UPDATE cj_scoreboard_config SET type=:type, maximum=:maximum, page=:page, color_data=:color_data WHERE cid=:id");
    query.bindValue(":type", DT["type"].toInt());
    query.bindValue(":maximum", DT["max"].toLongLong());
    query.bindValue(":page", DT["page"].toInt());
    query.bindValue(":color_data", DT["color"].toInt());
    query.bindValue(":id", DT["id"].toLongLong());
    execute(query);
}

QList<DataTable> Database::scoreboardMetaData()
{
    QSqlQuery query(db);
    query.prepare("SELECT SB.cid, C.name, SB.type FROM cj_scoreboard_config AS SB "
                  " INNER JOIN cj_contests AS C ON SB.cid=C.id WHERE SB.type!=0 AND id>=-2");
    execute(query);

    int filter = config()->getConfig("score_system").toBool() ? 3 : 2;

    QList<DataTable> ret;
    while (query.next())
    {
        DataTable DT;
        DT["id"] = query.value(0).toLongLong();
        DT["name"] = query.value(1).toString();
        DT["type"] = query.value(2).toInt() & filter;
        ret.append(DT);
    }

    return ret;
}

bool Database::isScoreboardAvailable(qint64 cid, int type)
{
    if (cid < -2)
        return false;

    QSqlQuery query(db);
    query.prepare("SELECT type FROM cj_scoreboard_config WHERE cid=:cid");
    query.bindValue(":cid", cid);
    execute(query);

    if (!query.next())
        return false;

    int filter = config()->getConfig("score_system").toBool() ? 3 : 2;

    return (query.value(0).toInt() & filter) & (1 << type);
}

QList<DataTable> Database::scoreboard(qint64 id, int type, qint64 page)
{
    QList<DataTable> ret;

    QSqlQuery query(db);
    query.prepare("SELECT maximum, page, color_data FROM cj_scoreboard_config WHERE cid=:cid");
    query.bindValue(":cid", id);
    execute(query);
    if (!query.next())
        return ret;

    qint64 total = query.value(0).toLongLong();
    int perPage = query.value(1).toInt();
    bool colorData = query.value(2).toBool();

    if (perPage == 0 && page > 0)
        return ret;

    qint64 startValue = page * perPage;

    qint64 cnt = std::numeric_limits<qint64>::max();
    if (perPage != 0)
        cnt = perPage;
    if (total != 0)
        cnt = qMin(cnt, total - page * perPage);
    cnt = qMax(cnt, static_cast<qint64>(0));

    if (cnt == std::numeric_limits<qint64>::max())
        cnt = -1;

    QString valueField;
    if (type == 0)
        valueField = "score";
    else if (type == 1)
        valueField = "num_corrects";
    else
        return ret;

    if (id == -2)
        query.prepare(QString("SELECT username, %1 FROM cj_users WHERE approved=1 ORDER BY %1 DESC LIMIT :start, :count").arg(valueField));
    else
    {
        query.prepare(QString("SELECT U.username, CD.%1 FROM cj_contests_data AS CD "
                              "INNER JOIN cj_users AS U ON CD.uid=U.id WHERE CD.cid=:cid AND U.approved=1 "
                              "ORDER BY CD.%1 DESC LIMIT :start, :count").arg(valueField));
        query.bindValue(":cid", id);
    }

    query.bindValue(":start", startValue);
    query.bindValue(":count", cnt);
    execute(query);

    while (query.next())
    {
        DataTable DT;
        DT["username"] = query.value(0);
        DT["value"] = query.value(1);
        ret.append(DT);
    }

    DataTable info;

    if (colorData)
    {
        if (id == -2)
            query.prepare(QString("SELECT MIN(%1), AVG(%1), MAX(%1) FROM cj_users WHERE approved=1").arg(valueField));
        else
        {
            query.prepare(QString("SELECT MIN(CD.%1), AVG(CD.%1), MAX(CD.%1) FROM cj_contests_data AS CD "
                                  "INNER JOIN cj_users AS U ON CD.uid=U.id "
                                  "WHERE cid=:cid AND U.approved=1").arg(valueField));
            query.bindValue(":cid", id);
        }

        execute(query);
        query.next();

        qreal minVal = query.value(0).toDouble();
        qreal avgVal = query.value(1).toDouble();
        qreal maxVal = query.value(2).toDouble();

        info["min"] = minVal;
        info["avg"] = avgVal;
        info["max"] = maxVal;
    }

    ret.prepend(info);
    return ret;
}

QList<DataTable> Database::getNews()
{
    QList<DataTable> ret;

    QSqlQuery query(db);
    query.prepare("SELECT id, title, content FROM cj_news");
    execute(query);

    while (query.next())
    {
        DataTable DT;
        DT["id"] = query.value(0).toLongLong();
        DT["title"] = query.value(1).toString();
        DT["content"] = query.value(2).toString();
        ret.append(DT);
    }

    return ret;
}

qint64 Database::addNews(const DataTable &in)
{
    QSqlQuery query(db);
    query.prepare("INSERT INTO cj_news (title, content) VALUES (:title, :content)");
    query.bindValue(":title", in["title"]);
    query.bindValue(":content", in["content"]);
    execute(query);

    return query.lastInsertId().toLongLong();
}

void Database::editNews(const DataTable &in)
{
    QSqlQuery query(db);
    query.prepare("UPDATE cj_news SET title=:title, content=:content WHERE id=:id");
    query.bindValue(":title", in["title"]);
    query.bindValue(":content", in["content"]);
    query.bindValue(":id", in["id"]);
    execute(query);
}

void Database::removeNews(qint64 id)
{
    QSqlQuery query(db);
    query.prepare("DELETE FROM cj_news WHERE id=:id");
    query.bindValue(":id", id);
    execute(query);
}

bool Database::hasCorrect(qint64 pid, qint64 uid)
{
    QSqlQuery query(db);
    query.prepare("SELECT correct_attempt FROM cj_scores_data WHERE pid=:pid AND uid=:uid");
    query.bindValue(":pid", pid);
    query.bindValue(":uid", uid);
    execute(query);

    if (query.next())
        return query.value(0).toBool();
    else
        return false;
}

bool Database::submissionAuth(qint64 sid, qint64 uid)
{
    QSqlQuery query(db);
    query.prepare("SELECT S.pid, S.is_public, P.public_subs, P.others_subs FROM cj_submits AS S "
                  "INNER JOIN cj_problems AS P ON S.pid=P.id WHERE S.id=:sid");
    query.bindValue(":sid", sid);
    execute(query);

    if (!query.next())
        return false;

    qint64 pid = query.value(0).toLongLong();
    bool ispub = query.value(1).toBool();
    int pubs = query.value(2).toInt();
    int oths = query.value(3).toInt();
    int authOpt = ispub ? pubs : oths;

    if (authOpt == 0)
        return false;
    else if (authOpt == 1)
        return hasCorrect(pid, uid);
    else if (authOpt == 2)
        return true;
}

QList<Contest> Database::contestUserQuery(int mode, const QString &constr)
{
    QString initial("SELECT id, name, desc, enabled, register_start, register_end, contest_start, "
                    "contest_end, after_contest_view, after_contest_submit FROM cj_contests %1");

    QList<Contest> ans;

    if (mode == 0)
        initial += QString(" ORDER BY id DESC LIMIT %1").arg(constr.toInt());
    else if (mode != 1)
        return ans;

    ConditionalQuery CQ(db, initial);
    CQ.addCond("id>=", 0);
    if (mode == 1)
        CQ.addCond("name LIKE ", constr);
    CQ.addCond("enabled=", 1);

    QSqlQuery query = CQ.resultQuery();

    execute(query);
    while (query.next())
    {
        qint64 ID = query.value(0).toLongLong();
        QString name = query.value(1).toString();
        QString desc = query.value(2).toString();
        bool enab = query.value(3).toBool();
        QDateTime regStart = QDateTime::fromMSecsSinceEpoch(query.value(4).toLongLong());
        QDateTime regEnd = QDateTime::fromMSecsSinceEpoch(query.value(5).toLongLong());
        QDateTime conStart = QDateTime::fromMSecsSinceEpoch(query.value(6).toLongLong());
        QDateTime conEnd = QDateTime::fromMSecsSinceEpoch(query.value(7).toLongLong());
        bool aftV = query.value(8).toBool();
        bool aftS = query.value(9).toBool();

        ans.append(Contest(ID, name, desc, enab, regStart, regEnd, conStart, conEnd, aftV, aftS));
    }

    return ans;
}

StatCode Database::addContest(const Contest &con)
{
    QSqlQuery query(db);
    query.prepare("INSERT INTO cj_contests (name, desc, enabled, register_start, register_end, contest_start, "
                  "contest_end, after_contest_view, after_contest_submit) "
                  "VALUES (:name, :desc, :enabled, :register_start, :register_end, :contest_start, :contest_end, "
                  ":after_contest_view, :after_contest_submit)");
    query.bindValue(":name", con.name());
    query.bindValue(":desc", con.description());
    query.bindValue(":enabled", static_cast<int>(con.enabled()));
    query.bindValue(":register_start", con.registerStart().toMSecsSinceEpoch());
    query.bindValue(":register_end", con.registerEnd().toMSecsSinceEpoch());
    query.bindValue(":contest_start", con.contestStart().toMSecsSinceEpoch());
    query.bindValue(":contest_end", con.contestEnd().toMSecsSinceEpoch());
    query.bindValue(":after_contest_view", static_cast<int>(con.afterContestView()));
    query.bindValue(":after_contest_submit", static_cast<int>(con.afterContestSubmit()));
    execute(query);

    if (query.numRowsAffected())
    {
        qint64 cid = query.lastInsertId().toLongLong();
        query.prepare("INSERT OR IGNORE INTO cj_scoreboard_config (cid, type, maximum, page, color_data) "
                      "SELECT :cid, type, maximum, page, color_data FROM cj_scoreboard_config WHERE cid=:code");
        query.bindValue(":cid", cid);
        query.bindValue(":code", -3);
        execute(query);

        return StatCode::OperationSuccessful;
    }
    else
        return StatCode::AlreadyExists;
}

StatCode Database::editContest(const Contest &con)
{
    QSqlQuery query(db);
    query.prepare("UPDATE cj_contests SET name=:name, desc=:desc, enabled=:enabled, register_start=:register_start, "
                  "register_end=:register_end, contest_start=:contest_start, contest_end=:contest_end, "
                  "after_contest_view=:after_contest_view, after_contest_submit=:after_contest_submit "
                  "WHERE id=:id");
    query.bindValue(":name", con.name());
    query.bindValue(":desc", con.description());
    query.bindValue(":enabled", static_cast<int>(con.enabled()));
    query.bindValue(":register_start", con.registerStart().toMSecsSinceEpoch());
    query.bindValue(":register_end", con.registerEnd().toMSecsSinceEpoch());
    query.bindValue(":contest_start", con.contestStart().toMSecsSinceEpoch());
    query.bindValue(":contest_end", con.contestEnd().toMSecsSinceEpoch());
    query.bindValue(":after_contest_view", static_cast<int>(con.afterContestView()));
    query.bindValue(":after_contest_submit", static_cast<int>(con.afterContestSubmit()));
    query.bindValue(":id", con.ID());
    execute(query);

    if (query.numRowsAffected())
        return StatCode::OperationSuccessful;
    else
        return StatCode::AlreadyExists;
}

void Database::removeContest(qint64 cid)
{
    if (cid == -1)
        NotAuthorizedException().raise();

    QSqlQuery query(db);

    query.prepare("UPDATE cj_problems SET cid=-1 WHERE cid=:cid");
    query.bindValue(":cid", cid);
    execute(query);

    query.prepare("DELETE FROM cj_contests_data WHERE cid=:cid");
    query.bindValue(":cid", cid);
    execute(query);

    query.prepare("DELETE FROM cj_scores_data WHERE cid=:cid");
    query.bindValue(":cid", cid);
    execute(query);

    query.prepare("DELETE FROM cj_contests WHERE id=:cid");
    query.bindValue(":cid", cid);
    execute(query);

    query.prepare("DELETE FROM cj_scoreboard_config WHERE cid=:cid");
    query.bindValue(":cid", cid);
    execute(query);
}

QList<QString> Database::contestListQuery(int mode, const QString &constr, bool onlyreal)
{
    QString initial("SELECT name FROM cj_contests %1");

    QList<QString> ans;

    if (mode == 0)
        initial += QString(" ORDER BY id DESC LIMIT %1").arg(constr.toInt());
    else if (mode != 1)
        return ans;

    ConditionalQuery CQ(db, initial);
    if (onlyreal)
        CQ.addCond("id>=", 0);
    else
        CQ.addCond("id>=", -1);
    if (mode == 1)
        CQ.addCond("name LIKE ", constr);

    QSqlQuery query = CQ.resultQuery();
    execute(query);
    while (query.next())
        ans.append(query.value(0).toString());

    return ans;
}

qint64 Database::getContestID(const QString &name)
{
    QSqlQuery query(db);
    query.prepare("SELECT id FROM cj_contests WHERE name=:name");
    query.bindValue(":name", name);

    execute(query);

    if (query.next())
        return query.value(0).toLongLong();
    else
        return -2;
}

QList<QString> Database::currentContests(qint64 uid)
{
    QSqlQuery query(db);
    query.prepare("SELECT name FROM cj_contests WHERE (contest_start<=:time1 AND (:time2<=contest_end OR after_contest_view=1) "
                  "AND id IN (SELECT cid FROM cj_contests_data WHERE uid=:uid)) OR id=-1 ORDER BY id ASC");

    qint64 curTime = QDateTime::currentMSecsSinceEpoch();
    query.bindValue(":time1", curTime);
    query.bindValue(":time2", curTime);
    query.bindValue(":uid", uid);
    execute(query);

    QList<QString> ret;
    while (query.next())
        ret.append(query.value(0).toString());

    return ret;
}

bool Database::canViewContest(qint64 cid, qint64 uid)
{
    if (cid == -1)
        return true;

    QSqlQuery query(db);
    query.prepare("SELECT contest_start, contest_end, enabled, after_contest_view FROM cj_contests WHERE id=:cid");
    query.bindValue(":cid", cid);
    execute(query);

    if (!query.next())
        return false;

    qint64 curTime = QDateTime::currentMSecsSinceEpoch();
    bool timeOK = (query.value(0).toLongLong() <= curTime) && (curTime <= query.value(1).toLongLong()
                                                               || query.value(3).toBool());
    bool enab = query.value(2).toBool();

    if (!(timeOK && enab))
        return false;

    query.prepare("SELECT COUNT(*) FROM cj_contests_data WHERE cid=:cid AND uid=:uid");
    query.bindValue(":cid", cid);
    query.bindValue(":uid", uid);
    execute(query);
    query.next();

    return query.value(0).toBool();
}

bool Database::canSubmitContest(qint64 cid, qint64 uid)
{
    if (cid == -1)
        return true;

    QSqlQuery query(db);
    query.prepare("SELECT contest_start, contest_end, enabled, after_contest_submit FROM cj_contests WHERE id=:cid");
    query.bindValue(":cid", cid);
    execute(query);

    if (!query.next())
        return false;

    qint64 curTime = QDateTime::currentMSecsSinceEpoch();
    bool timeOK = (query.value(0).toLongLong() <= curTime) && (curTime <= query.value(1).toLongLong()
                                                               || query.value(3).toBool());
    bool enab = query.value(2).toBool();

    if (!(timeOK && enab))
        return false;

    query.prepare("SELECT COUNT(*) FROM cj_contests_data WHERE cid=:cid AND uid=:uid");
    query.bindValue(":cid", cid);
    query.bindValue(":uid", uid);
    execute(query);
    query.next();

    return query.value(0).toBool();
}

StatCode Database::registerUserInContest(qint64 cid, qint64 uid)
{
    if (cid < 0)
        NotAuthorizedException().raise();

    QSqlQuery query(db);
    query.prepare("SELECT register_start, register_end FROM cj_contests WHERE id=:cid");
    query.bindValue(":cid", cid);
    execute(query);

    if (!query.next())
        return StatCode::CannotProcessAtThisTime;

    qint64 curTime = QDateTime::currentMSecsSinceEpoch();
    if (curTime < query.value(0).toLongLong() || curTime > query.value(1).toLongLong())
        return StatCode::CannotProcessAtThisTime;

    query.prepare("INSERT OR IGNORE INTO cj_contests_data (cid, uid, score, num_submits, num_corrects) "
                  "VALUES(:cid, :uid, 0, 0, 0)");
    query.bindValue(":cid", cid);
    query.bindValue(":uid", uid);
    execute(query);

    if (query.numRowsAffected())
        return StatCode::OperationSuccessful;
    else
        return StatCode::AlreadyRegistered;
}

bool Database::canViewProblem(const QString &name, qint64 uid)
{
    QSqlQuery query(db);
    query.prepare("SELECT cid, enabled FROM cj_problems WHERE name=:name");
    query.bindValue(":name", name);
    execute(query);

    if (query.next())
    {
        qint64 cid = query.value(0).toLongLong();
        bool enab = query.value(1).toBool();
        if (enab)
            return canViewContest(cid, uid);
        else
            return false;
    }
    else
        return false;
}

bool Database::canSubmitProblem(const QString &name, qint64 uid)
{
    QSqlQuery query(db);
    query.prepare("SELECT cid, enabled FROM cj_problems WHERE name=:name");
    query.bindValue(":name", name);
    execute(query);

    if (query.next())
    {
        qint64 cid = query.value(0).toLongLong();
        bool enab = query.value(1).toBool();
        if (enab)
            return canSubmitContest(cid, uid);
        else
            return false;
    }
    else
        return false;
}

Contest Database::contestDetails(qint64 cid)
{
    QSqlQuery query(db);
    query.prepare("SELECT id, name, desc, enabled, register_start, register_end, contest_start, "
                  "contest_end, after_contest_view, after_contest_submit FROM cj_contests WHERE id=:cid");
    query.bindValue(":cid", cid);
    execute(query);

    if (query.next())
    {
        qint64 ID = query.value(0).toLongLong();
        QString name = query.value(1).toString();
        QString desc = query.value(2).toString();
        bool enab = query.value(3).toBool();
        QDateTime regStart = QDateTime::fromMSecsSinceEpoch(query.value(4).toLongLong());
        QDateTime regEnd = QDateTime::fromMSecsSinceEpoch(query.value(5).toLongLong());
        QDateTime conStart = QDateTime::fromMSecsSinceEpoch(query.value(6).toLongLong());
        QDateTime conEnd = QDateTime::fromMSecsSinceEpoch(query.value(7).toLongLong());
        bool aftV = query.value(8).toBool();
        bool aftS = query.value(9).toBool();

        return Contest(ID, name, desc, enab, regStart, regEnd, conStart, conEnd, aftV, aftS);
    }
    else
        return Contest();
}

QList<DataTable> Database::userRecord(qint64 uid, qint64 start, int count)
{
    QSqlQuery query(db);
    query.prepare("SELECT P.name, C.name, SD.num_attempts, SD.correct_attempt, SD.max_score FROM cj_scores_data AS SD "
                  "INNER JOIN cj_contests AS C ON SD.cid=C.id INNER JOIN cj_problems AS P ON SD.pid=P.id "
                  "WHERE uid=:uid LIMIT :start, :count");
    query.bindValue(":uid", uid);
    query.bindValue(":start", start);
    query.bindValue(":count", count);
    execute(query);

    QList<DataTable> ret;

    while (query.next())
    {
        DataTable DT;
        DT["problem"] = query.value(0).toString();
        DT["contest"] = query.value(1).toString();
        DT["submits"] = query.value(2).toLongLong();
        DT["correct"] = query.value(3).toBool();
        DT["score"] = query.value(4).toDouble();
        ret.append(DT);
    }

    return ret;
}

void Database::installTables()
{
    qDebug() << "Installing database tables...";

    QSqlQuery query(db);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_config (registered_enabled BOOLEAN, "
                  "can_submit BOOLEAN, can_viewresult BOOLEAN, can_viewresult_all_nonpublic BOOLEAN, "
                  "can_viewresult_all_public BOOLEAN, max_subs_in_queue INTEGER, max_packet_size INTEGER, "
                  "server_timeout INTEGER, default_result_count INTEGER, score_system BOOLEAN, can_register BOOLEAN, "
                  "judge_enabled BOOLEAN, judge_threads INTEGER, max_library_size INTEGER, real_timer BOOLEAN)");
    execute(query);
    query.prepare("DELETE FROM cj_config");
    execute(query);
    query.prepare("INSERT INTO cj_config (registered_enabled, can_submit, can_viewresult, can_viewresult_all_nonpublic, "
                  "can_viewresult_all_public, max_subs_in_queue, max_packet_size, server_timeout, default_result_count, "
                  "score_system, can_register, judge_enabled, judge_threads, max_library_size, real_timer) "
                  "VALUES (1, 1, 1, 1, 1, 10, 64000, 20, 10, 1, 1, 1, 1, 20000, 0)");
    execute(query);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_contests (id INTEGER PRIMARY KEY ASC AUTOINCREMENT, name TEXT UNIQUE, "
                  "desc TEXT, enabled BOOLEAN, register_start INTEGER, register_end INTEGER, contest_start INTEGER, "
                  "contest_end INTEGER, after_contest_view BOOLEAN, after_contest_submit BOOLEAN)");
    execute(query);

    query.prepare("DELETE FROM cj_contests WHERE id<0");
    execute(query);

    query.prepare("INSERT INTO cj_contests (id, name) VALUES (-3, \"Default Config\")");
    execute(query);
    query.prepare("INSERT INTO cj_contests (id, name) VALUES (-2, \"Total Scoreboard\")");
    execute(query);
    query.prepare("INSERT INTO cj_contests (id, name) VALUES (-1, \"No Contest\")");
    execute(query);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_contests_data (cid INTEGER, uid INTEGER, score REAL, "
                  "num_submits INTEGER, num_corrects INTEGER, PRIMARY KEY (cid, uid))");
    execute(query);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_info (version TEXT)");
    execute(query);
    query.prepare("DELETE FROM cj_info");
    execute(query);
    query.prepare("INSERT INTO cj_info (version) VALUES (:version)");
    query.bindValue(":version", Config::version());
    execute(query);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_news (id INTEGER PRIMARY KEY ASC AUTOINCREMENT, title TEXT, content TEXT)");
    execute(query);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_problems (id INTEGER PRIMARY KEY ASC AUTOINCREMENT, name TEXT UNIQUE, desc TEXT, "
                  "num_tests INTEGER, time_limit INTEGER, memory_limit INTEGER, complete_judge BOOLEAN, enabled BOOLEAN, score_plan INTEGER, "
                  "num_corrects INTEGER DEFAULT (0), desc_file TEXT, folder TEXT, public_subs INTEGER, others_subs INTEGER, cid INTEGER)");
    execute(query);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_score_plans (id INTEGER PRIMARY KEY ASC AUTOINCREMENT, name TEXT UNIQUE, "
                  "penalty1 REAL, penalty2 REAL, converge_to REAL, multiplier REAL)");
    execute(query);

    query.prepare("INSERT OR IGNORE INTO cj_score_plans (name, penalty1, penalty2, converge_to, multiplier) "
                  "VALUES(\"No Penalty\", 0, 0, 0, 100)");
    execute(query);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_scoreboard_config (cid INTEGER PRIMARY KEY, type INTEGER, maximum INTEGER, "
                  "page INTEGER, color_data BOOLEAN)");
    execute(query);

    query.prepare("DELETE FROM cj_scoreboard_config WHERE cid<0");
    execute(query);

    query.prepare("INSERT INTO cj_scoreboard_config (cid, type, maximum, page, color_data) VALUES (-3, 3, 0, 10, 1)");
    execute(query);
    query.prepare("INSERT INTO cj_scoreboard_config (cid, type, maximum, page, color_data) VALUES (-2, 3, 0, 10, 1)");
    execute(query);
    query.prepare("INSERT INTO cj_scoreboard_config (cid, type, maximum, page, color_data) VALUES (-1, 3, 0, 10, 1)");
    execute(query);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_scores_data (uid INTEGER, pid INTEGER, num_attempts INTEGER, correct_attempt BOOLEAN, "
                  "max_score REAL, cid INTEGER, PRIMARY KEY (uid, pid, cid))");
    execute(query);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_submits (id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER, pid INTEGER, "
                  "date_and_time INTEGER, status INTEGER, last_test INTEGER, max_time INTEGER, max_memory INTEGER, "
                  "full_result TEXT, is_public BOOLEAN, score_diff REAL)");
    execute(query);

    query.prepare("CREATE TABLE IF NOT EXISTS cj_users (id INTEGER PRIMARY KEY ASC AUTOINCREMENT, username TEXT UNIQUE, password TEXT, "
                  "description TEXT, approved BOOLEAN, num_submits INTEGER DEFAULT (0), num_corrects INTEGER DEFAULT (0), "
                  "is_admin BOOLEAN DEFAULT (0), score REAL DEFAULT (0), join_date INTEGER)");
    execute(query);
    query.prepare("INSERT OR IGNORE INTO cj_users (username, password, description, approved, num_submits, num_corrects, is_admin, score, join_date) "
                  "VALUES(\"admin\", \"ISMvKXpXpadDiUoOSoAfww==\", \"Server Main Admin\", 1, 0, 0, 1, 0, :date)");
    query.bindValue(":date", QDateTime::currentMSecsSinceEpoch());
    execute(query);

    query.prepare("CREATE UNIQUE INDEX IF NOT EXISTS contests_index ON cj_contests (id ASC)");
    execute(query);

    query.prepare("CREATE UNIQUE INDEX IF NOT EXISTS contests_data_index ON cj_contests_data (cid ASC, uid ASC)");
    execute(query);

    query.prepare("CREATE UNIQUE INDEX IF NOT EXISTS problems_index ON cj_problems (id ASC)");
    execute(query);

    query.prepare("CREATE UNIQUE INDEX IF NOT EXISTS problems_index_2 ON cj_problems (name ASC)");
    execute(query);

    query.prepare("CREATE UNIQUE INDEX IF NOT EXISTS scores_data_index ON cj_scores_data (uid ASC, pid ASC, cid ASC)");
    execute(query);

    query.prepare("CREATE UNIQUE INDEX IF NOT EXISTS users_index ON cj_users (id ASC)");
    execute(query);

    query.prepare("CREATE UNIQUE INDEX IF NOT EXISTS users_index_2 ON cj_users (username ASC)");
    execute(query);

    query.prepare("CREATE INDEX IF NOT EXISTS submits_index ON cj_submits (uid ASC, pid ASC)");
    execute(query);

    qDebug() << "Done installing database tables.";
}
