/*
 * This file is part of community judge server project developed by Shervin Kh.
 * Copyright (C) 2014  Shervin Kh.
 * License: GPLv3 Or Later
 * Full license could be found in License file shipped with program or at http://www.gnu.org/licenses/
*/

#include <QtNetwork>
#include <QMap>
#include <QVariant>
#include "serverthread.h"
#include "database.h"
#include "tcpserver.h"
#include "config.h"

const int ServerThread::FILE_BUFFER_SIZE = 4096;
const int ServerThread::SCOREBOARD_CONFIG_PAGE_LENGTH = 10;
const int ServerThread::USER_RECORD_PAGE_LENGTH = 20;

ServerThread::ServerThread(Database *datab, TcpServer *ts, int socket, bool ssl,
                           QSslCertificate *crt, QSslKey *ky, QObject *parent) :
    QObject(parent), isSsl(ssl), cert(crt), key(ky), database(datab), tcpServer(ts),
    socketDescriptor(socket), length(-1), registeredIP(false), registeredUser(false),
    isAdmin(false), isActive(false)
{
}

void ServerThread::run()
{
    if (isSsl)
        serverSocket = new QSslSocket;
    else
        serverSocket = new QTcpSocket;

    if (!serverSocket->setSocketDescriptor(socketDescriptor))
    {
        serverSocket->deleteLater();
        return;
    }

    if (isSsl)
    {
        QSslSocket *ss = qobject_cast<QSslSocket *>(serverSocket);
        ss->setLocalCertificate(*cert);
        ss->setPrivateKey(*key);
        ss->setProtocol(QSsl::SecureProtocols);
        ss->startServerEncryption();
    }

    connect(serverSocket, SIGNAL(readyRead()), this, SLOT(readData()));
    connect(serverSocket, SIGNAL(disconnected()), this, SLOT(cleanup()));
    connect(serverSocket, SIGNAL(destroyed()), this, SIGNAL(done()));
    client.setDevice(serverSocket);

    if (!tcpServer->registerIP(serverSocket->peerAddress()))
        serverSocket->disconnectFromHost();
    else
        registeredIP = true;

    QTimer::singleShot(database->config()->getConfig("server_timeout").toLongLong() * 1000,
                       this, SLOT(disconnectSocket()));
}

void ServerThread::cleanup()
{
    if (registeredIP)
        tcpServer->unregisterIP(serverSocket->peerAddress());
    if (registeredUser)
        tcpServer->unregisterUser(username);
    serverSocket->deleteLater();
}

void ServerThread::sendSingleStatCode(StatCode stat)
{
    client << static_cast<int>(sizeof(int));
    client << static_cast<int>(stat);
}

void ServerThread::readData()
{
    if (serverSocket->state() != QAbstractSocket::ConnectedState)
        return;

    if (length == -1)
    {
        if (serverSocket->bytesAvailable() < sizeof(int))
            return;

        client >> length;

        if (length > database->config()->getConfig("max_packet_size").toLongLong() || length < 4)
            serverSocket->disconnectFromHost();
    }

    qint64 bytesToRead = qMin(serverSocket->bytesAvailable(), static_cast<qint64>(length - receivedData.length()));
    receivedData += serverSocket->read(bytesToRead);

    if (receivedData.length() == length)
    {
        clientRequest = new QDataStream(receivedData);
        clientRequest->setVersion(QDataStream::Qt_4_8);
        DataTable auth;
        (*clientRequest) >> auth;

        int mod;
        (*clientRequest) >> mod;
        StatCode mode = static_cast<StatCode>(mod);

        if (auth["version"] != Config::version())
            sendSingleStatCode(StatCode::IncompatibleVersion);
        else
        {
            try
            {
                if (!auth.contains("user"))
                {
                    if (mode == StatCode::RegisterationRequest)
                    {
                        if (database->config()->getConfig("can_register").toBool())
                            handleRegisterRequest();
                        else
                            sendSingleStatCode(StatCode::NotAvailable);
                    }
                }
                else
                {
                    StatCode stat = database->userStat(auth["user"].toString(), auth["pass"].toByteArray().toBase64());

                    if (stat == StatCode::UserOK || stat == StatCode::AdminOK)
                    {
                        username = auth["user"].toString();
                        uid = database->getuid(username);
                        isAdmin = stat == StatCode::AdminOK;

                        if (!tcpServer->registerUser(username))
                            serverSocket->disconnectFromHost();
                        else
                            registeredUser = true;

                        if (mode == StatCode::LoginRequest)
                            sendSingleStatCode(stat);
                        else if (mode == StatCode::SubmissionRequest)
                            handleSubmission();
                        else if (mode == StatCode::ResultRequest)
                            handleResultRequest();
                        else if (mode == StatCode::CompilerLogRequest)
                            handleCompilerLogRequest();
                        else if (mode == StatCode::ViewCodeRequest)
                            handleCodeViewRequest();
                        else if (mode == StatCode::ChangePasswordRequest)
                            handleChangePassword();
                        else if (mode == StatCode::ChangePublicState)
                            handleChangePublicState();
                        else if (mod >= static_cast<int>(StatCode::ProblemManagementQuery)
                                 && mod <= static_cast<int>(StatCode::ProblemManagementRejudge))
                            handleProblemManagement(mode);
                        else if (mod >= static_cast<int>(StatCode::ScorePlanQuery)
                                 && mod <= static_cast<int>(StatCode::ScorePlanRemove))
                            handleScorePlan(mode);
                        else if (mod >= static_cast<int>(StatCode::UserQuery)
                                 && mod <= static_cast<int>(StatCode::UserChangeDescription))
                            handleUserManagement(mode);
                        else if (mode == StatCode::ViewProfile)
                            handleViewProfile();
                        else if (mode == StatCode::SetConfig || mode == StatCode::GetConfig)
                            handleConfig(mode);
                        else if (mode == StatCode::DeleteSubmission)
                            handleDeleteSubmission();
                        else if (mode == StatCode::SubmissionPurge)
                            handleSubmissionPurge();
                        else if (mode == StatCode::PurgeFiles)
                            handlePurgeFiles();
                        else if (mod >= static_cast<int>(StatCode::ScoreboardConfig)
                                 && mod <= static_cast<int>(StatCode::Scoreboard))
                            handleScoreboard(mode);
                        else if (mode == StatCode::GiveDescription)
                            handleGiveDescription();
                        else if (mod >= static_cast<int>(StatCode::GetNews)
                                 && mod <= static_cast<int>(StatCode::RemoveNews))
                            handleNews(mode);
                        else if (mod >= static_cast<int>(StatCode::ContestUserQuery)
                                 && mod <= static_cast<int>(StatCode::ContestRemove))
                            handleContestManagement(mode);
                        else if (mode == StatCode::UserRecord)
                            handleUserRecord();
                        else
                            NotAuthorizedException().raise();
                    }
                    else
                        sendSingleStatCode(stat);
                }
            }
            catch (const DatabaseException &)
            {
                    sendSingleStatCode(StatCode::InternalDatabaseError);
            }
            catch (const FileOperationException &)
            {
                    sendSingleStatCode(StatCode::InternalFileOperationError);
            }
            catch (const NotAuthorizedException &)
            {
                    sendSingleStatCode(StatCode::NotAuthorized);
            }
        }

        delete clientRequest;

        if (!isActive)
            serverSocket->disconnectFromHost();
    }
}

void ServerThread::handleRegisterRequest()
{
    QString uname, description;
    QByteArray passwd;
    (*clientRequest) >> uname >> passwd >> description;

    StatCode stat = database->userStat(uname);
    StatCode result;

    if (stat == StatCode::NoSuchUser)
    {
        database->registerUser(uname, passwd.toBase64(), description);
        result = StatCode::OperationSuccessful;
    }
    else
        result = StatCode::AlreadyExists;

    sendSingleStatCode(result);
}

void ServerThread::handleSubmission()
{
    if (!isAdmin && !database->config()->getConfig("can_submit").toBool())
    {
        sendSingleStatCode(StatCode::NotAvailable);
        return;
    }

    QString pname;
    QByteArray code;
    (*clientRequest) >> pname >> code;

    StatCode result;
    qint64 pid = database->getpid(pname);

    if (pid != -1 && (isAdmin || database->canSubmitProblem(pname, uid)))
    {
        if (database->numPendingSubmits(uid) >= database->config()->getConfig("max_subs_in_queue").toLongLong())
            result = StatCode::SlowDown;
        else
        {
            qint64 subid = database->makeNewSubmit(uid, pid);

            QFile codeFile(QString("submits/%1.cpp").arg(subid));
            if (codeFile.open(QIODevice::WriteOnly))
            {
                QTextStream TS1(&codeFile);
                TS1 << code;
                TS1.flush();
                codeFile.close();

                result = StatCode::OperationSuccessful;
                database->updateSubmitStatus(subid, StatCode::InQueue, 0, 0, 0);
                emit newSubmit();
            }
            else
                FileOperationException().raise();
        }
    }
    else
        result = StatCode::NoSuchProblem;

    sendSingleStatCode(result);
}

void ServerThread::handleResultRequest()
{
    if (!isAdmin && !database->config()->getConfig("can_viewresult").toBool())
    {
        sendSingleStatCode(StatCode::NotAvailable);
        return;
    }

    DataTable RT;
    (*clientRequest) >> RT;

    if (!isAdmin)
    {
        if (RT.contains("from") && RT["from"] != username)
            NotAuthorizedException().raise();

        if (RT.contains("id"))
            NotAuthorizedException().raise();

        RT["count"] = database->config()->getConfig("default_result_count").toLongLong();
    }

    if (RT.contains("count") && RT["count"] == "default")
        RT["count"] = database->config()->getConfig("default_result_count").toLongLong();

    QList<SubmissionResult> submissions = database->giveSubmits(RT);

    if (!isAdmin)
    {
        if (!database->config()->getConfig("can_viewresult_all_nonpublic").toBool())
            for (int i = 0; i < submissions.size(); i++)
                if (submissions[i].username() != username && !submissions[i].isPublic())
                {
                    submissions.removeAt(i);
                    i--;
                }

        if (!database->config()->getConfig("can_viewresult_all_public").toBool())
            for (int i = 0; i < submissions.size(); i++)
                if (submissions[i].username() != username && submissions[i].isPublic())
                {
                    submissions.removeAt(i);
                    i--;
                }
    }

    if (database->config()->getConfig("score_system").toBool() == false)
        for (int i = 0; i < submissions.size(); i++)
            submissions[i] = submissions[i].deleteScore();

    QByteArray BA;
    QDataStream DS(&BA, QIODevice::Append);
    DS.setVersion(QDataStream::Qt_4_8);
    DS << static_cast<int>(StatCode::OperationSuccessful);
    DS << submissions;

    client << BA;
}

void ServerThread::handleCompilerLogRequest()
{
    qint64 subid;
    (*clientRequest) >> subid;

    if (isAdmin || database->giveUidForSubmit(subid) == uid || database->submissionAuth(subid, uid))
    {
        QFile file(QString("submits/%1.log").arg(subid));

        if (file.open(QIODevice::ReadOnly))
        {
            QTextStream TS(&file);
            QString data = TS.readAll();

            QByteArray BA;
            QDataStream DS2(&BA, QIODevice::Append);
            DS2.setVersion(QDataStream::Qt_4_8);
            DS2 << static_cast<int>(StatCode::OperationSuccessful);
            DS2 << data;

            client << BA;
        }
        else
            FileOperationException().raise();
    }
    else
        sendSingleStatCode(StatCode::CannotViewSubmission);
}

void ServerThread::handleCodeViewRequest()
{
    qint64 subid;
    (*clientRequest) >> subid;

    if (isAdmin || database->giveUidForSubmit(subid) == uid || database->submissionAuth(subid, uid))
    {
        QFile file(QString("submits/%1.cpp").arg(subid));

        if (file.open(QIODevice::ReadOnly))
        {
            QTextStream TS(&file);
            QString data = TS.readAll();

            QByteArray BA;
            QDataStream DS2(&BA, QIODevice::Append);
            DS2.setVersion(QDataStream::Qt_4_8);
            DS2 << static_cast<int>(StatCode::OperationSuccessful);
            DS2 << data;

            client << BA;
        }
        else
            FileOperationException().raise();
    }
    else
        sendSingleStatCode(StatCode::CannotViewSubmission);
}

void ServerThread::handleChangePassword()
{
    QString uname;
    QByteArray passwd;

    (*clientRequest) >> uname >> passwd;

    if (uname == username || isAdmin)
    {
        database->changePassword(uname, passwd.toBase64());
        sendSingleStatCode(StatCode::OperationSuccessful);
    }
    else
        NotAuthorizedException().raise();
}

bool ServerThread::validateProblem(const Problem &prob)
{
    if (!QFile::exists(QString("problems/%1/tester.out").arg(prob.folder())))
        return false;

    for (int i = 1; i <= prob.numTests(); i++)
        if (!QFile::exists(QString("problems/%1/%2.in").arg(prob.folder()).arg(i))
                || !QFile::exists(QString("problems/%1/%2.out").arg(prob.folder()).arg(i)))
            return false;

    return true;
}

void ServerThread::handleProblemManagement(StatCode stat)
{
    QByteArray data;
    QDataStream DS1(&data, QIODevice::Append);
    DS1.setVersion(QDataStream::Qt_4_8);

    if (stat == StatCode::ProblemManagementQuery)
    {
        bool user;
        int mode;
        QString constr;
        QString contest;
        (*clientRequest) >> user >> mode >> constr >> contest;
        if (!isAdmin)
        {
            user = true;
            if (contest.isEmpty())
                NotAuthorizedException().raise();
        }

        if (!user || database->canViewContest(database->getContestID(contest), uid))
        {
            QList<QString> lst = database->problemQuery(mode, constr, user, contest);
            DS1 << static_cast<int>(StatCode::OperationSuccessful) << lst;
        }
        else
            DS1 << static_cast<int>(StatCode::CannotProcessAtThisTime);
    }
    else if (stat == StatCode::ProblemManagementDetails)
    {
        QString name;
        bool user;
        (*clientRequest) >> name >> user;
        if (!isAdmin)
            user = true;

        if (!user || database->canViewProblem(name, uid))
        {
            Problem specs = database->problemDetails(name);
            DS1 << static_cast<int>(StatCode::OperationSuccessful) << specs;
        }
            DS1 << static_cast<int>(StatCode::CannotProcessAtThisTime);
    }
    else if (stat == StatCode::ProblemManagementEdit)
    {
        if (!isAdmin)
            NotAuthorizedException().raise();

        Problem prob;
        (*clientRequest) >> prob;
        if (validateProblem(prob))
        {
            if (prob.ID() == -1)
                DS1 << static_cast<int>(database->addProblem(prob));
            else
                DS1 << static_cast<int>(database->editProblem(prob));
        }
        else
            DS1 << static_cast<int>(StatCode::ProblemNotEnoughData);
    }
    else if (stat == StatCode::ProblemManagementRemove)
    {
        if (!isAdmin)
            NotAuthorizedException().raise();

        QString name;
        (*clientRequest) >> name;
        database->removeProblem(database->getpid(name));
        DS1 << static_cast<int>(StatCode::OperationSuccessful);
    }
    else if (stat == StatCode::ProblemManagementRejudge)
    {
        if (!isAdmin)
            NotAuthorizedException().raise();

        QString name;
        (*clientRequest) >> name;
        database->rejudgeProblem(database->getpid(name));
        emit newSubmit();
        DS1 << static_cast<int>(StatCode::OperationSuccessful);
    }
    else
        NotAuthorizedException().raise();

    client << data;
}

void ServerThread::handleChangePublicState()
{
    if (!isAdmin)
        NotAuthorizedException().raise();

    qint64 sid;
    bool state;

    (*clientRequest) >> sid >> state;
    database->publicize(sid, state);
    sendSingleStatCode(StatCode::OperationSuccessful);
}

void ServerThread::handleScorePlan(StatCode stat)
{
    if (!isAdmin)
        NotAuthorizedException().raise();

    QByteArray data;
    QDataStream DS1(&data, QIODevice::Append);
    DS1.setVersion(QDataStream::Qt_4_8);

    if (stat == StatCode::ScorePlanQuery)
    {
        QList<QString> lst = database->scorePlanQuery();

        DS1 << static_cast<int>(StatCode::OperationSuccessful) << lst;
    }
    else if (stat == StatCode::ScorePlanDetails)
    {
        QString name;
        (*clientRequest) >> name;
        ScorePlan specs = database->scorePlanDetails(name);

        DS1 << static_cast<int>(StatCode::OperationSuccessful) << specs;
    }
    else if (stat == StatCode::ScorePlanEdit)
    {
        ScorePlan plan;
        (*clientRequest) >> plan;

        if (plan.ID() == -1)
            DS1 << static_cast<int>(database->addScorePlan(plan));
        else
            DS1 << static_cast<int>(database->editScorePlan(plan));
    }
    else if (stat == StatCode::ScorePlanRemove)
    {
        QString name, replace;
        (*clientRequest) >> name >> replace;

        qint64 id = database->getScoreID(name);
        qint64 replace_id = database->getScoreID(replace);
        if (id == -1 || replace_id == -1)
            NotAuthorizedException().raise();

        database->removeScorePlan(name, id, replace_id);
        DS1 << static_cast<int>(StatCode::OperationSuccessful);
    }
    else
        NotAuthorizedException().raise();

    client << data;
}

void ServerThread::handleUserManagement(StatCode stat)
{
    if (!isAdmin)
        NotAuthorizedException().raise();

    if (stat == StatCode::UserQuery)
    {
        DataTable DT;
        (*clientRequest) >> DT;

        QList<User> res = database->userQuery(DT);

        QByteArray BA;
        QDataStream DS(&BA, QIODevice::Append);
        DS.setVersion(QDataStream::Qt_4_8);
        DS << static_cast<int>(StatCode::OperationSuccessful);
        DS << res;

        client << BA;
    }
    else if (stat == StatCode::UserChangeAdmin)
    {
        QString uname;
        bool state;
        (*clientRequest) >> uname >> state;

        sendSingleStatCode(database->changeAdminState(uname, state));
    }
    else if (stat == StatCode::UserChangeActivation)
    {
        QString uname;
        bool state;
        (*clientRequest) >> uname >> state;

        database->changeActivationState(uname, state);
        sendSingleStatCode(StatCode::OperationSuccessful);
    }
    else if (stat == StatCode::UserDelete)
    {
        QString uname;
        (*clientRequest) >> uname;

        database->deleteUser(database->getuid(uname));
        sendSingleStatCode(StatCode::OperationSuccessful);
    }
    else if (stat == StatCode::UserChangeDescription)
    {
        QString uname;
        QString desc;
        (*clientRequest) >> uname >> desc;

        database->changeDescription(uname, desc);
        sendSingleStatCode(StatCode::OperationSuccessful);
    }
    else if (stat == StatCode::RenameUser)
    {
        QString old, cur;
        (*clientRequest) >> old >> cur;
        sendSingleStatCode(database->renameUser(old, cur));
    }
}

void ServerThread::handleViewProfile()
{
    DataTable DT;
    DT["username"] = username;
    DT["order"] = "id";
    DT["order_type"] = "asc";

    QList<User> res = database->userQuery(DT);

    if (database->config()->getConfig("score_system").toBool() == false)
        res[0] = res[0].deleteScore();

    QByteArray BA;
    QDataStream DS(&BA, QIODevice::Append);
    DS.setVersion(QDataStream::Qt_4_8);
    DS << static_cast<int>(StatCode::OperationSuccessful);
    DS << res.at(0);

    client << BA;
}

void ServerThread::handleConfig(StatCode stat)
{
    if (!isAdmin)
        NotAuthorizedException().raise();

    QByteArray BA;
    QDataStream DS(&BA, QIODevice::Append);
    DS.setVersion(QDataStream::Qt_4_8);
    DS << static_cast<int>(StatCode::OperationSuccessful);

    if (stat == StatCode::GetConfig)
        DS << database->config()->get();
    else if (stat == StatCode::SetConfig)
    {
        DataTable DT;
        (*clientRequest) >> DT;
        database->setConfigs(DT);
        database->config()->load(database->loadConfigs());
        emit newSubmit();
    }

    client << BA;
}

void ServerThread::handleDeleteSubmission()
{
    if (!isAdmin)
        NotAuthorizedException().raise();

    qint64 sid;
    (*clientRequest) >> sid;
    database->deleteSubmission(sid);
    sendSingleStatCode(StatCode::OperationSuccessful);
}

void ServerThread::handleSubmissionPurge()
{
    if (!isAdmin)
        NotAuthorizedException().raise();

    DataTable DT;
    (*clientRequest) >> DT;

    database->submissionPurge(DT);
    sendSingleStatCode(StatCode::OperationSuccessful);
}

void ServerThread::handlePurgeFiles()
{
    if (!isAdmin)
        NotAuthorizedException().raise();

    database->purgeFiles();

    sendSingleStatCode(StatCode::OperationSuccessful);
}

void ServerThread::handleScoreboard(StatCode stat)
{
    QByteArray BA;
    QDataStream DS(&BA, QIODevice::Append);
    DS.setVersion(QDataStream::Qt_4_8);

    if (stat == StatCode::ScoreboardConfig)
    {
        int page;
        (*clientRequest) >> page;
        DS << static_cast<int>(StatCode::OperationSuccessful) << database->scoreboardConfig(SCOREBOARD_CONFIG_PAGE_LENGTH * page,
                                                                                            SCOREBOARD_CONFIG_PAGE_LENGTH);
    }
    else if (stat == StatCode::ScoreboardEdit)
    {
        DataTable DT;
        (*clientRequest) >> DT;
        database->scoreboardEdit(DT);
        DS << static_cast<int>(StatCode::OperationSuccessful);
    }
    else if (stat == StatCode::ScoreboardMetaData)
        DS << static_cast<int>(StatCode::OperationSuccessful) << database->scoreboardMetaData();
    else if (stat == StatCode::Scoreboard)
    {
        qint64 id;
        int type;
        int page;

        (*clientRequest) >> id >> type >> page;
        page = qMax(0, page);

        if (!database->isScoreboardAvailable(id, type))
        {
            sendSingleStatCode(StatCode::NotAvailable);
            return;
        }
        QList<DataTable> ans = database->scoreboard(id, type, page);

        DS << static_cast<int>(StatCode::OperationSuccessful);
        DS << ans;
    }

    client << BA;
}

void ServerThread::handleGiveDescription()
{
    QString probName;
    (*clientRequest) >> probName;

    Problem prob = database->problemDetails(probName);
    if (prob.name().isEmpty())
    {
        sendSingleStatCode(StatCode::NoSuchProblem);
        return;
    }

    if (prob.descriptionFile().isEmpty())
        NotAuthorizedException().raise();

    descFile = new QFile(QString("problems/%1/%2").arg(prob.folder()).arg(prob.descriptionFile()), this);
    if (!descFile->open(QIODevice::ReadOnly))
        FileOperationException().raise();

    descFileSize = descFile->size();
    descFileWritten = 0;
    client << static_cast<int>(descFileSize + sizeof(int)) << static_cast<int>(StatCode::OperationSuccessful);

    connect(serverSocket, SIGNAL(bytesWritten(qint64)), this, SLOT(sendDescFileFragment()));

    sendDescFileFragment();

    isActive = true;
}

void ServerThread::sendDescFileFragment()
{
    if (descFileWritten == descFileSize)
    {
        disconnectSocket();
        return;
    }

    if (serverSocket->bytesToWrite() < FILE_BUFFER_SIZE)
    {
        QByteArray cur = descFile->read(FILE_BUFFER_SIZE);
        client.writeRawData(cur.constData(), cur.length());
        descFileWritten += cur.size();
    }
}

void ServerThread::handleNews(StatCode stat)
{
    QByteArray BA;
    QDataStream DS(&BA, QIODevice::Append);
    DS.setVersion(QDataStream::Qt_4_8);
    DS << static_cast<int>(StatCode::OperationSuccessful);

    if (stat == StatCode::GetNews)
        DS << database->getNews();
    else if (stat == StatCode::EditNews)
    {
        if (!isAdmin)
            NotAuthorizedException().raise();

        DataTable DT;
        (*clientRequest) >> DT;

        if (DT["id"].toLongLong() == -1)
            DS << database->addNews(DT);
        else
            database->editNews(DT);
    }
    else if (stat == StatCode::RemoveNews)
    {
        if (!isAdmin)
            NotAuthorizedException().raise();

        qint64 id;
        (*clientRequest) >> id;

        database->removeNews(id);
    }

    client << BA;
}

void ServerThread::handleContestManagement(StatCode stat)
{
    QByteArray data;
    QDataStream DS1(&data, QIODevice::Append);
    DS1.setVersion(QDataStream::Qt_4_8);

    if (stat == StatCode::ContestUserQuery)
    {
        int mode;
        QString constr;
        (*clientRequest) >> mode >> constr;

        QList<Contest> lst = database->contestUserQuery(mode, constr);
        DS1 << static_cast<int>(StatCode::OperationSuccessful) << lst;
    }
    else if (stat == StatCode::ContestEdit)
    {
        if (!isAdmin)
            NotAuthorizedException().raise();

        Contest con;
        (*clientRequest) >> con;

        if (con.ID() == -1)
            DS1 << static_cast<int>(database->addContest(con));
        else
            DS1 << static_cast<int>(database->editContest(con));
    }
    else if (stat == StatCode::ContestRemove)
    {
        if (!isAdmin)
            NotAuthorizedException().raise();

        QString name;
        (*clientRequest) >> name;
        database->removeContest(database->getContestID(name));
        DS1 << static_cast<int>(StatCode::OperationSuccessful);
    }
    else if (stat == StatCode::ContestListQuery)
    {
        if (!isAdmin)
            NotAuthorizedException().raise();

        int mode;
        QString constr;
        bool onlyreal;
        (*clientRequest) >> mode >> constr >> onlyreal;

        QList<QString> lst = database->contestListQuery(mode, constr, onlyreal);
        DS1 << static_cast<int>(StatCode::OperationSuccessful) << lst;
    }
    else if (stat == StatCode::ContestDetails)
    {
        if (!isAdmin)
            NotAuthorizedException().raise();

        QString name;
        (*clientRequest) >> name;

        qint64 cid = database->getContestID(name);
        if (cid < 0)
            NotAuthorizedException().raise();
        else
            DS1 << static_cast<int>(StatCode::OperationSuccessful) << database->contestDetails(cid);
    }
    else if (stat == StatCode::RegisterContest)
    {
        qint64 cid;
        (*clientRequest) >> cid;
        DS1 << static_cast<int>(database->registerUserInContest(cid, uid));
    }
    else if (stat == StatCode::CurrentContests)
    {
        DS1 << static_cast<int>(StatCode::OperationSuccessful);
        DS1 << database->currentContests(uid);
    }
    else
        NotAuthorizedException().raise();

    client << data;
}

void ServerThread::handleUserRecord()
{
    QString user;
    int page;

    (*clientRequest) >> user >> page;

    if (!isAdmin && user != username)
        NotAuthorizedException().raise();

    QByteArray BA;
    QDataStream DS(&BA, QIODevice::Append);
    DS.setVersion(QDataStream::Qt_4_8);
    DS << static_cast<int>(StatCode::OperationSuccessful) << database->userRecord(database->getuid(user),
                                                                                  USER_RECORD_PAGE_LENGTH * page, USER_RECORD_PAGE_LENGTH);

    client << BA;
}

void ServerThread::disconnectSocket()
{
    serverSocket->disconnectFromHost();
}
