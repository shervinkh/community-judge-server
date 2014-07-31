#-------------------------------------------------
#
# Project created by QtCreator 2013-07-31T22:10:17
#
#-------------------------------------------------

QT       += core network sql
QT       -= gui

TARGET = CommunityJudgeServer
TEMPLATE = app

CONFIG   += console
CONFIG   -= app_bundle

QMAKE_CXXFLAGS += -std=c++0x


SOURCES += main.cpp \
    runner.cpp \
    judger.cpp \
    serverthread.cpp \
    tcpserver.cpp \
    signalhandler.cpp \
    database.cpp \
    config.cpp

HEADERS  += \
    runner.h \
    judger.h \
    serverthread.h \
    tcpserver.h \
    signalhandler.h \
    database.h \
    submissionresult.h \
    score.h \
    problem.h \
    user.h \
    config.h \
    contest.h
