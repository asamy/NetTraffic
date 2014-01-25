#-------------------------------------------------
#
# Project created by QtCreator 2014-01-24T23:59:24
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = NetworkTraffic
TEMPLATE = app


SOURCES += main.cpp\
		mainwindow.cpp \
		capturethread.cpp

HEADERS  += mainwindow.h capturethread.h

FORMS    += mainwindow.ui
LIBS 	 += -lpacket
win32 {
 LIBS += -lwpcap
} else {
 LIBS == -lpcap
}

CONFIG +=
