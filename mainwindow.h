#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define WIN32
#endif

#define HAVE_REMOTE
#include <pcap.h>
#include <Packet32.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	explicit MainWindow(QWidget *parent = 0);
	~MainWindow();

	void updateData(double,quint64,double);
	void addError(const QString& error);

protected Q_SLOTS:
	void startCapture();

private:
	Ui::MainWindow *ui;
	QThread m_thread;

	pcap_if_t *m_devs;
};

extern MainWindow *g_window;

#endif // MAINWINDOW_H
