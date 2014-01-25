#include "mainwindow.h"

#include <QApplication>

MainWindow *g_window;

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	g_window = new MainWindow();
	g_window->show();

	return a.exec();
}
