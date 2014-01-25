#include "mainwindow.h"
#include "capturethread.h"

#include "ui_mainwindow.h"

#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow)
{
	ui->setupUi(this);
	connect(ui->startButton, SIGNAL(clicked()), this, SLOT(startCapture()));

	pcap_if_t *d;
	int counter;
	char errbuf[PCAP_ERRBUF_SIZE + 1];

	if (pcap_findalldevs(&m_devs, errbuf) == -1) {
		addError("Cannot find any devices connected!");
		return;
	}

	for (counter = 0, d = m_devs; d; d = d->next) {
		QListWidgetItem* devName = new QListWidgetItem();
		devName->setText("#" + QString::number(counter + 1) + " " + QString::fromLatin1(d->description));

		ui->deviceList->addItem(devName);
	}
}

MainWindow::~MainWindow()
{
	delete ui;
}

void MainWindow::startCapture()
{
	int selected = ui->deviceIndex->text().toInt();
	if (selected < 1) {
		QMessageBox::information(this, tr("Error"), tr("Incorrect device index!"));
		return;
	}

	ui->startButton->setEnabled(false);
	// figure out the interface..
	int counter;
	pcap_if_t *iface;

	for (counter = 1, iface = m_devs; iface && counter != selected; iface = iface->next);

	CaptureThread *c = new CaptureThread();
	c->setIface(iface);
	c->moveToThread(&m_thread);
	connect(c, SIGNAL(finished()), &m_thread, SLOT(quit()));
	connect(c, SIGNAL(finished()), c, SLOT(deleteLater()));
	connect(&m_thread, SIGNAL(finished()), &m_thread, SLOT(deleteLater()));
	connect(&m_thread, SIGNAL(started()), c, SLOT(startCapture()));
	m_thread.start();
}

void MainWindow::updateData(double kBps, quint64 pps, double bandwidth)
{
	// Current usage
	ui->ppsLabel->setText(QString::number(pps) + " PPS");
	ui->currentKBps->setText(QString::number(kBps) + " KB");
	ui->currentMBps->setText(QString::number(kBps * 0.0009765625) + " MB");

	// Total usage
	ui->totalmBps->setText(QString::number(bandwidth) + " MB");
	if ((bandwidth /= 1024) >= 1)
		ui->totalgBps->setText(QString::number(bandwidth) + " GB");
	if ((bandwidth *= 1048576) >= 1)
		ui->totalkBps->setText(QString::number(bandwidth) + " KB");
}

void MainWindow::addError(const QString &error)
{
	ui->errorText->appendPlainText(error);
}
