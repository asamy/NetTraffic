#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include "mainwindow.h"

class CaptureThread : public QObject
{
	Q_OBJECT
	QThread m_worker;
	pcap_if_t *d;

public:
	void setIface(pcap_if_t *iface) { d = iface; }

public slots:
	void startCapture();

private:
	static void dispatch(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data);

signals:
	void finished();
};

#endif
