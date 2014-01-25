#include "capturethread.h"
#include "mainwindow.h"

void CaptureThread::startCapture()
{
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	pcap_t *fp;
	struct timeval st_ts;
	struct bpf_program fcode;

	if (!(fp = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf))) {
		g_window->addError(tr("Unable to open adapter: %1\n").arg(d->description));
		goto out;
	}

	if (pcap_compile(fp, &fcode, "ip and tcp", 1, 0xffffff) < 0) {
		g_window->addError("Could not compile the packet filter!\n");
		goto out;
	}

	if (pcap_setfilter(fp, &fcode) < 0) {
		g_window->addError("Unable to set the filter\n");
		goto out;
	}

	if (pcap_setmode(fp, MODE_STAT) < 0) {
		g_window->addError("Error setting mode\n");
		goto out;
	}

	pcap_loop(fp, 0, &CaptureThread::dispatch, (PUCHAR)&st_ts);
out:
	pcap_close(fp);
	emit finished();
}

void CaptureThread::dispatch(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct timeval *old_ts = (struct timeval *)state;
	u_int delay;
	unsigned long long pps;
	double kBps;
	static double bandwidth = 0.0f;

	delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
	kBps = (((*(qlonglong*)(pkt_data + 8)) * 1000000) / (delay)) * 0.001;
	pps  = (((*(qlonglong*)(pkt_data))     * 1000000) / (delay));
	bandwidth += kBps * 0.001;
	g_window->updateData(kBps, pps, bandwidth);

	old_ts->tv_sec = header->ts.tv_sec;
	old_ts->tv_usec = header->ts.tv_usec;
}
