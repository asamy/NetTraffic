#include "capture.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

static void handle_traffic(u_char *p, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct capture *c = (struct capture *)p;
	struct timeval *old_ts = c->priv;

	u_int delay;
	uint32_t pps;
	double kBps;

	delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
	kBps = (((*(uint64_t*)(pkt_data + 8)) * 1000000) / (delay)) * 0.001;
	pps  = (((*(uint32_t*)(pkt_data))     * 1000000) / (delay));

	if (c->peek <= kBps)
		c->peek = kBps;

	c->cur_bw += kBps;
	c->capture_fn(c, kBps, pps);

	old_ts->tv_sec = header->ts.tv_sec;
	old_ts->tv_usec = header->ts.tv_usec;
}

static int vasprintf(char **strp, const char *fmt, va_list ap)
{
	int len;
	va_list ap_copy;

	va_copy(ap_copy, ap);
	len = vsnprintf(NULL, 0, fmt, ap_copy);
	va_end(ap_copy);

	if (len < 0)
		return -1;

	*strp = malloc(len+1);
	if (!*strp)
		return -1;

	return vsprintf(*strp, fmt, ap);
}

static void set_error(struct capture *c, const char *fmt, ...)
{
	va_list ap;
	char *ptr;

	va_start(ap, fmt);
	if (vasprintf(&ptr, fmt, ap) < 0)
		ptr = NULL;
	va_end(ap);

	if (!ptr) {
		fprintf(stderr, "Allocation failed, terminating now...\n");
		abort();
	}

	if (c->errmsg)
		free(c->errmsg);

	c->has_err = true;
	c->errmsg = ptr;
}

struct capture *capture_new(void)
{
	struct capture *ret;

	ret = malloc(sizeof(*ret));
	if (!ret)
		return NULL;

	ret->fp = NULL;
	ret->cur_bw = 0.0f;
	ret->priv = NULL;
	ret->capture_fn = NULL;

	return ret;
}

void capture_free(struct capture *c)
{
	if (!c)
		return;

	pcap_breakloop(c->fp);
	pcap_close(c->fp);

	if (c->errmsg)
		free(c->errmsg);

	free(c);
}

bool capture_set_iface(struct capture *c, pcap_if_t *iface)
{
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	struct bpf_program fcode;
	pcap_t *fp;

	if (c->fp)
		capture_stop(c);

	if (!(fp = pcap_open(iface->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf))) {
		set_error(c, errbuf);
		return false;
	}

	if (pcap_compile(fp, &fcode, "ip and tcp", 1, 0xffffff) < 0) {
		set_error(c, "unable to compile packet filter");
		return false;
	}

	if (pcap_setfilter(fp, &fcode) < 0) {
		set_error(c, "unable to set the filter");
		return false;
	}

	if (pcap_setmode(fp, MODE_STAT) < 0) {
		set_error(c, "unable to set the mode");
		return false;
	}

	c->fp = fp;
	return true;
}

void capture_start(struct capture *c)
{
	struct timeval st_ts;
	if (c) {
		c->priv = &st_ts;
		pcap_loop(c->fp, 0, handle_traffic, (PUCHAR)c);
	}
}

void capture_stop(struct capture *c)
{
	if (c && c->fp) {
		pcap_breakloop(c->fp);
		pcap_close(c->fp);
	}
}
