#ifndef CAPTURE_H
#define CAPTURE_H

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define WIN32
#endif

#define HAVE_REMOTE
#include <pcap.h>
#include <Packet32.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#include <stdint.h>
#include <stdbool.h>

struct capture {
	pcap_t *fp;
	double cur_bw;
	double peak;

	bool has_err;
	char *errmsg;

	void *priv;
	void (*capture_fn) (struct capture *, double kBps, uint32_t pps);
};

struct capture *capture_new(void);
void capture_free(struct capture *c);

bool capture_set_iface(struct capture *c, pcap_if_t *iface);
void capture_start(struct capture *c);
void capture_stop(struct capture *c);

#endif
