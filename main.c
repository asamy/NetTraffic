#include "capture.h"

#include <signal.h>
#include <stdio.h>

static struct capture *c;

static void print_data(struct capture *c, double kBps, uint32_t pps)
{
	COORD coord;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &consoleInfo);
	coord.X = consoleInfo.dwCursorPosition.X;
	coord.Y = consoleInfo.dwCursorPosition.Y;

	printf("\t\t\t\tCurrent usage:\n");
	printf("\t\t\tKBps: %.2f Mbps: %.2f PPS: %d\n\n", kBps, kBps * .0078125, pps);

	printf("\t\t\t\tTotal usage:\n");
	printf("\t\t\tKB: %.2f MB: %.2f GB: %.2f\n", c->cur_bw, c->cur_bw * 0.001, (c->cur_bw * 0.001) / 1024);

	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
}

static void handle_sig(int sig)
{
	FILE *fp = fopen("last_bandwidth.txt", "w");

	fprintf(fp, "%.2f\n", c->cur_bw);
	fclose(fp);

	fprintf(stderr, "Caught signal, quitting.\n");
	capture_free(c);
	exit(EXIT_FAILURE);
}

int main(void)
{
	pcap_if_t *iface, *devs;
	int j, i;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	FILE *fp;

	printf("Copyright (C) Ahmed Samy 2014 <f.fallen45@gmail.com>\n\n");
	printf("\t\t\tNetwork Traffic Analyzer\n");

	if (pcap_findalldevs(&devs, errbuf) == -1 || !devs) {
		fprintf(stderr, "No network devices are currently connected\n");
		return 1;
	}

	printf("Enabled Network Devices:\n");
	for (i = 1, iface = devs; iface; iface = iface->next)
		printf("%d - %s\n", i++, iface->description);

prompt:
	printf("Device Index> ");
	scanf("%d", &j);

	/* Find the interface pointer.  */
	for (i = 1, iface = devs; iface && i != j; iface = iface->next, ++i);
	if (!iface) {
		fprintf(stderr, "Invalid device index %d, please try again.", j);
		goto prompt;
	}

	c = capture_new();
	c->capture_fn = print_data;

	if (!capture_set_iface(c, iface)) {
		fprintf(stderr, "Internal error: could not set the interface to capture!\n");
		pcap_freealldevs(devs);
		return 1;
	}
	pcap_freealldevs(devs);

	fp = fopen("last_bandwidth.txt", "r");
	if (fp) {
		fscanf(fp, "%lf", &c->cur_bw);
		fclose(fp);
	}

	signal(SIGINT, handle_sig);
	signal(SIGABRT, handle_sig);
	signal(SIGTERM, handle_sig);

	capture_start(c);
	return 0;
}
