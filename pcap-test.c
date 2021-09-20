#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "header.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
		print_ethernet(packet);
		uint8_t tcp_offset = print_IP(packet + 14);
		//printf("계산 전 %d\n",tcp_offset );
		tcp_offset *= 4;
		tcp_offset += 14;
		//printf("계산 후 %d",tcp_offset );

		uint8_t data_offset = print_TCP(packet + tcp_offset);
		//printf("%d\n", data_offset);
		
		data_offset *= 4;
		//printf("%d\n", data_offset);
		
		data_offset += tcp_offset;
		//printf("%d\n", data_offset);
		const char* data;
		data = packet + data_offset;
		print_Data(data);
		printf("%.8s \n", data);
		printf("\n");


	}

	pcap_close(pcap);
}