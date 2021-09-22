#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "header.h"

int check_TCP(const u_char* packet);
int check_IP(const u_char* packet);
void print_ethernet(const u_char* packet);
uint8_t print_IP(const u_char* packet);
uint8_t print_TCP(const u_char* packet);
void print_Data(const u_char* packet);

int global_ip_length;
int global_tcp_length;
int global_total_length;


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

		int flag = 0;
		flag = check_IP(packet);
		if (flag == 1) continue;
		flag = check_TCP(packet + 14);
		if (flag == 1) continue;

		print_ethernet(packet);
		uint8_t tcp_offset = print_IP(packet + 14);
		tcp_offset *= 4;
		tcp_offset += 14;
		uint8_t data_offset = print_TCP(packet + tcp_offset);
		data_offset *= 4;
		data_offset += tcp_offset;
		const char* data;
		data = packet + data_offset;
		print_Data(data);
	}

	pcap_close(pcap);
}


int check_IP(const u_char* packet)
{
    struct ethernet_hdr* eh;
    eh = (struct ethernet_hdr *)packet;
    if((ntohs(eh->ether_type)) != 0x0800)
	{
		printf("IP가 아님\n\n");
		return 1;
	}
	else
	{
		return 0;
	}
}



int check_TCP(const u_char* packet)
{
    struct IPv4_hdr* ip2;
    ip2 = (struct IPv4_hdr *)packet;
     
    if((ip2->Protocol) != 0x06)
    {
		printf("TCP가 아님\n\n");
        return 1;
    }
    else
    {
        return 0;
    }
}



void print_ethernet(const u_char* packet)
{
    struct ethernet_hdr* eh;
    eh = (struct ethernet_hdr *)packet;
    printf("Ethernet Destination %x: %x: %x: %x: %x: %x \n",eh->ether_dst_mac[0],eh -> ether_dst_mac[1],eh -> ether_dst_mac[2],eh -> ether_dst_mac[3],eh -> ether_dst_mac[4],eh -> ether_dst_mac[5]);
    printf("Ethernet Source  %x: %x: %x: %x: %x: %x \n",eh->ether_src_mac[0],eh -> ether_src_mac[1],eh -> ether_src_mac[2],eh -> ether_src_mac[3],eh -> ether_src_mac[4],eh -> ether_src_mac[5]);

}

uint8_t print_IP(const u_char* packet)
{
    struct IPv4_hdr* ip;
    ip = (struct IPv4_hdr *)packet;
    printf("IP Source  %d.%d.%d.%d \n",ip->IP_src_mac[0],ip -> IP_src_mac[1],ip -> IP_src_mac[2],ip -> IP_src_mac[3]);
    printf("IP Destination  %d.%d.%d.%d \n",ip->IP_dst_mac[0],ip -> IP_dst_mac[1],ip -> IP_dst_mac[2],ip -> IP_dst_mac[3]);
    global_ip_length = (ip->version)*4;
    global_total_length = ntohs(ip->Ip_total_length);
    return(ip->version); //iplength 출력
}

uint8_t print_TCP(const u_char* packet)
{
    struct TCP_hdr* tcp;
    tcp = (struct TCP_hdr *)packet;
    printf("TCP Source port: %d \n", ntohs(tcp->tcp_sport));
    printf("TCP Destination port: %d \n", ntohs(tcp->tcp_dport));
    global_tcp_length = (tcp->data_offset)*4;
    return tcp->data_offset;

}

void print_Data(const u_char* packet)
{
	// 길이 정보들을 토대로 데이터 유무 판단
    if(global_total_length > (global_ip_length + global_tcp_length) )
    {
        struct Data* dt;
        dt = (struct Data *)packet;
        printf("%x %x %x %x %x %x %x %x\n\n", dt->data[0], dt->data[1], dt->data[2], dt->data[3], dt->data[4], dt->data[5], dt->data[6], dt->data[7] );
    }
    
	else
    {
        printf("Data의 크기가 0\n\n");
        return;
    }

}