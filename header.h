#pragma once
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

int global_ip_length;
int global_tcp_length;
int global_total_length;

struct ethernet_hdr
{
    uint8_t   ether_dst_mac[6]; //Ethernet 헤더의 des mac, 6byte
    uint8_t   ether_src_mac[6]; //Ethernet 헤더의 src mac, 6byte
    uint8_t   ether_type[2];    //다음 레이어에 어떤 프로토콜이 오는지, 2byte
};


struct IPv4_hdr
{
    uint8_t version:4;
    uint8_t IHL:4; //IP 헤더의 크기/4, 4bit
    uint8_t Ip_tos;
    uint16_t Ip_total_length;
    ////엔디언 주의


    // uint8_t  Protocol; //다음 레이어에 어떤 프로토콜이 오는지, 1byte
    uint8_t dummy[8];
    uint8_t  IP_src_mac[4]; //IP 헤더의 src address, 4byte
    uint8_t  IP_dst_mac[4]; //IP 헤더의 dst address, 4byte
};

struct TCP_hdr
{
    
    uint16_t tcp_sport;      //
    uint16_t tcp_dport;
    uint8_t dummy[8];
    uint8_t dummy2:4;
    uint8_t data_offset:4;      //
};

struct Data
{
    
    uint8_t data[8];      //
         //
};



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
    //printf("ihl %d", ip->IHL);
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
    //printf("아 짜증나 %x  %d \n", tcp->data_offset, tcp->data_offset);
    global_tcp_length = (tcp->data_offset)*4;
    return tcp->data_offset;

}

void print_Data(const u_char* packet)
{
    //printf("전역변수들 출력: ip: %d tcp:%d total:%d \n\n", global_ip_length, global_tcp_length, global_total_length);
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