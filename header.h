#pragma once
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

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

    ////엔디언 주의


    // uint8_t  Protocol; //다음 레이어에 어떤 프로토콜이 오는지, 1byte
    uint8_t dummy[11];
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
    return(ip->version);
}

uint8_t print_TCP(const u_char* packet)
{
    struct TCP_hdr* tcp;
    tcp = (struct TCP_hdr *)packet;
    printf("TCP Source port: %d \n", ntohs(tcp->tcp_sport));
    printf("TCP Destination port: %d \n", ntohs(tcp->tcp_dport));
    //printf("아 짜증나 %x  %d \n", tcp->data_offset, tcp->data_offset);
    return tcp->data_offset;
}

void print_Data(const u_char* packet)
{
    struct Data* dt;
    dt = (struct Data *)packet;
    printf("%x %x %x %x %x %x %x %x\n ", dt->data[0], dt->data[1], dt->data[2], dt->data[3], dt->data[4], dt->data[5], dt->data[6], dt->data[7] );
}