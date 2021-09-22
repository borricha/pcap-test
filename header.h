#pragma once
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

struct ethernet_hdr
{
    uint8_t   ether_dst_mac[6]; //Ethernet 헤더의 des mac, 6byte
    uint8_t   ether_src_mac[6]; //Ethernet 헤더의 src mac, 6byte
    uint16_t   ether_type;    //다음 레이어에 어떤 프로토콜이 오는지, 2byte
};



struct IPv4_hdr
{
    uint8_t version:4;
    uint8_t IHL:4; //IP 헤더의 크기/4, 4bit
    uint8_t Ip_tos;
    uint16_t Ip_total_length; //엔디언 주의
    uint8_t dummy[4];
    uint8_t TTL;
    uint8_t Protocol; // uint8_t  Protocol; //다음 레이어에 어떤 프로토콜이 오는지, 1byte
    uint8_t dummy2[2];
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
    uint8_t data[8];
};