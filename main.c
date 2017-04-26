/*
 * Copyright (C) 2016 francis_hao <francis_hao@126.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <inttypes.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define __FAVOR_BSD
#include <netinet/tcp.h>
#define MAXBYTES2CAPTURE	2048
#define IPPORT_HTTPS		443
void print_raw_data(const uint8_t *start,uint16_t size)
{
	uint16_t i;
	for (i=0;i<size;i++){
		printf("%02x ",start[i]);
		if (((i+1)%8 == 0) || (i==size-1)){
			printf(" ");	
		}
		if (((i+1)%16 == 0) || (i==size-1)){
			printf("\n");	
		}
	}
	
}
pcap_t* open_pcap(const char *source)
{
	pcap_t* pcap_fd = NULL;
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE]={0};
	pcap_fd = pcap_create(source, errbuf);
	if (NULL == pcap_fd){
		printf("pcap_create failed : %s\n",errbuf);
		return NULL;
	}
	ret = pcap_activate(pcap_fd);
	if (ret != 0){
		pcap_perror(pcap_fd, "pcap_activate error: ");	
		pcap_close(pcap_fd);
		return NULL;
	}
	return pcap_fd;

}
void mac_to_hex(uint8_t* hex, const char* mac)
{
	sscanf(mac, "%x:%x:%x:%x:%x:%x", &hex[0],&hex[1],&hex[2],&hex[3],&hex[4],&hex[5]);
}

int send_packet(void)
{
	uint16_t buff_len;
	uint8_t  buff[100]={0};
	struct ether_header *ether_sp = NULL;
	struct iphdr *ip_sp = NULL;
	struct tcphdr *tcp_sp = NULL;
	uint8_t *vlan_sp = NULL; 
	uint8_t *beyond_tcp = NULL; 
	char tmp[]={2,4,5,0xb4,4,2,8,0x0a,1,0x49,0x77,0x9a,0,0,0,0,1,3,3,7};	
	pcap_t *eth_out=NULL;
/****************************** ether layer *************************************/
	ether_sp = (struct ether_header*)buff;
	mac_to_hex(ether_sp->ether_dhost, "00:50:56:eb:b0:73");
	mac_to_hex(ether_sp->ether_shost, "00:0c:29:bc:0c:f5");
	//ether_sp->ether_type = htons(ETHERTYPE_IP);
	ether_sp->ether_type = htons(ETHERTYPE_VLAN);

/****************************** vlan layer *************************************/
	vlan_sp = (uint8_t*)(ether_sp + 1);
	vlan_sp[0]=0;
	vlan_sp[1]=2;
	vlan_sp[2]=8;
	vlan_sp[3]=0;
 
/****************************** ip layer *************************************/
	ip_sp = (struct iphdr*)(vlan_sp+4);
	ip_sp->version = 4;
	ip_sp->ihl = 5;//length 5*4 =20 byte
	ip_sp->tos = 0;
	ip_sp->tot_len = htons(60); //reassign below
	ip_sp->id = htons(0x1a6c);//maybe wrong
	ip_sp->ttl= 64;
	ip_sp->protocol = IPPROTO_TCP;
	ip_sp->frag_off = htons(0x4000);
	ip_sp->check = htons(0x383d);
	ip_sp->saddr = inet_addr("192.168.79.135");
	ip_sp->daddr = inet_addr("223.6.248.220");

/****************************** tcp layer *************************************/
	tcp_sp = (struct tcphdr*)(ip_sp + 1);
	tcp_sp->th_sport = htons(50604);
	tcp_sp->th_dport = htons(80);
	tcp_sp->th_seq = htonl(0xba3f6df6);
	tcp_sp->th_ack = htonl(0);
	tcp_sp->th_off = 0x0a;
	tcp_sp->th_flags = TH_SYN;
	tcp_sp->th_win = htons(29200);
	tcp_sp->th_sum = htons(0xe841);


/****************************** tcp2 layer *************************************/
	beyond_tcp = (uint8_t*)(tcp_sp+1);
	memcpy(beyond_tcp, tmp, sizeof (tmp));
	buff_len = (char*)beyond_tcp - (char*)ether_sp + sizeof (tmp);
	print_raw_data(buff,buff_len);
	eth_out = open_pcap("ens33");
	if (eth_out == NULL){
		return -1;
	}

	pcap_inject(eth_out, buff, buff_len);
	return 0;
}


int main(void)
{
	send_packet();
	return 0;
}
