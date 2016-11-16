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
void process_packet(u_char *arg, const struct pcap_pkthdr *stamp_len, const u_char *packet)
{

	struct ether_header *ether_sp = NULL;
	struct iphdr *ip_sp = NULL;
	struct tcphdr *tcp_sp = NULL;
	unsigned char *beyond_tcp = NULL; 
	uint8_t ether_len = 14;
	uint8_t ip_len    = 0;
	uint8_t tcp_len   = 0;
	uint8_t beyond_tcp_len = 0;
	uint16_t sport;  /* tcp source port*/
	uint16_t dport;  /* tcp destination port*/
	
	uint8_t *counter = arg;
/****************************** ether and ip layer *************************************/
	ether_sp = (struct ether_header *)packet;
	ip_sp	 = (struct iphdr *)(ether_sp + 1);
	if (ip_sp->protocol != IPPROTO_TCP){  /* only process tcp */
		return;	
	}
	ip_len = ip_sp->ihl * 4;

/****************************** tcp layer *************************************/
	tcp_sp = (struct tcphdr *)((uint8_t *)ip_sp + ip_len);
	sport = ntohs(tcp_sp->source);
	dport = ntohs(tcp_sp->dest);
	printf("%d,%d\n",sport,dport);
	if (sport != IPPORT_HTTPS && dport != IPPORT_HTTPS){ /* only process https */
		return;
	}
	tcp_len    = tcp_sp->doff * 4 ;

/****************************** beyond_tcp layer *************************************/
	beyond_tcp = (unsigned char *)((uint8_t *)tcp_sp + tcp_len);
	beyond_tcp_len = stamp_len->len - ether_len - ip_len - tcp_len;

/****************************** print raw data *************************************/
	printf("packet count :%d\n",++(*counter));
	printf("captured packet size: %d\n",stamp_len->caplen);
	printf("tatol    packet size: %d\n",stamp_len->len);
	printf("display ether: \n");
	print_raw_data((const uint8_t *)ether_sp,ether_len);
	printf("display ip: \n");
	print_raw_data((const uint8_t *)ip_sp,ip_len);
	printf("display tcp: \n");
	print_raw_data((const uint8_t *)tcp_sp,tcp_len);
	printf("display beyond_tcp: \n");
	print_raw_data((const uint8_t *)beyond_tcp,beyond_tcp_len);
	
	return;
}
int main(void)
{
	int  ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device  = NULL;
	uint8_t count  = 0;
	pcap_t *descr = NULL;
	struct bpf_program program;
	bpf_u_int32 mask = 0;

	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	device = pcap_lookupdev(errbuf);
	if(device != NULL) {
		printf("success: device: %s\n", device);
	} else {
		printf("pcap_lookupdev error: %s\n", errbuf);
		return -1;
	}
	descr = pcap_open_live(device,MAXBYTES2CAPTURE,1,512,errbuf);
	if(descr == NULL){
		printf("pcap_open_live error:%s\n",errbuf);
		return -1;
	}
	//printf("%d\n",pcap_datalink(descr));/*display datalink type*/
	ret = pcap_compile(descr,&program,"! port 22 and ! arp and host 192.168.42.132",1,mask);
	if (ret != 0){
		pcap_perror(descr,"pcap_compile");
		return -1;
	}
	ret = pcap_setfilter(descr,&program);
	if (ret != 0){
		pcap_perror(descr,"pcap_setfilter");
		return -1;
	}
	pcap_loop(descr,-1,process_packet,&count);

	return 0;
}
