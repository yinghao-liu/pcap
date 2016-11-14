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
#define MAXBYTES2CAPTURE	2048
void process_packet(u_char *arg, const struct pcap_pkthdr *stamp_len, const u_char *packet)
{
	uint8_t *counter = arg;
	uint16_t i;
	printf("packet count :%d\n",++(*counter));
	printf("captured packet size: %d\n",stamp_len->caplen);
	printf("tatol    packet size: %d\n",stamp_len->len);
	printf("display:\n");
	for (i=0;i<stamp_len->len;i++){
		printf("%02x ",packet[i]);
		if(i==0){
			continue;
		}
		if (((i+1)%8 == 0) || (i==stamp_len->len-1)){
			printf(" ");	
		}
		if (((i+1)%16 == 0) || (i==stamp_len->len-1)){
			printf("\n");	
		}
	}
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
	//printf("%d\n",pcap_datalink(descr));
	ret = pcap_compile(descr,&program,"! port 22 and ! arp and ! host 192.168.30.58 and host 192.168.42.132",1,mask);
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
