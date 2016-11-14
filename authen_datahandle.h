#ifndef AUTHEN_DATAHANDLE_H
#define AUTHEN_DATAHANDLE_H

#include <inttypes.h>
#include <endian.h>
#define HARDTYPE_ETHER    0x0001 /* 以太网 */
//	网络协议类型定义
#define ETHER_LEN	6	     /* Ethernet MAC addr Length*/
#define	ETHERTYPE_ARP      	0x0806	/* Address resolution*/
#define	ETHERTYPE_REVARP  	0x8035 	/* Reverse ARP*/
#define	ETHERTYPE_IP      	0x0800
#define	ETHERTYPE_PPPOED	0x8863
#define	ETHERTYPE_PPPOE	    0x8864
#define ETHERTYPE_VLAN      0x8100
#define	AUTHEN_IPPROTO_TCP	6
#define	AUTHEN_IPPROTO_UDP	17
#define PROTO_UNDEF	-1
#define ARP_REQUEST     0x0001 /* arp请求包 */
#define ARP_REPLY       0x0002 /* arp回应包 */

#define MAX_PORT_NUM    65535

#define NETDATA_UPLOAD     1
#define NETDATA_DOWNLOAD   2
#define NETDATA_UNKNOWN    3


/* 关键字获取标志, 用于特殊情况处理 */
#define TAG_GETKEY_COMMON       0x0
#define TAG_GETKEY_REVERSEDATA  0x1 /* 用于确认包处理,处理反向数据时需要注意IP/MAC的取值 */
#define TAG_GETKEY_WEBREQUEST   0x2
#define TAG_GETKEY_PPPOELOGOUT  0x4
#define TAG_GETKEY_ADDUSERFLAG  0x8

/* 以太网头 */
typedef struct ether_head_tag
{
        uint8_t  ether_dsthost[ETHER_LEN];   /* 目的MAC */
        uint8_t  ether_srchost[ETHER_LEN];   /* 源MAC */
        uint16_t ether_type;				/* 以太网协议类型 */
} ether_head_t;

typedef struct ether_arp_tag
{
    uint16_t arp_hrd;
    uint16_t arp_pro;
    uint8_t arp_hln;
    uint8_t arp_pln;
    uint16_t arp_op;
    uint8_t arp_sha[ETHER_LEN];
    uint8_t arp_spa[4];
    uint8_t arp_tha[ETHER_LEN];
    uint8_t arp_tpa[4];
    uint8_t padding[18];
} arp_data_t;

typedef struct arppacket
{
    ether_head_t etherhead;
    arp_data_t arpdata;
} arp_packet_t;

/* pppoe 头 */
typedef struct pppoe_head_tag
{
        uint8_t  pppoe_ver:4;
        uint8_t  pppoe_type:4;
        uint8_t  pppoe_code;
        uint16_t pppoe_sessionid;
        uint16_t pppoe_packetlen;
        uint16_t pppoe_protocol; /* 非规范 */
}pppoe_head_t;

/* pppoe 数据头  */
typedef struct pppoe_data_tag
{
        uint8_t  pppoe_code;
        uint8_t  pppoe_identifier;
        uint16_t pppoe_datalen;
}pppoe_data_t;

/* VLAN头 */
typedef struct vlan_head_tag
{
    	uint16_t vlan_id;
    	uint16_t vlan_type;
}vlan_head_t;

//! 定义IP头ppp
typedef  uint32_t pf_in_addr ;

typedef struct ip_head_tag
{
#ifdef WORDS_BIGENDIAN
        uint8_t ip_v:4, ip_hl:4;
#else
        uint8_t ip_hl:4, ip_v:4;
#endif
        uint8_t ip_tos;
        uint16_t ip_len;
        uint16_t ip_id;
        uint16_t ip_off;
        uint8_t ip_ttl;
        uint8_t ip_p;
        uint16_t ip_sum;
        pf_in_addr ip_src;
        pf_in_addr ip_dst;
} ip_head_t;


// tcp包头
typedef struct tcp_head_tag
{
        uint16_t th_sport;
        uint16_t th_dport;
        uint32_t th_seq;
        uint32_t th_ack;
#ifdef WORDS_BIGENDIAN
        uint8_t th_off:4, th_x2:4;
#else
        uint8_t th_x2:4, th_off:4;
#endif
        uint8_t th_flags;
        uint16_t th_win;
        uint16_t th_sum;
        uint16_t th_urp;
} tcp_head_t;


// udp包头
typedef struct
{
        uint16_t uh_sport;           /* source port */
        uint16_t uh_dport;           /* destination port */
        uint16_t uh_ulen;            /* udp length */
        uint16_t uh_sum;             /* udp checksum */
} udp_head_t;

#pragma pack(push)
#pragma pack(1)
typedef struct tag_dns_head
{
    unsigned short trans_id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answer_rrs;
    unsigned short authority_rrs;
    unsigned short additional_rrs;
    unsigned char queries[0];
}dns_name_t;

typedef struct tag_dns_data
{
    unsigned short ans_name;
    unsigned short ans_type;
    unsigned short ans_class;
    unsigned int   ans_time;
    unsigned short ans_data_len;
    unsigned char  ans_data[0];
}dns_answers_t;

typedef struct dns_layer
{
    ether_head_t *pstEth;
    ip_head_t *pstIp;
    udp_head_t *pstUdp;
    dns_name_t *pstDns;
    dns_answers_t *pstDnsAsw;
}dns_layer_t;
#pragma pack(pop)

typedef struct tag_DoublePointer
{
    void * pvFirstPointer;
    void * pvSecondPointer;
}AUTHEN_DPOINTER_S;

void *authen_netDataHandle( void *cap_fp);
int get_gateway_mac(unsigned char *eth, unsigned char *gateway_mac);
int get_interface_addr(unsigned char *mac_addr, unsigned int *ip_addr, unsigned char *dev);

#endif /* AUTHEN_DATAHANDLE_H */

