#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "checksum.h"

#ifndef TRACE_
#define TRACE_

#define ETHER_HDR_SIZE 14 //bytes
#define END_OF_PCAP_FILE -2

#define MAC_ADDR_LEN 6 //In bytes
#define ETHER_TYPE_LEN 2 //In bytes
#define TOS_LEN 6
#define ECN_LEN 2
#define TOTAL_LEN_LEN 16
#define ARP_HDR_IPV4_SIZE 224 //in bytes

#define IDENTIFCATION_LEN 16
#define FLAGS_LEN 3


#define IP_ADDR_SIZ 4 //in bytes



//IP HDR
#define IP_HDR_SIZE 20 //in bytes
#define TOS_OFFSET 1 //bytes
#define TOTAL_LEN_OFFSET 2 //bytes
#define TTL_OFFSET 8 //bytes
#define PROTOCOL_OFFSET 9 //bytes
#define CHKSUM_OFFSET 10 //bytes
#define SRC_IP_OFFSET 12 //bytes
#define DST_IP_OFFSET 16 //bytes
#define DATA_OFFSET 20 //bytes
#define IP_CHKSUM_CORRECT 0

//TCP HDR
#define TCP_SRC_PORT_OFFSET 0
#define TCP_DST_PORT_OFFSET 2
#define TCP_SEQ_NUM_OFFSET 4
#define TCP_ACK_NUM_OFFSET 8
#define TCP_WINDOW_SIZE_OFFSET 14
#define TCP_CHKSUM_OFFSET 16
#define TCP_FLAGS_OFFSET 13
#define TCP_ECN_OFFSET 12
#define TCP_ECN_MASK (0x01C0)

//TCP FLAGS MASKS
#define SYN_FLAG_MASK (0x02)
#define RST_FLAG_MASK (0x04)
#define FIN_FLAG_MASK (0x01)


//TCP PSEUDO HDR
#define TCP_PSEUDO_HDR_SIZE 12
#define TCP_DATAGRAM_OFFSET 12
#define TCP_PSEUDO_HDR_SRC_ADDR_OFFSET 0
#define TCP_PSEUDO_HDR_DST_ADDR_OFFSET 4
#define TCP_PSEUDO_HDR_ZEROS_OFFSET 8
#define TCP_PSEUDO_HDR_PROTOCOL_OFFSET 9
#define TCP_PSEUDO_HDR_TCP_LEN_OFFSET 10

//ARP HDR
//opcode
//src ip
//src mac
//dst ip
//dst mac

//ICMP HDR

//UDP HDR

//PROTOCOL NAME TO OPCODE
#define ETH_HDR_IP_OPCODE 8 //(0x0800)
#define ETH_HDR_ARP_OPCODE 1544 //(0x0806)
#define IP_HDR_TCP_OPCODE 6
#define IP_HDR_UDP_OPCODE 17
#define IP_HDR_ICMP_OPCODE 1
#define ARP_HDR_REQ_OPCODE 256
#define ARP_HDR_REP_OPCODE 512


typedef struct {
  unsigned char mac_dst[MAC_ADDR_LEN]; //magic numbers
  unsigned char mac_src[MAC_ADDR_LEN];
  unsigned short type;
}ether_hdr;

typedef struct {
  uint8_t tos; //actually 6 bits
  uint16_t total_len;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t chksum;
  uint32_t src_ip;
  uint32_t dst_ip;
  const u_char *data;
  u_char *raw_hdr;
}ip_hdr;

typedef struct{
  uint16_t hardware_type; //network protocol type ex. ether is 1
  uint16_t protocol_type; //i think supposed to be value 0x0800
  uint8_t hlen; //Hardware Address Length
  uint8_t plen; //protocol address length
  uint16_t opcode; //operation
  uint8_t sha[MAC_ADDR_LEN]; //sender hardware address -- MAC Address
  uint32_t spa; //sender protocol address -- IP Address
  uint32_t tha[MAC_ADDR_LEN]; //target hardware address -- MAC Address
  uint32_t tpa; //target protocol address -- IP Address
}arp_hdr;

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint16_t ecn; //only 3 bits fin and other flags going to have to do some masking stuff
  uint16_t window_size;
  uint8_t flags;
  uint16_t chksum;
  uint16_t chksum_pass;
  //  const u_char *data;
}tcp_hdr;

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint16_t cheksum;
  uint32_t data;
}udp_hdr;


tcp_hdr *get_tcp_hdr(const u_char *pkt_data_pos, ip_hdr *Ip_Hdr);

void print_tcp_hdr(tcp_hdr *Tcp_Hdr);

uint16_t check_tcp_hdr(const u_char *pkt_data_pos, tcp_hdr *Tcp_Hdr, ip_hdr *Ip_Hdr);

ip_hdr *get_ip_hdr(const u_char *pkt_data_pos);

void print_ip_hdr(ip_hdr *Ip_Hdr);

ether_hdr *get_ethernet_hdr(const u_char *pkt_data_pos);

void print_ethernet_hdr(ether_hdr *Ether_Hdr);

arp_hdr *get_arp_hdr(const u_char *pkt_data_pos);

void print_arp_hdr(arp_hdr *Arp_Hdr);

udp_hdr *get_udp_hdr(const u_char *pkt_data_pos);

char *print_mac_addr(const u_char *addr_binary);

char *print_ip_addr(const u_char *addr_binary);

void *safe_malloc(size_t size);

void print_udp_hdr(udp_hdr *Udp_Hdr);

#endif
