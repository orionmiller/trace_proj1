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

typedef struct {
  unsigned char mac_dst[MAC_ADDR_LEN]; //magic numbers
  unsigned char mac_src[MAC_ADDR_LEN];
  unsigned short type;
}ether_hdr;

/* typedef struct { */
/*   uint8_t version; */
/*   uint8_t hdr_len; */
/*   uint8_t tos[TOS_LEN]; //type_of_service */
/*   uint8_t ecn[ECN_LEN]; //explicit_congestion_notification */
/*   uint8_t total_len[TOTAL_LEN_LEN]; //WTF RETARDED #DEFINE */
/*   uint8_t id[IDENTIFCATION_LEN]; //identification */
/*   uint8_t flags[FLAGS_LEN]; */
/*   uint8_t fragment_offset; */
/*   uint8_t ttl; //time_to_live */
/*   uint8_t protocol;  */
/*   uint8_t checksum; */
/*   uint8_t ip_addr_src; //wrong size */
/*   uint8_t ip_addr_dst; //wrong size */
/*   uint8_t options; //if header length > 5 -- not sure if needed */
/*   const u_char *data; */
/* }ip_hdr; */




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


#define ETHER_HDR_SIZE 14 //bytes

void *safe_malloc(size_t size)
{
  void *allocated_mem;
  if((allocated_mem = malloc(size))== NULL)
    {
      printf("Memory Allocation Error\n");
      exit(EXIT_FAILURE);
    }
  return allocated_mem;
}

#define TCP_SRC_PORT_OFFSET 0
#define TCP_DST_PORT_OFFSET 2
#define TCP_SEQ_NUM_OFFSET 4
#define TCP_ACK_NUM_OFFSET 8
#define TCP_WINDOW_SIZE_OFFSET 14
#define TCP_CHKSUM_OFFSET 16
#define TCP_ECN_OFFSET 12
#define TCP_ECN_MASK (0x01C0)

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint16_t ecn; //only 3 bits fin and other flags going to have to do some masking stuff
  uint16_t window_size;
  uint16_t chksum;
  //  const u_char *data;
}tcp_hdr;


tcp_hdr *get_tcp_hdr(const u_char *pkt_data_pos)
{
  tcp_hdr *Tcp_Hdr = (tcp_hdr *)safe_malloc(sizeof(tcp_hdr));
  memcpy(&(Tcp_Hdr->src_port), pkt_data_pos + TCP_SRC_PORT_OFFSET, sizeof(uint16_t));
  Tcp_Hdr->src_port = ntohs(Tcp_Hdr->src_port);  //should make implementation to all conversion taken outside collection into struct
  memcpy(&(Tcp_Hdr->dst_port), pkt_data_pos + TCP_DST_PORT_OFFSET, sizeof(uint16_t));
  memcpy(&(Tcp_Hdr->seq_num), pkt_data_pos + TCP_SEQ_NUM_OFFSET, sizeof(uint32_t));
  memcpy(&(Tcp_Hdr->ack_num), pkt_data_pos + TCP_ACK_NUM_OFFSET, sizeof(uint32_t));
  memcpy(&(Tcp_Hdr->ecn), pkt_data_pos + TCP_ECN_OFFSET, sizeof(uint16_t));
  Tcp_Hdr->ecn = TCP_ECN_MASK & Tcp_Hdr->ecn; //double check
  Tcp_Hdr->ecn = Tcp_Hdr->ecn >> 6; //double check
  memcpy(&(Tcp_Hdr->window_size), pkt_data_pos + TCP_WINDOW_SIZE_OFFSET, sizeof(uint16_t));
  memcpy(&(Tcp_Hdr->chksum), pkt_data_pos + TCP_CHKSUM_OFFSET, sizeof(uint16_t));

  return Tcp_Hdr;
}

void print_tcp_hdr(tcp_hdr *Tcp_Hdr)
{
  printf("\tTCP Header\n");
  printf("\t\tSource Port: %u\n", (unsigned int)Tcp_Hdr->src_port);
  printf("\t\tDestination Port: \n");
  printf("\t\tSequence number: \n");
  printf("\t\tAck Number: \n");
  printf("\t\tSYN flag: \n");
  printf("\t\tReset flag: \n");
  printf("\t\tWindow Size: \n");
  printf("\t\tChecksum: \n");
  printf("\n");
}

#define TCP_PSEUDO_HDR_SIZE 12
#define TCP_DATAGRAM_OFFSET 12

typedef struct {
  uint8_t tos; //actually 6 bits
  uint8_t total_len;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t chksum;
  uint32_t src_ip;
  uint32_t dst_ip;
  const u_char *data;
  u_char *raw_hdr;
}ip_hdr;

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

void check_tcp_hdr(const u_char *pkt_data_pos, tcp_hdr *Tcp_Hdr, ip_hdr *Ip_Hdr)
{
  uint32_t datagram_size;
  //  u_char *chksum_datagram = NULL;
  datagram_size = TCP_PSEUDO_HDR_SIZE + ntohl(Ip_Hdr->total_len) - IP_HDR_SIZE;
  //  chksum_datagram = (u_char *)calloc(sizeof(u_char), datagram_size);
  
  printf("datagram size: %u\n", datagram_size);
  printf("ip_hdr total len without conversion: %u\n", Ip_Hdr->total_len);
  printf("ip_hdr total len with conversion: %u\n", ntohl(Ip_Hdr->total_len));

}





ip_hdr *get_ip_hdr(const u_char *pkt_data_pos)
{
  ip_hdr *Ip_Hdr = (ip_hdr *)safe_malloc(sizeof(ip_hdr));
  Ip_Hdr->raw_hdr = (u_char *)safe_malloc(sizeof(IP_HDR_SIZE));
  memcpy(&(Ip_Hdr->tos), pkt_data_pos + TOS_OFFSET, sizeof(uint8_t));
  Ip_Hdr->tos = Ip_Hdr->tos >> 2;
  memcpy(&(Ip_Hdr->total_len), pkt_data_pos + TOTAL_LEN_OFFSET, sizeof(uint8_t));
  memcpy(&(Ip_Hdr->ttl), pkt_data_pos + TTL_OFFSET, sizeof(uint8_t));
  memcpy(&(Ip_Hdr->protocol), pkt_data_pos + PROTOCOL_OFFSET, sizeof(uint8_t));
  memcpy(&(Ip_Hdr->chksum), pkt_data_pos + CHKSUM_OFFSET, sizeof(uint16_t));
  Ip_Hdr->chksum = ntohs(Ip_Hdr->chksum);
  memcpy(&(Ip_Hdr->src_ip), pkt_data_pos + SRC_IP_OFFSET, sizeof(uint32_t));
  memcpy(&(Ip_Hdr->dst_ip), pkt_data_pos + DST_IP_OFFSET, sizeof(uint32_t));
  Ip_Hdr->data = pkt_data_pos + DATA_OFFSET;
  memcpy(Ip_Hdr->raw_hdr, pkt_data_pos, IP_HDR_SIZE);
  
  return Ip_Hdr;
}



//Takes in the current PCAP data position
//takes in the ethernet header and checks to see if is correct
//if no errors then it copies the data into a struct and returns
//the pointer of the struct
ether_hdr *get_ethernet_hdr(const u_char *pkt_data_pos)
{
  //needs to be redone properly since structures can be padded
  ether_hdr *Ether_Hdr = (ether_hdr *)safe_malloc(ETHER_HDR_SIZE);
  memcpy(&(*(Ether_Hdr)), pkt_data_pos, ETHER_HDR_SIZE); //used to be set equale to Ether_Hdr
  return Ether_Hdr;
}


char *print_ip_addr(const u_char *addr_binary)
{
  struct in_addr in;
  memcpy(&(in.s_addr), addr_binary, sizeof(uint32_t));
  return inet_ntoa(in);
}


void print_ip_hdr(ip_hdr *Ip_Hdr)
{
  printf("\tIP Header\n");
  printf("\t\tTOS: 0x%X\n", Ip_Hdr->tos);
  printf("\t\tTTL: %u\n", (uint32_t)Ip_Hdr->ttl);
  printf("\t\tProtocol: NEED AFUNCTION for dis\n");
  if (in_cksum((unsigned short int *)Ip_Hdr->raw_hdr, IP_HDR_SIZE) == IP_CHKSUM_CORRECT)
    {
    printf("\t\tChecksum: Correct (0x%X)\n", Ip_Hdr->chksum);      
    }
  else
    {
      printf("\t\tChecksum: Incorrect (0x%X)\n", Ip_Hdr->chksum);
    }
  printf("\t\tSender IP: %s\n", print_ip_addr((const u_char *)&(Ip_Hdr->src_ip)));
  printf("\t\tDest IP: %s\n", print_ip_addr((const u_char *)&(Ip_Hdr->dst_ip)));
  printf("\n");
} 

char *print_mac_addr(const u_char *addr_binary)
{
  struct ether_addr addr;
  memcpy(&addr, addr_binary, MAC_ADDR_LEN); //done incorrectly fix
  return ether_ntoa(&addr);
}

void print_ethernet_hdr(ether_hdr *Ether_Hdr)
{
  printf("\tEthernet Header\n");
  printf("\t\tDest MAC: %s\n", print_mac_addr(Ether_Hdr->mac_dst));
  printf("\t\tSource MAC: %s\n",print_mac_addr(Ether_Hdr->mac_src));
  printf("\t\tType: %u\n", (unsigned int)Ether_Hdr->type); //may cause issues
  printf("\n");
}

/* typedef struct{ */
/*   uint16_t hardware_type; //network protocol type ex. ether is 1 */
/*   uint16_t protocol_type; //i think supposed to be value 0x0800 */
/*   uint8_t hlen; //Hardware Address Length */
/*   uint8_t plen; //protocol address length */
/*   uint16_t opcode; //operation */
/*   uint32_t sha; //sender hardware address */
/*   uint32_t spa; //sender protocol address */
/*   uint32_t tha; //target hardware address */
/*   uint32_t tpa; //target protocol address */
/* }arp_hdr; */

arp_hdr *get_arp_hdr(const u_char *pkt_data_pos)
{
  uint32_t offset = 0;
  arp_hdr *Arp_Hdr = safe_malloc(sizeof(arp_hdr));
  memcpy(&(Arp_Hdr->hardware_type), pkt_data_pos + offset, sizeof(uint16_t));
  offset += sizeof(uint16_t);
  
  memcpy(&(Arp_Hdr->protocol_type), pkt_data_pos + offset, sizeof(uint16_t));
  offset += sizeof(uint16_t);
  
  memcpy(&(Arp_Hdr->hlen), pkt_data_pos + offset, sizeof(uint8_t));
  offset += sizeof(uint8_t);
  
  memcpy(&(Arp_Hdr->plen), pkt_data_pos + offset, sizeof(uint8_t));
  offset += sizeof(uint8_t);
  
  memcpy(&(Arp_Hdr->opcode), pkt_data_pos + offset, sizeof(uint16_t));
  offset += sizeof(uint16_t);
  
  memcpy(&(Arp_Hdr->sha), pkt_data_pos + offset, sizeof(uint32_t));
  offset += MAC_ADDR_LEN;
  
  memcpy(&(Arp_Hdr->spa), pkt_data_pos + offset, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  memcpy(&(Arp_Hdr->tha), pkt_data_pos + offset, sizeof(uint32_t));
  offset += MAC_ADDR_LEN;

  memcpy(&(Arp_Hdr->tpa), pkt_data_pos + offset, sizeof(uint32_t));

  return Arp_Hdr;
}

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint16_t cheksum;
  uint32_t data;
}udp_hdr;

udp_hdr *get_udp_hdr(const u_char *pkt_data_pos)
{
  uint32_t offset = 0;
  udp_hdr *Udp_Hdr = safe_malloc(sizeof(udp_hdr));
  
  memcpy(&(Udp_Hdr->src_port), pkt_data_pos + offset, sizeof(uint16_t)); //in network order
  offset += sizeof(uint16_t);

  memcpy(&(Udp_Hdr->dst_port), pkt_data_pos + offset, sizeof(uint16_t)); //in network order
  offset += sizeof(uint16_t);

  memcpy(&(Udp_Hdr->len), pkt_data_pos + offset, sizeof(uint16_t));
  offset += sizeof(uint16_t);

  memcpy(&(Udp_Hdr->cheksum), pkt_data_pos + offset, sizeof(uint16_t));
  offset += sizeof(uint16_t);

  memcpy(&(Udp_Hdr->data), pkt_data_pos + offset, sizeof(uint32_t));

  return Udp_Hdr;
}

void print_arp_hdr(arp_hdr *Arp_Hdr)
{
  printf("\tARP Header\n");
  printf("\t\tOpcode: %u\n", (unsigned int)(Arp_Hdr->opcode));
  printf("\t\tSender MAC: %s\n", print_mac_addr((const u_char *)&(Arp_Hdr->sha)));
  printf("\t\tSender IP: %s\n", print_ip_addr((const u_char *)&(Arp_Hdr->spa)));
  printf("\t\tTarget MAC: %s\n", print_mac_addr((const u_char *)&(Arp_Hdr->tha)));
  printf("\t\tTarget IP: %s\n", print_ip_addr((const u_char *)&(Arp_Hdr->tpa)));
  printf("\n");
}


int main(int argc, char *argv[])
{
  char *pcap_filename;
  pcap_t *pcap_file;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr pkt_header;

  struct pcap_pkthdr *Pkt_Header = &pkt_header;
  uint32_t  pkt_data_pos = 0;
  const u_char *pkt_data;
  unsigned int pkt_data_len;
  ether_hdr *Ether_Hdr;
  //  arp_hdr *Arp_Hdr;
  ip_hdr *Ip_Hdr;
  tcp_hdr *Tcp_Hdr;


  if (argc != 2) //magic number
    {
      printf("usage: ./trace <pcap_file>\n");
      exit(EXIT_SUCCESS);
    }

  pcap_filename = argv[1]; //magic number

  pcap_file = pcap_open_offline(pcap_filename, errbuf);

  if (pcap_file == NULL)
    {
      printf("%s\n", errbuf);
      exit(EXIT_FAILURE);
    }

  printf("successfully opened file\n");
  while (pcap_next_ex(pcap_file, &Pkt_Header, &pkt_data) != END_OF_PCAP_FILE)
    {
      pkt_data_pos = 0;
      pkt_data_len = Pkt_Header->len;
      printf("Packet Length: %u\n\n", pkt_data_len);
      Ether_Hdr = get_ethernet_hdr((pkt_data+pkt_data_pos));
      print_ethernet_hdr(Ether_Hdr);
      //check for arp
      /* pkt_data_pos += ETHER_HDR_SIZE;  */
      /* Arp_Hdr = get_arp_hdr((pkt_data+pkt_data_pos)); */
      /* print_arp_hdr(Arp_Hdr); */
      pkt_data_pos += ETHER_HDR_SIZE;
      Ip_Hdr = get_ip_hdr((pkt_data+pkt_data_pos));
      print_ip_hdr(Ip_Hdr);
      pkt_data_pos += IP_HDR_SIZE;
      Tcp_Hdr = get_tcp_hdr((pkt_data+pkt_data_pos));
      print_tcp_hdr(Tcp_Hdr);
      check_tcp_hdr(pkt_data+pkt_data_pos, Tcp_Hdr, Ip_Hdr);
    }
  pcap_close(pcap_file);

  //-------------------
  //DONT FORGET TO WORRY ABOUT MEMORY LEAQUES
  //-------------------
   
  return EXIT_SUCCESS;
}
