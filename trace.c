#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define END_OF_PCAP_FILE -2

#define MAC_ADDR_LEN 6 //In bytes
#define ETHER_TYPE_LEN 2 //In bytes
#define TOS_LEN 6
#define ECN_LEN 2
#define TOTAL_LEN_LEN 16
#define ARP_HDR_IPV4_SIZE 224 //in bytes

#define IDENTIFCATION_LEN 16
#define FLAG_LEN 3

typedef struct {
  unsigned char mac_dst[MAC_ADDR_LEN]; //magic numbers
  unsigned char mac_src[MAC_ADDR_LEN];
  unsigned short type;
}ether_hdr;

typedef struct {
  uint8_t version;
  uint8_t hdr_len;
  uint8_t tos[TOS_LEN]; //type_of_service
  uint8_t ecn[ECN_LEN]; //explicit_congestion_notification
  uint8_t total_len[TOTAL_LEN_LEN]; //WTF RETARDED #DEFINE
  uint8_t identification[IDENTIFCATION_LEN];
  uint8_t flags[FLAG_LEN];
  uint8_t fragment_offset;
  uint8_t time_to_live;
  uint8_t protocol;
  uint8_t checksum;
  uint8_t ip_addr_src;
  uint8_t ip_addr_dst;
  uint8_t options; //if header length > 5 -- not sure if needed
  const u_char *data;
}ip_hdr;

ether_hdr *get_ethernet_hdr(const u_char *pkt_data_pos)
{

  uint32_t offset = 0;
  //needs to be redone properly since structures can be padded
  ip_hdr *Ip_Hdr = safe_malloc(sizeof(ip_hdr));

  memcpy(&(Ip_Hdr->version), pkt_data_pos + offset, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  memcpy(&(Ip_Hdr->hdr_len), pkt_data_pos + offset, sizeof(uint8_t));
  offset += sizeof(uint8_t);

  memcpy(&(Ip_Hdr->tos), pkt_data_pos + offset, sizeof(uint8_t)*TOS_LEN);
  offset += sizeof(uint8_t) * TOS_LEN;

  memcpy(&(Ip_Hdr->ecn), pkt_data_pos + offset, sizeof(uint8_t)*ECN_LEN);
  offset += sizeof(uint8_t) * ECN_LEN;





  return Ip_Hdr;
}


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

//Takes in the current PCAP data position
//takes in the ethernet header and checks to see if is correct
//if no errors then it copies the data into a struct and returns
//the pointer of the struct
ether_hdr *get_ethernet_hdr(const u_char *pkt_data_pos)
{
  //needs to be redone properly since structures can be padded
  ether_hdr *Ether_Hdr = safe_malloc(ETHER_HDR_SIZE);
  memcpy(&(*(Ether_Hdr)), pkt_data_pos, ETHER_HDR_SIZE); //used to be set equale to Ether_Hdr
  return Ether_Hdr;
}

ip_hdr *get_ip_hdr(const u_char *pkt_data_pos)
{
  return NULL;
}

char *print_ip_addr(const u_char *addr_binary)
{
  struct in_addr in;
  memcpy(&(in.s_addr), addr_binary, sizeof(uint32_t));
  return inet_ntoa(in);
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

upd_hdr *get_udp_hdr(const u_char *pkt_data_pos)
{
  uint32_t offset = 0;
  upd_hdr *Udp_Hdr = safe_malloc(sizeof(udp_hdr));
  
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
  arp_hdr *Arp_Hdr;


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
      pkt_data_pos += ETHER_HDR_SIZE; 
      Arp_Hdr = get_arp_hdr((pkt_data+pkt_data_pos));
      print_arp_hdr(Arp_Hdr);
    }
  pcap_close(pcap_file);

  //-------------------
  //DONT FORGET TO WORRY ABOUT MEMORY LEAQUES
  //-------------------
   
  return EXIT_SUCCESS;
}
