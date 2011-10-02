#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <stdint.h>

#define END_OF_PCAP_FILE -2

#define MAC_ADDR_LEN 6 //In bytes
#define ETHER_TYPE_LEN 2 //In bytes
#define TOS_LEN 6
#define ECN_LEN 2
#define TOTAL_LEN_LEN 16
#define ARP_HDR_IPV4_SIZE 224 //in bytes

#define IDENTIFCATION_LEN 1 //INCORECCT FIIIXXX
#define FLAG_LEN 4 //FIIIIIIIIIIIIIIIX

typedef struct {
  unsigned char mac_dst[MAC_ADDR_LEN]; //magic numbers
  unsigned char mac_src[MAC_ADDR_LEN];
  unsigned short type;
}ether_hdr;

typedef struct {
  unsigned char version;
  unsigned char header_length;
  unsigned char type_of_service[TOS_LEN];
  unsigned char explicit_congestion_notif[ECN_LEN];
  unsigned char total_len[TOTAL_LEN_LEN]; //WTF RETARDED #DEFINE
  unsigned char identification[IDENTIFCATION_LEN];
  unsigned char flags[FLAG_LEN];
  unsigned char fragment_offset;
  unsigned char time_to_live;
  unsigned char protocol;
  unsigned char checksum;
  unsigned char ip_addr_src;
  unsigned char ip_addr_dst;
  unsigned char options; //if header length > 5 -- not sure if needed
  const u_char *data;
}ip_hdr;


typedef struct{
  uint16_t hardware_type; //network protocol type ex. ether is 1
  uint16_t protocol_type; //i think supposed to be value 0x0800
  uint8_t hlen; //Hardware Address Length
  uint8_t plen; //protocol address length
  uint16_t opcode; //operation
  uint32_t sha; //sender hardware address
  uint32_t spa; //sender protocol address
  uint32_t tha; //target hardware address
  uint32_t tpa; //target protocol address
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

char *print_mac_addr(const u_char *addr_binary)
{
  struct ether_addr addr;
  memcpy(&addr, addr_binary, MAC_ADDR_LEN);
  return ether_ntoa(&addr);
}


void print_ethernet_hdr(ether_hdr *Ether_Hdr)
{
  printf("Ethernet Header Output:\n");
  printf("Dest MAC: %s\n", print_mac_addr(Ether_Hdr->mac_dst));
  printf("Sourc MAC: %s\n",print_mac_addr(Ether_Hdr->mac_src));
  printf("Type: %u\n", (unsigned int)Ether_Hdr->type); //may cause issues
  printf("\n");
}

arp_hdr *get_arp_hdr(const u_char *pkt_data_pos)
{
  uint32_t offset = 0;
  arp_hdr *Arp_Hdr = safe_malloc(ARP_HDR_IPV4_SIZE);
  memcpy(&(Arp_Hdr->hardware_type), pkt_data_pos + offset, sizeof(uint16_t));
  offset += sizeof(uint16_t);
  memcpy(&(Arp_Hdr->protocol_type), pkt_data_pos + offset, sizeof(uint16_t));
  offset += sizeof(uint16_t);
  memcpy(&(Arp_Hdr->hlen), pkt_data_pos + offset, sizeof(uint8_t));
  offset += sizeof(uint8_t);
  memcpy(&(Arp_Hdr->plen), pkt_data_pos + offset, sizeof(uint8_t));
  offset += sizeof(uint8_t);
  memcpy(&(Arp_Hdr->opcode), pkt_data_pos + offset, sizeof(uint16_t));
  offset += sizeof(uint32_t);
  memcpy(&(Arp_Hdr->sha), pkt_data_pos + offset, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(&(Arp_Hdr->spa), pkt_data_pos + offset, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(&(Arp_Hdr->tha), pkt_data_pos + offset, sizeof(uint32_t));
  offset += sizeof(uint32_t);
  memcpy(&(Arp_Hdr->tpa), pkt_data_pos + offset, sizeof(uint32_t));

  return Arp_Hdr;
}

void print_arp_hdr(arp_hdr *Arp_Hdr)
{
  printf("Opcode: %u\n", (unsigned int)(Arp_Hdr->opcode));
  printf("Sender MAC: %s\n", print_mac_addr((const u_char *)&(Arp_Hdr->sha)));
  printf("Sender IP: \n");
  printf("Target MAC: %s\n", print_mac_addr((const u_char *)&(Arp_Hdr->tha)));
  printf("Target IP: \n");
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


  if (argc != 2) 
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
      pkt_data_len = Pkt_Header->len;
      printf("Packet Length: %u\n", pkt_data_len);
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
