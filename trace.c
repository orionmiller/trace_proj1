#include "trace.h"

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
  printf("\t\tDestination Port: %u\n",(unsigned int)Tcp_Hdr->dst_port);
  printf("\t\tSequence number: %u\n", Tcp_Hdr->seq_num);
  printf("\t\tAck Number: %u\n", Tcp_Hdr->ack_num);
  printf("\t\tSYN flag: \n");
  printf("\t\tReset flag: \n");
  printf("\t\tWindow Size: \n");
  printf("\t\tChecksum: 0x%X\n", ntohs(Tcp_Hdr->chksum));
  printf("\n");
}

uint16_t check_tcp_hdr(const u_char *pkt_data_pos, tcp_hdr *Tcp_Hdr, ip_hdr *Ip_Hdr)
{
  //  uint32_t datagram_size;
  u_char *chksum_datagram;
  uint16_t tcp_len = 0;
  uint16_t tcp_len_nto = 0;
  uint16_t tcp_len_no_pseudo = 0;
  uint8_t zeros = 0;
  int i;
  tcp_len = TCP_PSEUDO_HDR_SIZE + ntohs(Ip_Hdr->total_len) - IP_HDR_SIZE;
  tcp_len_no_pseudo = ntohs(Ip_Hdr->total_len) - IP_HDR_SIZE;
  tcp_len_nto = htons(tcp_len_no_pseudo);
  chksum_datagram = (u_char *)malloc(tcp_len);

  //CREATE PSEUDO HEADER
  memcpy(chksum_datagram + TCP_PSEUDO_HDR_SRC_ADDR_OFFSET , &(Ip_Hdr->src_ip), sizeof(uint32_t));
  memcpy(chksum_datagram + TCP_PSEUDO_HDR_DST_ADDR_OFFSET , &(Ip_Hdr->dst_ip), sizeof(uint32_t));
  memcpy(chksum_datagram + TCP_PSEUDO_HDR_ZEROS_OFFSET, &(zeros), sizeof(uint8_t));
  //zeros area was already tacken care of because of calloc
  memcpy(chksum_datagram + TCP_PSEUDO_HDR_PROTOCOL_OFFSET , &(Ip_Hdr->protocol), sizeof(uint8_t));
  memcpy(chksum_datagram + TCP_PSEUDO_HDR_TCP_LEN_OFFSET , &(tcp_len_nto), sizeof(uint16_t));

  //DUMP TCP DATAGRAM INTO PSEUDO_HDR+TCP_DATAGRAM

  memcpy(chksum_datagram + TCP_DATAGRAM_OFFSET, pkt_data_pos, tcp_len_no_pseudo);

  //  printf("tcp len nto: 0x%X",tcp_len_nto)
  //COMPUTE CHECKSUM
  printf("pseudo header::\n");
  for (i = 0; i < TCP_PSEUDO_HDR_SIZE; i++)
    {
      printf("%X ", chksum_datagram[i]);
    }
  printf("\ntcp header::\n");
  for (i = TCP_PSEUDO_HDR_SIZE; i < TCP_PSEUDO_HDR_SIZE + TCP_PSEUDO_HDR_SIZE; i++)
    {
      printf("%X ", chksum_datagram[i]);
    }
  printf("\ntcp data::\n");
  for (i = TCP_PSEUDO_HDR_SIZE + TCP_PSEUDO_HDR_SIZE; i < tcp_len; i++)
    {
      printf("%X ", chksum_datagram[i]);
    }
  printf("\n");


  return in_cksum((u_short *)chksum_datagram, tcp_len);

  //  printf("datagram size: %u\n", datagram_size);
  //  printf("ip_hdr total len without conversion: %u\n", Ip_Hdr->total_len);
  //  printf("ip_hdr total len with conversion: %u\n", ntohs(Ip_Hdr->total_len));
}


ip_hdr *get_ip_hdr(const u_char *pkt_data_pos)
{
  ip_hdr *Ip_Hdr = (ip_hdr *)safe_malloc(sizeof(ip_hdr));
  Ip_Hdr->raw_hdr = (u_char *)safe_malloc(sizeof(IP_HDR_SIZE));
  memcpy(&(Ip_Hdr->tos), pkt_data_pos + TOS_OFFSET, sizeof(uint8_t));
  Ip_Hdr->tos = Ip_Hdr->tos >> 2;
  memcpy(&(Ip_Hdr->total_len), pkt_data_pos + TOTAL_LEN_OFFSET, sizeof(uint16_t));
  memcpy(&(Ip_Hdr->ttl), pkt_data_pos + TTL_OFFSET, sizeof(uint8_t));
  memcpy(&(Ip_Hdr->protocol), pkt_data_pos + PROTOCOL_OFFSET, sizeof(uint8_t));
  memcpy(&(Ip_Hdr->chksum), pkt_data_pos + CHKSUM_OFFSET, sizeof(uint16_t));
  Ip_Hdr->chksum = ntohs(Ip_Hdr->chksum); //should apply ntohs elsewhere
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
  printf("\t\tProtocol: %u\n", Ip_Hdr->protocol); //need a function for human readable
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
