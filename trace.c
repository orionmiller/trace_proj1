#include "trace.h"

tcp_hdr *get_tcp_hdr(const u_char *pkt_data_pos, ip_hdr *Ip_Hdr)
{
  tcp_hdr *Tcp_Hdr = (tcp_hdr *)safe_malloc(sizeof(tcp_hdr));
  memcpy(&(Tcp_Hdr->src_port), pkt_data_pos + TCP_SRC_PORT_OFFSET, sizeof(uint16_t));
  memcpy(&(Tcp_Hdr->dst_port), pkt_data_pos + TCP_DST_PORT_OFFSET, sizeof(uint16_t));
  memcpy(&(Tcp_Hdr->seq_num), pkt_data_pos + TCP_SEQ_NUM_OFFSET, sizeof(uint32_t));
  memcpy(&(Tcp_Hdr->ack_num), pkt_data_pos + TCP_ACK_NUM_OFFSET, sizeof(uint32_t));
  memcpy(&(Tcp_Hdr->ecn), pkt_data_pos + TCP_ECN_OFFSET, sizeof(uint16_t));
  Tcp_Hdr->ecn = TCP_ECN_MASK & Tcp_Hdr->ecn; //double check
  Tcp_Hdr->ecn = Tcp_Hdr->ecn >> 6; //double check
  memcpy(&(Tcp_Hdr->window_size), pkt_data_pos + TCP_WINDOW_SIZE_OFFSET, sizeof(uint16_t));
  memcpy(&(Tcp_Hdr->chksum), pkt_data_pos + TCP_CHKSUM_OFFSET, sizeof(uint16_t));
  memcpy(&(Tcp_Hdr->flags), pkt_data_pos + TCP_FLAGS_OFFSET, sizeof(uint8_t));
  Tcp_Hdr->chksum_pass = check_tcp_hdr(pkt_data_pos, Tcp_Hdr, Ip_Hdr);
  //save to structure variable checksum pass or failure

  return Tcp_Hdr;
}

void print_tcp_hdr(tcp_hdr *Tcp_Hdr)
{
  printf("\tTCP Header\n");

  switch (ntohs(Tcp_Hdr->src_port))
    {
    case HTTP:
      printf("\t\tSource Port: HTTP\n");
      break;

    case TELNET:
      printf("\t\tSource Port: TELNET\n");
      break;

    case FTP:
      printf("\t\tSource Port: FTP\n");
      break;

    case POP3:
      printf("\t\tSource Port: POP3\n");
      break;

    case SMTP:
      printf("\t\tSource Port: SMTP\n");
      break;

    default:
      printf("\t\tSource Port:  %u\n", ntohs(Tcp_Hdr->src_port));
      break;
    }

  switch (ntohs(Tcp_Hdr->dst_port))
    {
    case HTTP:
      printf("\t\tDest Port: HTTP\n");
      break;

    case TELNET:
      printf("\t\tDest Port: TELNET\n");
      break;

    case FTP:
      printf("\t\tDest Port: FTP\n");
      break;

    case POP3:
      printf("\t\tDest Port: POP3\n");
      break;

    case SMTP:
      printf("\t\tDest Port: SMTP\n");
      break;

    default:
      printf("\t\tDest Port:  %u\n", ntohs(Tcp_Hdr->dst_port));
      break;
    }

  printf("\t\tSequence Number: %u\n", ntohl(Tcp_Hdr->seq_num));
  printf("\t\tACK Number: %u\n", ntohl(Tcp_Hdr->ack_num));
  if (Tcp_Hdr->flags & SYN_FLAG_MASK)
    printf("\t\tSYN Flag: Yes\n");
  else
    printf("\t\tSYN Flag: No\n");
  if (Tcp_Hdr->flags & RST_FLAG_MASK)
    printf("\t\tRST Flag: Yes\n");
  else
    printf("\t\tRST Flag: No\n");
  if (Tcp_Hdr->flags & FIN_FLAG_MASK)
    printf("\t\tFIN Flag: Yes\n");  
  else
    printf("\t\tFIN Flag: No\n");  
  printf("\t\tWindow Size: %u\n", ntohs(Tcp_Hdr->window_size));
  if (Tcp_Hdr->chksum_pass == 0)
    printf("\t\tChecksum: Correct (0x%x)\n", ntohs(Tcp_Hdr->chksum));
  else
    printf("\t\tChecksum: Incorrect (0x%x)\n", ntohs(Tcp_Hdr->chksum));
}

uint16_t check_tcp_hdr(const u_char *pkt_data_pos, tcp_hdr *Tcp_Hdr, ip_hdr *Ip_Hdr)
{
  u_char *chksum_datagram;
  uint16_t tcp_len = 0;
  uint16_t tcp_len_nto = 0;
  uint16_t tcp_len_no_pseudo = 0;
  uint8_t zeros = 0;

  tcp_len = TCP_PSEUDO_HDR_SIZE + ntohs(Ip_Hdr->total_len) - IP_HDR_SIZE;
  tcp_len_no_pseudo = ntohs(Ip_Hdr->total_len) - IP_HDR_SIZE;
  tcp_len_nto = htons(tcp_len_no_pseudo);
  chksum_datagram = (u_char *)malloc(tcp_len);

  memcpy(chksum_datagram + TCP_PSEUDO_HDR_SRC_ADDR_OFFSET , &(Ip_Hdr->src_ip), sizeof(uint32_t));
  memcpy(chksum_datagram + TCP_PSEUDO_HDR_DST_ADDR_OFFSET , &(Ip_Hdr->dst_ip), sizeof(uint32_t));
  memcpy(chksum_datagram + TCP_PSEUDO_HDR_ZEROS_OFFSET, &(zeros), sizeof(uint8_t));
  memcpy(chksum_datagram + TCP_PSEUDO_HDR_PROTOCOL_OFFSET, &(Ip_Hdr->protocol), sizeof(uint8_t));
  memcpy(chksum_datagram + TCP_PSEUDO_HDR_TCP_LEN_OFFSET , &(tcp_len_nto), sizeof(uint16_t));
  memcpy(chksum_datagram + TCP_DATAGRAM_OFFSET, pkt_data_pos, tcp_len_no_pseudo);

  return in_cksum((u_short *)chksum_datagram, tcp_len);
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
  printf("\t\tTOS: 0x%x\n", Ip_Hdr->tos);
  printf("\t\tTTL: %u\n", (uint32_t)Ip_Hdr->ttl);
  switch (Ip_Hdr->protocol)
    {
    case IP_HDR_TCP_OPCODE:
      printf("\t\tProtocol: TCP\n");
      break;

    case IP_HDR_UDP_OPCODE:
        printf("\t\tProtocol: UDP\n");
      break;

    case IP_HDR_ICMP_OPCODE:
      printf("\t\tProtocol: ICMP\n");
      break;

    default:
        printf("\t\tProtocol: Uknown\n");
      break;
    }

  if (in_cksum((unsigned short int *)Ip_Hdr->raw_hdr, IP_HDR_SIZE) == IP_CHKSUM_CORRECT)
    printf("\t\tChecksum: Correct (0x%x)\n", Ip_Hdr->chksum);      
  else
      printf("\t\tChecksum: Incorrect (0x%x)\n", Ip_Hdr->chksum);

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
  switch (Ether_Hdr->type)
    {
    case ETH_HDR_IP_OPCODE:
      printf("\t\tType: IP\n");
      break;

    case ETH_HDR_ARP_OPCODE:
      printf("\t\tType: ARP\n");
      break;

    default:
      printf("\t\tType: Unknown\n");
    }

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
  
  memcpy(&(Arp_Hdr->sha), pkt_data_pos + offset, MAC_ADDR_LEN);
  offset += MAC_ADDR_LEN;
  
  memcpy(&(Arp_Hdr->spa), pkt_data_pos + offset, sizeof(uint32_t));
  offset += sizeof(uint32_t);

  memcpy(&(Arp_Hdr->tha), pkt_data_pos + offset, MAC_ADDR_LEN);
  offset += MAC_ADDR_LEN;

  memcpy(&(Arp_Hdr->tpa), pkt_data_pos + offset, sizeof(uint32_t));

  return Arp_Hdr;
}

void print_arp_hdr(arp_hdr *Arp_Hdr)
{
  printf("\tARP header\n");
  switch (Arp_Hdr->opcode)
    {
    case ARP_HDR_REQ_OPCODE:
      printf("\t\tOpcode: Request\n");
      break;

    case ARP_HDR_REP_OPCODE:
      printf("\t\tOpcode: Reply\n");
      break;

    default:
      printf("\t\tUnknown");
      break;
    }

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

void print_udp_hdr(udp_hdr *Udp_Hdr)
{
  printf("\tUDP Header\n");
  printf("\t\tSource Port:  %u\n", ntohs(Udp_Hdr->src_port));
  printf("\t\tDest Port:  %u\n", ntohs(Udp_Hdr->dst_port));
}

icmp_hdr *get_icmp_hdr(const u_char *pkt_data_pos)
{
  //  int i;
  icmp_hdr *Icmp_Hdr = safe_malloc(sizeof(icmp_hdr));
  memcpy(&(Icmp_Hdr->type), pkt_data_pos + ICMP_TYPE_HDR_OFFSET, sizeof(uint8_t));
  memcpy(&(Icmp_Hdr->code), pkt_data_pos + ICMP_CODE_HDR_OFFSET, sizeof(uint8_t));

  /* for (i = 0; i < 64; i++) */
  /*   { */
  /*     printf("%X ", pkt_data_pos[i]); */
  /*   } */
  /* printf("\n"); */
  
  return Icmp_Hdr;
}

void print_icmp_hdr(icmp_hdr *Icmp_Hdr)
{
  printf("\tICMP Header\n");
  switch (Icmp_Hdr->type)
    {
    case ICMP_HDR_REQ_OPCODE:
      //      printf("\t\tType: Request %u\n", Icmp_Hdr->type);
      printf("\t\tType: Request\n");
      break;

    case ICMP_HDR_REP_OPCODE:
      //      printf("\t\tType: Reply %u\n", Icmp_Hdr->type);
      printf("\t\tType: Reply\n");
      break;

    default:
      printf("\t\tType: Unknown %u\n", Icmp_Hdr->type);
      break;
    }
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


