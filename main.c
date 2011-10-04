#include "trace.h"

int main(int argc, char *argv[])
{
  char *pcap_filename;
  pcap_t *pcap_file;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr pkt_header;
  struct pcap_pkthdr *Pkt_Header = &pkt_header;

  uint32_t  offset = 0;
  const u_char *pkt_data;
  unsigned int pkt_data_len;
  ether_hdr *Ether_Hdr;
  arp_hdr *Arp_Hdr;
  ip_hdr *Ip_Hdr;
  tcp_hdr *Tcp_Hdr;
  udp_hdr *Udp_Hdr;
  icmp_hdr *Icmp_Hdr;
  int num_pkt = 1;


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

  while (pcap_next_ex(pcap_file, &Pkt_Header, &pkt_data) != END_OF_PCAP_FILE)
    {
      pkt_data_len = Pkt_Header->len;
      printf("\nPacket number: %d  Packet Len: %u\n\n", num_pkt, pkt_data_len);
      //GET DATA
      offset = 0;
      Ether_Hdr = get_ethernet_hdr((pkt_data+offset));
      print_ethernet_hdr(Ether_Hdr);
      offset += ETHER_HDR_SIZE;

      switch (Ether_Hdr->type)
	{
	  
	case ETH_HDR_IP_OPCODE:
	  Ip_Hdr = get_ip_hdr((pkt_data+offset));
	  offset += IP_HDR_SIZE;
	  print_ip_hdr(Ip_Hdr);

	  switch (Ip_Hdr->protocol)
	    {
	    case IP_HDR_TCP_OPCODE:
	      Tcp_Hdr = get_tcp_hdr((pkt_data+offset), Ip_Hdr);
	      print_tcp_hdr(Tcp_Hdr);
	      free(Tcp_Hdr);
	      free(Ip_Hdr->raw_hdr);
	      free(Ip_Hdr);
	      break;

	    case IP_HDR_UDP_OPCODE:
	      Udp_Hdr = get_udp_hdr(pkt_data+offset);
	      print_udp_hdr(Udp_Hdr);
	      free(Udp_Hdr);
	      free(Ip_Hdr->raw_hdr);
	      free(Ip_Hdr);
	      break;

	    case IP_HDR_ICMP_OPCODE:
	      Icmp_Hdr = get_icmp_hdr((pkt_data+offset));
	      print_icmp_hdr(Icmp_Hdr);
	      free(Icmp_Hdr);
	      free(Ip_Hdr->raw_hdr);
	      free(Ip_Hdr);
	      break;
		    
	    default:
	      break;
	    }
	  break;

	case ETH_HDR_ARP_OPCODE:
	  Arp_Hdr = get_arp_hdr((pkt_data+offset));
	  print_arp_hdr(Arp_Hdr);
	  free(Arp_Hdr);

	  break;
	  
	default:
	  printf("NOT THERE\n\n");
	  break;
	}

      free(Ether_Hdr);
      num_pkt++;
    }
  pcap_close(pcap_file);

  //-----------------------------------------//
  //DONT FORGET TO WORRY ABOUT MEMORY LEAQUES//
  //-----------------------------------------//
   
  return EXIT_SUCCESS;
}
