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

  while (pcap_next_ex(pcap_file, &Pkt_Header, &pkt_data) != END_OF_PCAP_FILE)
    {
      offset = 0;
      pkt_data_len = Pkt_Header->len;
      printf("Packet Length: %u\n\n", pkt_data_len);
      Ether_Hdr = get_ethernet_hdr((pkt_data+offset));
      print_ethernet_hdr(Ether_Hdr);
      //check for arp
      /* offset += ETHER_HDR_SIZE;  */
      /* Arp_Hdr = get_arp_hdr((pkt_data+offset)); */
      /* print_arp_hdr(Arp_Hdr); */
      offset += ETHER_HDR_SIZE;
      Ip_Hdr = get_ip_hdr((pkt_data+offset));

      print_ip_hdr(Ip_Hdr);
      offset += IP_HDR_SIZE;
      Tcp_Hdr = get_tcp_hdr((pkt_data+offset));
      print_tcp_hdr(Tcp_Hdr);
      printf("checksum out: %X\n", check_tcp_hdr(pkt_data+offset, Tcp_Hdr, Ip_Hdr));
    }
  pcap_close(pcap_file);

  //-------------------
  //DONT FORGET TO WORRY ABOUT MEMORY LEAQUES
  //-------------------
   
  return EXIT_SUCCESS;
}
