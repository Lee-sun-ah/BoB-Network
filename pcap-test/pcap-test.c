#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "libnet-headers.h"
#include "libnet-macros.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_e_hdr(struct libnet_ethernet_hdr* tmp){
	printf("Src MAC Address : ");
	for(int i=0; i<6; i++){
		printf("%02x",tmp->ether_shost[i]);
		if(i==5) {
			printf("\n");
			break;
		}
		printf(":");
	}
	printf("Dst MAC Address : ");
	for(int i=0; i<6; i++){
		printf("%02x",tmp->ether_dhost[i]);
		if(i==5) {
			printf("\n");
			break;
		}
		printf(":");
	}
}	
void print_i_hdr(struct libnet_ipv4_hdr* tmp){
	printf("Src IP : %s\n",inet_ntoa(tmp->ip_src));
	printf("Dst IP : %s\n",inet_ntoa(tmp->ip_dst));
}	
void print_t_hdr(struct libnet_tcp_hdr* tmp){
	printf("Src Port : %d\n",ntohs(tmp->th_sport));
	printf("Dst Port : %d\n",ntohs(tmp->th_dport));
}	
void print_payload(const u_char* tmp, struct pcap_pkthdr* header){
	printf("Payload : ");
	int x=header->caplen-(LIBNET_ETH_H+LIBNET_IPV4_H+LIBNET_TCP_H);
	if(x==0) printf("not exist\n");
	for(int i=0; i<x; i++){
		if (i==8) break;
		printf("%.2x ",tmp[i]);
	}	
	printf("\n");
}
void print_info(struct pcap_pkthdr* header, const u_char* packet){
	struct libnet_ethernet_hdr* e_hdr;//14bytes
	struct libnet_ipv4_hdr* i_hdr;//20bytes
	struct libnet_tcp_hdr* t_hdr;//20bytes
	const u_char* payload;
	
	e_hdr=(struct libnet_ethernet_hdr*)packet;
	if(ntohs(e_hdr->ether_type)==ETHERTYPE_IP){
		i_hdr=(struct libnet_ipv4_hdr*)(packet+LIBNET_ETH_H);
		if(i_hdr->ip_p==0x06){
			t_hdr=(struct libnet_tcp_hdr*)(packet+LIBNET_ETH_H+LIBNET_IPV4_H);
			payload=(u_char*)(packet+LIBNET_ETH_H+LIBNET_IPV4_H+LIBNET_TCP_H);

			printf("\n");
			print_e_hdr(e_hdr);	
			print_i_hdr(i_hdr);
			print_t_hdr(t_hdr);
			print_payload(payload,header);
			printf("%u bytes captured\n", header->caplen);
		}
	}
}
int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		print_info(header,packet);
	}
	pcap_close(pcap);
}


