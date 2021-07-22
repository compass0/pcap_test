#include "pcap-test.h"
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>


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

void parsingTCPPacket(const u_char* packet);
void parseEthernetHeader(struct libnet_ethernet_hdr *ethernetH);
void parseIpv4Header(struct libnet_ipv4_hdr *ipv4H);
void parseTCPHeader(struct libnet_tcp_hdr *tcpH);

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

		parsingTCPPacket(packet);
	}

	pcap_close(pcap);
}

void parsingTCPPacket(const u_char* packet){
	struct libnet_ethernet_hdr *ethernetH;
	struct libnet_ipv4_hdr *ipv4H;
	struct libnet_tcp_hdr *tcpH;
	struct packet_data *data;
	
	ethernetH = (struct libnet_ethernet_hdr *)packet;
	parseEthernetHeader(ethernetH);
	

	if(ntohs(ethernetH->ether_type) == (u_int16_t)0x800){
		packet += 14;
		ipv4H = (struct libnet_ipv4_hdr *)packet;
		parseIpv4Header(ipv4H);

		if(ipv4H->ip_p == 0x06){
			packet += (uint16_t)(4*4);
			tcpH = (struct libnet_tcp_hdr *)packet;
			parseTCPHeader(tcpH);

			u_int length = htons(ipv4H->ip_len) - (uint16_t)(4*4);
			packet += (u_char)length;
			data = (struct packet_data *)packet;

			for(int i = 0; i<8; i++){
				printf("%02x ", data->data[i]);
			}
			printf("\n");
		}
	}
	printf("\n");
}

void parseEthernetHeader(struct libnet_ethernet_hdr *ethernetH){
	printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x \n", ethernetH->ether_dhost[0], ethernetH->ether_dhost[1], ethernetH->ether_dhost[2], ethernetH->ether_dhost[3], ethernetH->ether_dhost[4], ethernetH->ether_dhost[5]);
	printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x \n", ethernetH->ether_shost[0], ethernetH->ether_shost[1], ethernetH->ether_shost[2], ethernetH->ether_shost[3], ethernetH->ether_shost[4], ethernetH->ether_shost[5]);
}

void parseIpv4Header(struct libnet_ipv4_hdr *ipv4H){
	printf("src ip : %s\n", inet_ntoa(ipv4H->ip_src));
	printf("dst ip : %s\n", inet_ntoa(ipv4H->ip_dst));
}

void parseTCPHeader(struct libnet_tcp_hdr *tcpH){
	printf("src port : %d\n", tcpH->th_sport);
	printf("dst port : %d\n", tcpH->th_dport);
}