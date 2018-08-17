#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <iostream>
#include <map>
#include <iterator>

using namespace std;
#define TCP_FIN  (0x1 << 0)  
#define TCP_SYN  (0x1 << 1)  
#define TCP_RST  (0x1 << 2) 
#define TCP_PSH  (0x1 << 3)  
#define TCP_ACK  (0x1 << 4)  
#define TCP_URG  (0x1 << 5)  
#define TCP_ECE  (0x1 << 6) 
#define TCP_CWR  (0x1 << 7) 

struct	ether_header {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short	ether_type;
};
struct	ether_header_vlan {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	uint16_t vlan_proto;
	uint16_t vlan_tci;
	uint16_t ether_type;
};
struct iphdr {
        uint8_t                 ip_hl:4; /* both fields are 4 bits */
        uint8_t                 ip_v:4;
        uint8_t                 ip_tos;
        uint16_t                ip_len;
        uint16_t                ip_id;
        uint16_t                ip_off;
        uint8_t                 ip_ttl;
        uint8_t                 ip_p;
        uint16_t                ip_sum;
        struct in_addr  ip_src;
        struct in_addr  ip_dst;
};
#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 
struct tcphdr {
        uint16_t                source;
        uint16_t                dest;
        uint16_t                seq;
        uint32_t                ack_seq;
        uint8_t                 hl;                     //tcp header length
        uint8_t                 Flags;
        uint16_t                window;
        uint16_t                check;
        uint16_t                urg_ptr;
} ;

struct iphdr *ip;
struct tcphdr *tcp;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *pcap;
struct pcap_pkthdr hdr;
const unsigned char   *packet;

uint16_t ether_type;

struct ether_header *eth;
struct ether_header_vlan *ether_header_vlan;

std::map <std::string,int> Out;

void PrintJson(){
	cout<<"{"<<endl;
	for (std::map <std::string,int>::iterator it = Out.begin();it!=Out.end();it++){
		cout<<"\""<<it->first << "\":" <<it->second;	
		if (++it!=Out.end()) cout<<",";
		it--;
		cout<<endl;
	}
	cout<<"}"<<endl;
}

int main(int argc, char **argv){

//for s in `cat packetstats.cpp |grep 'Out\[\"[a-zA-Z_-]\{0,20\}\"\]' -o |sort -u `;do  echo $s=0\; ;done

	Out["EthernetBytes"]=0;
	Out["IpBytes"]=0;
	Out["IpPackets"]=0;
	Out["TCP_ACK"]=0;
	Out["TCP_ACK-ECE"]=0;
	Out["TCP_ACK-RST"]=0;
	Out["TcpBytes"]=0;
	Out["TCP_FIN"]=0;
	Out["TCP_FIN-ACK"]=0;
	Out["TCP_FIN-PSH"]=0;
	Out["TCP_FIN-PSH-ACK"]=0;
	Out["TCP_OTHER"]=0;
	Out["TcpPackets"]=0;
	Out["TCP_PSH-ACK"]=0;
	Out["TCP_PSH-URG"]=0;
	Out["TCP_RST"]=0;
	Out["TCP_SYN"]=0;
	Out["TCP_SYN-ACK"]=0;
	Out["TooSmallFrames"]=0;
	Out["TotalPackets"]=0;
	Out["UdpBytes"]=0;
	Out["UdpPackets"]=0;
	Out["VlanTagged"]=0;


	pcap=pcap_open_offline(argv[1], errbuf);
	if(pcap==NULL){
		fprintf(stderr,"Cannot open input file\n");
		return 0;
	}

	while((packet=pcap_next(pcap,&hdr))!=NULL) {
		Out["TotalPackets"]++;
		Out["EthernetBytes"]=Out["EthernetBytes"]+hdr.caplen+12+8+4; 
		if(hdr.caplen<12) {
			Out["TooSmallFrames"]++;
			continue;
		}
		eth=(struct ether_header *)packet;
		
		int offset_payload=0;
		int eth_len=0;
		/* "Decapsulate" Vlan tagged frames */
		switch(htons(eth->ether_type)){
			case 0x8100:
				Out["VlanTagged"]++;
				ether_header_vlan=(struct ether_header_vlan *)packet;
				ether_type=ether_header_vlan->ether_type;
				offset_payload=4;
				break;
			default:
				ether_type=eth->ether_type;
				break;
			
		}
		/* Calculate the size of the ethernet header, normal or one that includes the vlan tag */
		eth_len=sizeof(struct ether_header)+offset_payload;
		switch(htons(ether_type)){
			case 0x0800:
				Out["IpPackets"]++;
				Out["IpBytes"]+=hdr.caplen-(eth_len);
				ip=(struct iphdr *)(packet+eth_len);
				switch(ip->ip_v){
					case 0x04:	
						Out["IPv4Packets"]++;
						switch(ip->ip_p){
							case 0x06:
								Out["TcpPackets"]++;
								Out["TcpBytes"]+=(hdr.caplen-eth_len);
								tcp=(struct tcphdr*)ip+1;
								switch(tcp->Flags){
									case TCP_SYN:
										Out["TCP_SYN"]++;
										break;
									case (TCP_SYN|TCP_ACK):
										Out["TCP_SYN-ACK"]++;
										break;
									case (TCP_ACK):
										Out["TCP_ACK"]++;
										break;
									case (TCP_ACK|TCP_PSH):
										Out["TCP_PSH-ACK"]++;
										break;
									case (TCP_RST):
										Out["TCP_RST"]++;
										break;
									case (TCP_ACK|TCP_FIN):
										Out["TCP_FIN-ACK"]++;
										break;
									case (TCP_FIN):
										Out["TCP_FIN"]++;
										break;														
									case (TCP_FIN|TCP_ACK|TCP_PSH):
										Out["TCP_FIN-PSH-ACK"]++;
										break;		
									case (TCP_FIN|TCP_PSH):
										Out["TCP_FIN-PSH"]++;
										break;
									case (TCP_PSH|TCP_URG):
										Out["TCP_PSH-URG"]++;
										break;										
									case (TCP_ACK|TCP_ECE):
										Out["TCP_ACK-ECE"]++;
										break;											
									case (TCP_ACK|TCP_RST):
										Out["TCP_ACK-RST"]++;
										break;														
									default:
										Out["TCP_OTHER"]++;
										//printf("Leading text \n"BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(tcp->Flags));
										break;
								}
								break;
							case 0x11:
								Out["UdpPackets"]++;
								Out["UdpBytes"]+=(hdr.caplen-eth_len);
								break;
						}
						break;
					case 0x06:
						Out["IPv6Packets"]++;
						break;
					}
				break;
		}
	}
	PrintJson();
	/*
	for (std::map <std::string,int>::iterator it = Out.begin();it!=Out.end();it++){
		std::cout<<it->first << " => " <<it->second<<std::endl;
	}
	*/
}