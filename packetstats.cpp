#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <sys/resource.h>


#include <iostream>
#include <map>
#include <iterator>
#include <algorithm>
#include <string>
#include <utility>
#include <vector>


struct rusage  rusage;
#define SHOWRSS        getrusage(RUSAGE_THREAD,&rusage);printf("Rss: %ld MiB\n",rusage.ru_maxrss/1024);


using namespace std;


#define TCP_FIN  (0x1 << 0)  
#define TCP_SYN  (0x1 << 1)  
#define TCP_RST  (0x1 << 2) 
#define TCP_PSH  (0x1 << 3)  
#define TCP_ACK  (0x1 << 4)  
#define TCP_URG  (0x1 << 5)  
#define TCP_ECE  (0x1 << 6) 
#define TCP_CWR  (0x1 << 7) 

struct udphdr {
	uint16_t 	src;
	uint16_t 	dst;
	uint16_t 	len;
	uint16_t	check;
}__attribute__((packed));

struct tcphdr {
		uint16_t                src;
		uint16_t                dst;
		uint16_t                seq;
		uint32_t                ack_seq;
		uint8_t                 hl;                     //tcp header length
		uint8_t                 Flags;
		uint16_t                window;
		uint16_t                check;
		uint16_t                urg_ptr;
} __attribute__((packed));

struct	ether_header {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short	ether_type;
}__attribute__((packed));

struct	ether_header_vlan {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	uint16_t vlan_proto;
	uint16_t vlan_tci;
	uint16_t ether_type;
}__attribute__((packed));

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
} __attribute__((packed));

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


struct iphdr *ip;
struct tcphdr *tcp;
struct udphdr *udp;

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *pcap;
struct pcap_pkthdr hdr;
const unsigned char   *packet;

uint16_t ether_type;

struct ether_header *eth;
struct ether_header_vlan *ether_header_vlan;

std::map <std::string,int> Out;
std::map <std::string,int> DstIps;
std::map <std::string,int> SrcIps;
std::map <int,int> TcpSrcPorts;
std::map <int,int> UdpSrcPorts;
std::vector<std::pair<std::string, int> > TopDstIpsPackets(20);
std::vector<std::pair<std::string, int> > TopSrcIpsPackets(20);
std::vector<std::pair<int , int> > TopUdpSrcPorts(20);

void PrintJson(){

	//print main stuff 
	cout<<"{"<<endl;
	for (std::map <std::string,int>::iterator it = Out.begin();it!=Out.end();it++){
		cout<<"\t\""<<it->first << "\":" <<it->second;	
		std::cout<<","<<std::endl;
		/*if (++it!=Out.end()) cout<<",";
		it--;
		cout<<endl;
		*/
	}

	//top destination ips (packets)
	std::cout << "\t\"TopDstIpsPackets\": { " <<std::endl;
	
	for (std::vector<std::pair<std::string, int> >::iterator it = TopDstIpsPackets.begin() ; it != TopDstIpsPackets.end(); ++it)
	{
		std::cout <<"\t\t\""<< it->first << "\":" << it->second;
		if(++it<TopDstIpsPackets.end()) {
			if(it->second!=0) cout<<","; else {
				cout<<endl;
				break;
			}
		}
		it--;
		cout<<endl;
	}
	cout<<"\t},"<<endl;


	//top source ips (packets)
	std::cout << "\t\"TopSrcIpsPackets\": { " <<std::endl;
	for (std::vector<std::pair<std::string, int> >::iterator it = TopSrcIpsPackets.begin() ; it != TopSrcIpsPackets.end(); ++it)
	{
		std::cout <<"\t\t\""<< it->first << "\":" << it->second;
		if(++it<TopSrcIpsPackets.end()) cout<<",";
		it--;
		cout<<endl;
	}
	cout<<"\t}"<<endl;

	//top src udp ports
	std::cout << "\t\"TopUdpSrcPorts\": { " <<std::endl;
	for (std::vector<std::pair<int, int> >::iterator it = TopUdpSrcPorts.begin() ; it != TopUdpSrcPorts.end(); ++it)
	{
		std::cout <<"\t\t\""<< it->first << "\":" << it->second;
		if(++it<TopUdpSrcPorts.end()) {
			if(it->first!=0) cout<<","; else {
				cout<<endl;
				break;
			}
		}
		it--;
		cout<<endl;
	}
	cout<<"\t}"<<endl;



	//end !?


	cout<<"}"<<endl;
	//cout<<"Src ips"<<SrcIps.size();
	/*
	for(std::map<int,int>::iterator it=SrcPorts.begin();it!=SrcPorts.end();it++){
		cout<<it->first<< " " << it->second<<std::endl;
		
	}*/
}

int main(int argc, char **argv){

//for s in `cat packetstats.cpp |grep 'Out\[\"[0-9a-zA-Z_-]\{0,120\}\"\]' -o |sort -u `;do  echo $s=0\; ;done


	pcap=pcap_open_offline(argv[1], errbuf);
	if(pcap==NULL){
		fprintf(stderr,"Cannot open input file\n");
		return 0;
	}

	while((packet=pcap_next(pcap,&hdr))!=NULL) {
		Out["TOTAL-Packets"]++;
		/* 
			We add Interframe Gap, Preamble and CRC, so we get the actual bits/bytes on the wire, 
			it is quite somehow important for many small packets.
			https://kb.juniper.net/InfoCenter/index?page=content&id=kb14737
			https://www.cisco.com/c/en/us/about/security-center/network-performance-metrics.html
			
		*/
		Out["TOTAL-Bytes"]+=hdr.caplen+12+8+4; 
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
			case 0x0800://ipv4
				Out["L3_IP-Packets"]++;
				Out["L3_IP-Bytes"]+=hdr.caplen-(eth_len);
				ip=(struct iphdr *)(packet+eth_len);
				switch(ip->ip_v){
					case 0x04:	
						Out["L3_IPv4-Packets"]++;
						Out["L3_IPv4-Bytes"]+=(hdr.caplen-eth_len);
						DstIps[inet_ntoa(ip->ip_dst)]++;
						SrcIps[inet_ntoa(ip->ip_src)]++;
					
						switch(ip->ip_p){
							case 0x01:
								Out["L4_ICMP-Packets"]++;
								Out["L4_ICMP-Bytes"]+=(hdr.caplen-eth_len);
								break;
							case 0x02:
								Out["L4_IGMP-Packets"]++;
								Out["L4_IGMP-Bytes"]+=(hdr.caplen-eth_len);
								break;
							case 0x06:
								/* this "correct" only because size of ip header  = size of tcp header */
								tcp=(struct tcphdr*)ip+1;
								TcpSrcPorts[htons(tcp->src)]++;
								Out["L4_TCP-Packets"]++;
								Out["L4_TCP-Bytes"]+=(hdr.caplen-eth_len);
								
								switch(tcp->Flags){
									case TCP_SYN:
										Out["TCP_FLAGS-SYN-Packets"]++;
										Out["TCP_FLAGS-SYN-Bytes"]+=(hdr.caplen-eth_len);;
										break;
									case (TCP_SYN|TCP_ACK):
										Out["TCP_FLAGS-SYN-ACK-Packets"]++;
										Out["TCP_FLAGS-SYN-ACK-Bytes"]+=(hdr.caplen-eth_len);;
										break;
									case (TCP_ACK):
										Out["TCP_FLAGS-ACK-Packets"]++;
										Out["TCP_FLAGS-ACK-Bytes"]+=(hdr.caplen-eth_len);
										break;
									case (TCP_ACK|TCP_PSH):
										Out["TCP_FLAGS-PSH-ACK-Packets"]++;
										Out["TCP_FLAGS-PSH-ACK-Bytes"]+=(hdr.caplen-eth_len);;
										break;
									case (TCP_RST):
										Out["TCP_FLAGS-RST-Packets"]++;
										Out["TCP_FLAGS-RST-Bytes"]+=(hdr.caplen-eth_len);;
										break;
									case (TCP_ACK|TCP_FIN):
										Out["TCP_FLAGS-FIN-ACK-Packets"]++;
										Out["TCP_FLAGS-FIN-ACK-Bytes"]+=(hdr.caplen-eth_len);;
										break;
									case (TCP_FIN):
										Out["TCP_FLAGS-FIN-Packets"]++;
										Out["TCP_FLAGS-FIN-Bytes"]+=(hdr.caplen-eth_len);;
										break;														
									case (TCP_FIN|TCP_ACK|TCP_PSH):
										Out["TCP_FLAGS-FIN-PSH-ACK-Packets"]++;
										Out["TCP_FLAGS-FIN-PSH-ACK-Bytes"]+=(hdr.caplen-eth_len);;
										break;		
									case (TCP_FIN|TCP_PSH):
										Out["TCP_FLAGS-FIN-PSH-Packets"]++;
										Out["TCP_FLAGS-FIN-PSH-Bytes"]+=(hdr.caplen-eth_len);;
										break;
									case (TCP_PSH|TCP_URG):
										Out["TCP_FLAGS-PSH-URG-Packets"]++;
										Out["TCP_FLAGS-PSH-URG-Bytes"]+=(hdr.caplen-eth_len);;
										break;										
									case (TCP_ACK|TCP_ECE):
										Out["TCP_FLAGS-ACK-ECE-Packets"]++;
										Out["TCP_FLAGS-ACK-ECE-Bytes"]+=(hdr.caplen-eth_len);;
										break;											
									case (TCP_ACK|TCP_RST):
										Out["TCP_FLAGS-ACK-RST-Packets"]++;
										Out["TCP_FLAGS-ACK-RST-Bytes"]+=(hdr.caplen-eth_len);;
										break;														
									default:
										Out["TCP_FLAGS-OTHER-Packets"]++;
										Out["TCP_FLAGS-OTHER-Bytes"]+=(hdr.caplen-eth_len);;
										//printf("Leading text \n"BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(tcp->Flags));
										break;
								}
								break;
							case 0x11:
								Out["L4_UDP-Packets"]++;
								Out["L4_UDP-UdpBytes"]+=(hdr.caplen-eth_len);
								udp=(struct udphdr *)((char *)ip+sizeof(struct iphdr));
								switch(ntohs(ip->ip_off)){
									case 0x4000://df 
									case 0x2000://mf
									case 0x0000://no fragments
										UdpSrcPorts[ntohs(udp->src)]++;
										//printf("%d\n",ntohs(udp->src));
										break;
									default:
											Out["UDP_Fragmented-Packets"]++;
										break;


								}


								break;
							default:
								Out["L4_OTHER-Packets"]++;
								Out["L4_OTHER-Bytes"]++;
								break;
						}
						break;
					}
				break;
			case 0x86DD: //ipv6
				Out["L3_IP-Packets"]++;
				Out["L3_IP-Bytes"]+=(hdr.caplen-eth_len);
				Out["L3_IPv6-Packets"]++;
				Out["L3_IPv6-Bytes"]+=(hdr.caplen-eth_len);
				break;
			case 0x0806:
				Out["L2_ARP-Packets"]++;
				Out["L2_ARP-Bytes"]+=(hdr.caplen-eth_len);
				break;
			case 0x88CC:
				Out["L2_LLDP-Packets"]++;
				Out["L2_LLDP-Bytes"]+=(hdr.caplen-eth_len);
				break;
			default:
				//printf("%.4X",htons(ether_type));
				Out["L2_OTHER-Packets"]++;
				Out["L2_OTHER-Bytes"]+=(hdr.caplen-eth_len);
				break;

		}
	}
	
/*
	for (map <string,int>::iterator it = SrcIps.begin();it!=SrcIps.end();it++){
		cout<<"ipp "<<it->first << ":" <<it->second<<endl;
	}
*/
	/* 
	Create Top dst ips list 
	ripped from here https://stackoverflow.com/questions/17963905/how-can-i-get-the-top-n-keys-of-stdmap-based-on-their-values 
	don't judge me monkey
	*/
	cout<<"Sorting Top Dst Ips"<<endl;
	std::partial_sort_copy(DstIps.begin(),
						   DstIps.end(),
						   TopDstIpsPackets.begin(),
						   TopDstIpsPackets.end(),
						   [](std::pair<const std::string, int> const& l,
							  std::pair<const std::string, int> const& r)
						   {
							   return l.second > r.second;
						   });
	/* top src ips list */
	cout<<"Sorting Top Src Ips"<<endl;
	std::partial_sort_copy(SrcIps.begin(),
						   SrcIps.end(),
						   TopSrcIpsPackets.begin(),
						   TopSrcIpsPackets.end(),
						   [](std::pair<const std::string, int> const& l,
							  std::pair<const std::string, int> const& r)
						   {
							   return l.second > r.second;
						   });

	/* top src ports */
	cout<<"Sorting Top Src ports"<<endl;
	std::partial_sort_copy(UdpSrcPorts.begin(),
						   UdpSrcPorts.end(),
						   TopUdpSrcPorts.begin(),
						   TopUdpSrcPorts.end(),
						   [](std::pair<const int , int> const& l,
							  std::pair<const int, int> const& r)
						   {
							   return l.second > r.second;
						   });
	PrintJson();


}