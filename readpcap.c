#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#define PCAP_ERRBUF_SIZE 8192
struct  lpcap_hdr {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} ;

struct lpacket_hdr {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} ;


struct pcapfile {
	FILE *fp;
	struct lpcap_hdr hdr;
	unsigned char *p;
	int isstdin;
};
typedef struct pcapfile pcap_t;

struct pcap_pkthdr {
	struct timeval ts;
	uint32_t caplen;
	uint32_t len;
};

const unsigned char *pcap_next(struct pcapfile *l, struct pcap_pkthdr *h){

	struct lpacket_hdr fhdr;

	if(fread(&fhdr,1,sizeof(struct lpacket_hdr),l->fp)<=0)
		return (NULL); 

	h->caplen=fhdr.incl_len;
	h->len=fhdr.orig_len;

	if(fread(l->p,fhdr.incl_len,1,l->fp)<=0)
		return (NULL);

	return l->p;
}
struct pcapfile * pcap_open_offline(char * f, char *errbuf){

	struct pcapfile *l;
	l=(struct pcapfile *) malloc(sizeof(struct pcapfile));

	if(l==NULL)
		return (NULL);
	memset(l,0,sizeof(struct pcapfile));

	if(strcmp("-",f)==0) {
		l->fp=stdin;
		l->isstdin=1;
	} 		
	else 
		l->fp=fopen(f,"rb");

	if(l->fp==NULL){
		free(l);
		fprintf(stderr,"Cannot open %s\n",f);
		return (NULL);
	}

	if(fread(&l->hdr,sizeof(struct lpcap_hdr),1,l->fp)!=1){
		fprintf(stderr,"Read error\n");
		free(l);
		return (NULL);
	}
	//printf("%4X",l->hdr.magic_number);
	if(l->hdr.magic_number!=0xA1B2C3D4){
		fprintf(stderr,"Endianness change not handled (magic_number=%X)\n",l->hdr.magic_number);
		free(l);
		return(NULL);
	}

	if((l->p=(unsigned char *)malloc(128*1024))==NULL){
		perror("malloc");
		free(l);
		return (NULL);	
	}

	return(l);
}
