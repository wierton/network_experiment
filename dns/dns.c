#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct DNS_HEADER {
	uint16_t ID;        //random number identify this query
	uint8_t QR     : 1; //response(1), query(0)
	uint8_t opcode : 4; //0 for standard query, 1 for inverse query, 2 for server status
	uint8_t AA     : 1; //authoritative answer
	uint8_t TC     : 1; //truncation
	uint8_t RD     : 1; //recursion desired
	uint8_t RA     : 1; //recursion available
	uint8_t Z      : 3; //for future
	uint8_t rcode  : 4; // 0 no error
						// 1 format error:not a standard query
						// 2 server failure
						// 3 name error:given name may not exist
						// 4 not implemented
						// 5 refused
	uint16_t qdcount;   //number of queries
	uint16_t ancount;   //number of responses
	uint16_t nscount;   //may be no use
	uint16_t arcount;   //may be no use
};

struct Q_SEC {
	/*char Q_NAME[]; uncertain length*/
	uint16_t qtype;     // default to be 1
	uint16_t qclass;    // default to be 1
};

struct R_SEC {
	/*char NAME[]; uncertain length*/
	uint16_t type;
#define RR_TYPE_A		1 //a host address
#define RR_TYPE_NS		2 //an authoritative name server
#define RR_TYPE_MD		3 //a mail destination (Obsolete - use MX)
#define RR_TYPE_MF		4 //a mail forwarder (Obsolete - use MX)
#define RR_TYPE_CNAME	5 //the canonical name for an alias
#define RR_TYPE_SOA		6 //marks the start of a zone of authority
#define RR_TYPE_MB		7 //a mailbox domain name (EXPERIMENTAL)
#define RR_TYPE_MG		8 //a mail group member (EXPERIMENTAL)
#define RR_TYPE_MR		9 //a mail rename domain name(EXPERIMENTAL)
#define RR_TYPE_NUL		10 //a null RR (EXPERIMENTAL)
#define RR_TYPE_WKS		11 //a well known service description
#define RR_TYPE_PTR		12 //a domain name pointer
#define RR_TYPE_HINFO	13 //host information
#define RR_TYPE_MINFO	14 //mailbox or mail list information
#define RR_TYPE_MX		15 //mail exchange
#define RR_TYPE_TXT		16 //text strings
	uint16_t class;
#define CLASS_IN 1 //the Internet
#define CLASS_CS 2 //the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
#define CLASS_CH 3 //the CHAOS class
#define CLASS_HS 4 //Hesiod [Dyer 87]
	uint32_t ttl;
	uint16_t rdlength;
	struct in_addr raddr;
}__attribute__((packed));


void hexdump(const char *buf, int len) {
	int i, j;
	for(i = 0; i < len; i+=8) {
		printf("%02hx: ", i);
		for(j = i; j < i+8; j++) {
			printf(j<len?"%02hhx ":"   ", buf[j]);
		}

		printf("|");

		for(j = i; j < i+8; j++) {
			if(32 <= buf[j] && buf[j] <= 126)
				printf(j<len?"%c":" ", buf[j]);
			else
				printf(j<len?".":" ");
		}
		printf("|\n");
	}
}

int bufdump(const char *buf, int len, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	int bytes_write = vfprintf(stdout, format, ap);
	printf("----------------------------+--------+\n");
	hexdump(buf, len);
	printf("----------------------------+--------+\n");
	return bytes_write;
}

char *convert_domain_name_to_stream(const char *name) {
	int i, j = 1, p = 0;
	static char raw_domain[256];	
	for(i=0; name[i]; i++) {
		if(name[i]=='.') {
			raw_domain[p] = j-p-1;
			p = j;
			j++;
		}else{
			raw_domain[j++] = name[i];
		}
	}
	raw_domain[p] = j-p-1;
	raw_domain[j] = 0;
	return raw_domain;
}

char *read_domain_name_from_stream(const char *section_start) {
	int i, p=0, q=0;
	static char domain_name[256];
	for(;section_start[q];) {
		for(i=(uint8_t)section_start[q++];i;i--) {
			domain_name[p++]=section_start[q++];
		}
		domain_name[p++] = section_start[q]?'.':'\0';
	}
	return domain_name;
}

int contruct_request_stream(char *buf, char *domain_name) {
	struct DNS_HEADER *dns_header = (void *)buf;
	char* domain = convert_domain_name_to_stream(domain_name);
	int domain_len = strlen(domain)+1;
	struct Q_SEC* q_sec = (void*)buf + sizeof(struct DNS_HEADER) + domain_len;

	dns_header->ID = 45487;
	dns_header->QR = 1;
	dns_header->opcode = 0;
	dns_header->AA = 0;
	dns_header->TC = 0;
	dns_header->RD = 0;
	dns_header->RA = 0;
	dns_header->Z  = 0;
	dns_header->rcode = 0;
	dns_header->qdcount = htons(1);
	dns_header->ancount = 0;
	dns_header->nscount = 0;
	dns_header->arcount = 0;

	strcpy(buf + sizeof(struct DNS_HEADER), domain);
	q_sec->qtype = htons(1);
	q_sec->qclass = htons(1);

	return sizeof(struct DNS_HEADER)+domain_len+sizeof(struct Q_SEC);
}

void dumps_response_stream(const char *buf) {
	struct DNS_HEADER *dns_header = (void *)buf;
	dns_header->qdcount = ntohs(dns_header->qdcount);
	dns_header->ancount = ntohs(dns_header->ancount);

	switch(dns_header->rcode) {
		case 0:break;
		case 1:printf("format error\n");return;
		case 2:printf("server failure\n");return;
		case 3:printf("no such domain name\n");return;
		case 4:printf("server hasn't implemented this function\n");return;
		case 5:printf("server refused to answer.\n");return;
	}

	char *section_start = (char*)buf + sizeof(struct DNS_HEADER);

	/*ignore request content*/
	for(int i = dns_header->qdcount; i>0; i--) {
		section_start += strlen(section_start) + 1 + 2 + 2;
	}

	/*response record*/
	for(int i = dns_header->ancount; i>0; i--) {
		uint8_t domain_length = 0;
		char *domain_start = section_start;

		if((section_start[0]&0xc0)==0xc0) { 
			domain_start = (void*)buf+section_start[1];
			domain_length = 2;
		} else {
			domain_length = strlen(domain_start) + 1;
		}
		printf("%s", read_domain_name_from_stream(domain_start));
		struct R_SEC *response_section = (void*)section_start + domain_length;
		section_start += domain_length + sizeof(struct R_SEC);

		if(ntohs(response_section->type) == RR_TYPE_A) {
			printf(" ipv%d ", ntohs(response_section->rdlength));
			printf("%s\n", inet_ntoa(response_section->raddr));
		}

		if(ntohs(response_section->type) == RR_TYPE_CNAME) {
			domain_start = (void*)&response_section->raddr;
			domain_length = strlen(domain_start) + 1;
			printf("\t[CNAME]\n");
			section_start += domain_length - sizeof(response_section->raddr);
		}
	}
}

const uint8_t test_req[] = {
	0x9e, 0xb8, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
	0x08, 0x62, 0x69, 0x6c, 0x69, 0x62, 0x69, 0x6c,
	0x69, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
	0x00, 0x01
};

int main(int argc, char *argv[]) {
    int len;
	const int BUFSIZE = 1000;
    int client_sockfd;
    struct sockaddr_in remote_addr;
    char buf[BUFSIZE];
	int addr_len = sizeof(struct sockaddr_in);

    remote_addr.sin_family=AF_INET;
    //remote_addr.sin_addr.s_addr=inet_addr("114.212.11.66");
    remote_addr.sin_addr.s_addr=inet_addr("8.8.8.8");
    remote_addr.sin_port=htons(53);

    if((client_sockfd=socket(AF_INET,SOCK_DGRAM,0))<0) {
        perror("socket");
        return -1;
    }

	/*dns query*/
	for(int i = 1; i < argc; i++) {
		int stream_length = contruct_request_stream(buf, argv[i]);
		sendto(client_sockfd, buf, stream_length, 0, (struct sockaddr *)&remote_addr, addr_len);

		len=recvfrom(client_sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&remote_addr, &addr_len);
		//bufdump(buf, len, "recv %d bytes, dumps data:\n", len);
		dumps_response_stream(buf);
	}

    close(client_sockfd);

	return 0;
}
