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
	uint32_t type;
	uint32_t class;
	uint32_t ttl;
	uint16_t rdlength;
	struct in_addr raddr;
};

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

char *read_domain_name_from_stream(const char *stream) {
	int i, p=0, q=0;
	static char domain_name[256];
	for(;stream[q];) {
		for(i=(uint8_t)stream[q++];i;i--) {
			domain_name[p++]=stream[q++];
		}
		domain_name[p++] = stream[q]?'.':'\0';
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

	void *section_start = (void*)buf + sizeof(struct DNS_HEADER);
	printf("%s", read_domain_name_from_stream(section_start));
	struct R_SEC *response_section = section_start + strlen(section_start) + 1;
	printf(" ipv%d ", ntohs(response_section->rdlength)/4);
	printf("%s\n", inet_ntoa(response_section->raddr));
}

const uint8_t test_req[] = {
	0x9e, 0xb8, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
	0x08, 0x62, 0x69, 0x6c, 0x69, 0x62, 0x69, 0x6c,
	0x69, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
	0x00, 0x01
};

int main() {
    int len;
	const int BUFSIZE = 1000;
    int client_sockfd;
    struct sockaddr_in remote_addr;
    char buf[BUFSIZE];
	int addr_len = sizeof(struct sockaddr_in);

    remote_addr.sin_family=AF_INET;
    remote_addr.sin_addr.s_addr=inet_addr("114.212.11.66");
    remote_addr.sin_port=htons(53);

    if((client_sockfd=socket(AF_INET,SOCK_DGRAM,0))<0) {
        perror("socket");
        return -1;
    }

	int stream_length = contruct_request_stream(buf, "www.bilibili.com");

	bufdump(buf, stream_length, "send %d bytes, dumps data:\n", stream_length);
/*
	printf("captured by wireshark:\n");
	hexdump(test_req, sizeof(test_req));
	printf("--------------------------------------\n");
*/
	sendto(client_sockfd, buf, stream_length, 0, (struct sockaddr *)&remote_addr, addr_len);
	//len=sendto(client_sockfd, test_req, sizeof(test_req), 0, (struct sockaddr *)&remote_addr, addr_len);
	len=recvfrom(client_sockfd, buf, BUFSIZE, 0, (struct sockaddr *)&remote_addr, &addr_len);
	bufdump(buf, len, "recv %d bytes, dumps data:\n", len);
	dumps_response_stream(buf);
    close(client_sockfd);

	return 0;
}
