#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <assert.h>
#include <linux/ip.h>
#include <linux/in.h>
#define BUFFER_MAX 2048

int main(int argc,char* argv[]){
	int sock_fd;
	int n_read;
	char buffer[BUFFER_MAX];
	char *eth_head;
	char *ip_head;
	char *tcp_head;
	char *udp_head;
	char *icmp_head;
	unsigned char *p;
	unsigned char *type;

	if((sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0){
		printf("error create raw socket. \n");
		return -1;
	}
	while(1){
		n_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
		if(n_read < 42){
			printf("error when recv msg. \n");
			return -1;
		}
		eth_head = buffer;
		p = eth_head;
		printf("MAC address: %.2x : %02x : %02x : %02x : %02x : %02x ==> %.2x : %02x : %02x : %02x : %02x : %02x \n",
			p[6],p[7],p[8],p[9],p[10],p[11],
			p[0],p[1],p[2],p[3],p[4],p[5]);
		ip_head = eth_head + 14;
		type = eth_head + 12;
		if(type[1] == 0){	//ip
			unsigned char *temp;
			struct iphdr *ipheader = (struct iphdr *)(ip_head);
			temp = ip_head + 12;
			printf("IP: %d.%d.%d.%d ==> %d.%d.%d.%d \n",
				temp[0],temp[1],temp[2],temp[3],
				temp[4],temp[5],temp[6],temp[7]);
			temp = ip_head + 12;

			printf("Protocol:");
			switch(ipheader -> protocol){
				case IPPROTO_ICMP:printf("icmp\n");break;
				case IPPROTO_IGMP:printf("igmp\n");break;
				case IPPROTO_IPIP:printf("ipip\n");break;
				case IPPROTO_TCP:printf("tcp\n");break;
				case IPPROTO_UDP:printf("udp\n");break;
				default:printf("Pls query yourself.\n");
			}
			
			printf("Header Length: %d\n", ipheader->ihl);
			printf("Version: %d\n",ipheader->version);
			printf("Total Length: %d\n",ipheader->tot_len);
			printf("ID: %d\n",ipheader->id);
			printf("TTL: %d\n",ipheader->ttl);			
		}
		else if((type[1] == 6) || type[1] == 0x35){	//arp  or rarp
			unsigned char *temp=ip_head;
			if(type[1] == 6)
				printf("Protocol:ARP \n");
			else
				printf("Protocol:RARP \n");
			short arr = (p[0] << 8) + p[1];
			printf("format of heardware type: 0x%02x\n",arr);

			temp += 2;
			arr = (p[0] << 8) + p[1];
			printf("format of protocol type: 0x%04x\n",arr);
			
			temp += 2;
			arr = p[0];
			printf("length of hardware address :0x%d\n",arr);
			
			temp += 1;
			arr = p[0];
			printf("lengtg of protocol address :0x%d\n",arr);
			
			temp +=1;
			arr = (p[0] << 8) + p[1];
			if(type[1] ==6){
				if(arr == 1)
					printf("operation : ARP Request \n");
				else
					printf("operation : ARP Responce \n");
			}
			else{
				if(arr == 1)
					printf("operation :RARP Request \n");
				else
					printf("operation :RARP Request \n");
				}
			temp += 2;
			printf("Sender MAC address: %.2x:%02x:%02x:%02x:%02x:%02x\n",
				temp[0],temp[1],temp[2],temp[3],temp[4],temp[5]);
				
			temp += 6;
			printf("Sender IP address: %.2x:%02x:%02x:%02x \n",
				temp[0],temp[1],temp[2],temp[3]);

			temp += 4;
			printf("Target MAC address: %.2x:%02x:%02x:%02x:%02x:%02x\n",
				temp[0],temp[1],temp[2],temp[3],temp[4],temp[5]);
			
			temp += 6;
			printf("Target IP address: %.2x:%02X:%02x:%02x \n",
				temp[0],temp[1],temp[2],temp[3]);
		}
		else
			assert(0);
	}
	return -1;
}

		
