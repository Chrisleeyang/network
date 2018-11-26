#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/ioctl.h>

#include <unistd.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netdb.h>
#include <assert.h>
#define BUFFER_MAX 2048
#define ECHO_REQUEST 8

unsigned short check_sum(unsigned short *addr,int size){
	unsigned int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
	while(size > 1)
	{	
		sum += *w++;
		size-=2;
	}
	if(size == 1)
		sum+=*w;
	sum=(sum>>16) + (sum&0xffff);
	sum=(sum>>16)+(sum&0xffff);
	return (unsigned short)(~sum);
}

char ip_addr[16]="192.168.2.2";
unsigned char dest_mac_addr[6]={0x00,0x0c,0x29,0x34,0xc4,0xd2};
int main(int argc,char* argv[]){
	int s;
	if((s=socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP)))<1){
		printf("socket create failed\n");
		return -1;
	}
	char datagram[4096];
	
	struct ip *ip_header = (struct ip*)datagram;
	ip_header->ip_hl = 5;
	ip_header->ip_v=4;
	ip_header->ip_tos=0;
	ip_header->ip_len=sizeof(struct ip);
	ip_header->ip_id=1;
	ip_header->ip_off=0;
	ip_header->ip_ttl=255;
	ip_header->ip_p=1;
	ip_header->ip_src.s_addr=inet_addr(ip_addr);
	ip_header->ip_dst.s_addr=inet_addr(argv[1]);
	printf("%s\n%s\n",ip_addr,argv[1]);
	printf("src:%s\n",inet_ntoa(ip_header->ip_src));
	printf("dst:%s\n",inet_ntoa(ip_header->ip_dst));
	ip_header->ip_sum=0;
	ip_header->ip_sum=check_sum((unsigned short*)datagram,sizeof(struct ip));
	struct icmphdr *icmp_header=(struct icmphdr*)(datagram + ip_header->ip_len);
	icmp_header->type=8;
	icmp_header->code=0;
	icmp_header->un.echo.id=0;
	icmp_header->un.echo.sequence=0;
	icmp_header->checksum=0;
	icmp_header->checksum=check_sum((unsigned short*)icmp_header,sizeof(struct icmphdr));

	const char* if_name="eth0";
	struct sockaddr_in dest;
	struct hostent *host;
	struct ifreq req;
	memset(&req,0,sizeof(req));
	strncpy(req.ifr_name,if_name,IFNAMSIZ-1);
	ioctl(s,SIOCGIFINDEX,&req);
	int if_index=req.ifr_ifindex;
	
	struct sockaddr_ll dest_addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_halen = ETH_ALEN,
		.sll_ifindex = if_index,
	};
	memcpy((unsigned char*)&dest_addr.sll_addr,&dest_mac_addr,ETH_ALEN);
	int err = sendto(s,datagram,sizeof(struct ip)+sizeof(struct icmphdr),0,(struct sockaddr*)&dest_addr,sizeof(dest_addr));
	if(err<0){
		printf("send failed\n");
		return -1;
	}
	else
		printf("send success\n");
	//recv!
	int n_read=0;
	int sock_fd0;
	char buffer[2048];
	if((sock_fd0 = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP)))<0){
		printf("SOCKET CREATE ERROR\n");
		return -1;
	}
	struct sockaddr_ll addr;
	socklen_t addr_len =sizeof(addr);
	while(1){
		printf("waiting for data...\n");
		n_read=recvfrom(sock_fd0,buffer,2048,0,(struct sockaddr*)&addr,&addr_len);
  		
		//printf("recv!\n");
		ip_header=(struct ip*)buffer;
		if(strcmp(inet_ntoa(ip_header->ip_dst), "0.0.0.0")==0 ||strcmp(inet_ntoa(ip_header->ip_src),"0.0.0.0")==0)
			continue ;
		else{
		printf("recv!\n");
		icmp_header=(struct icmphdr*)(buffer + ip_header->ip_len);
		if(icmp_header->type==8){
			ip_header->ip_dst = ip_header->ip_src;
			inet_aton(ip_addr,&ip_header->ip_src);
			icmp_header->type=0;
			if_name="eth0";
			memset(&req,0,sizeof(req));
			strncpy(req.ifr_name,if_name,IFNAMSIZ-1);
			ioctl(s,SIOCGIFINDEX,&req);
			if_index=req.ifr_ifindex;
			
			struct sockaddr_ll dest_addr_reply ={
				.sll_family =AF_PACKET,
				.sll_protocol = htons(ETH_P_IP),
				.sll_halen = ETH_ALEN,
				.sll_ifindex = if_index,
			};
			
	memcpy((unsigned char*)&dest_addr_reply.sll_addr,&dest_mac_addr,ETH_ALEN);
	int err=sendto(s,buffer,sizeof(struct ip) + sizeof(struct icmphdr),0,(struct sockaddr *)&dest_addr_reply,sizeof(dest_addr_reply));
	printf("%d\n",icmp_header->type);
	printf("%x\n",icmp_header->checksum);
	if(err<0){
		printf("reply failed\n");
		return -1;
	}
	else{
		printf("reply success\n");
		break;
	}
	}
	else{
		printf("get reply\n");
	}}
	}
	return 0;
}
