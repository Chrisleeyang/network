#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define MAX_DEVICE 5
#define MAX_ROUTE_INFO 20
#define MAX_ARP_SIZE 20
#define BUFFER_SIZE 2048

struct Route_item
{
	char destination[16];
	char gateway[16];
	char netmask[16];
	char interface[16];
};

struct Arp_table_item
{
	char ip_addr[16];
	char mac_addr[18];
};

struct Device_item
{	
	char interface[14];
	char mac_addr[16];
	int index;
};

struct Route_item route_tb[MAX_ROUTE_INFO];
struct Arp_table_item arp_tb[MAX_ARP_SIZE];
struct Device_item device_tb[MAX_DEVICE];

//the sum of ......
int nr_route_info=0;
int nr_arp_table=0;
int nr_device=0;

void copy_string(char* dest, char* src){
	memcpy((void*)dest,(void*)src,strlen(src));
}

void strMac2hexMac(unsigned char* mac,char* c)
{
	int counter = 0;	
	int i;
	int d1=0;
	int d2=0;
	int len = strlen(c);
	for(i=0;i<len-1;i++){
		if(c[i]!=':'){
			if(c[i]>97)
				d1=(c[i]-97+10);
			else
				d1=(c[i]-48);

			if(c[i+1]>97)
				d2=(c[i+1]-97+10);
			else
				d2=(c[i+1]-48);

			mac[counter]=d1*16+d2;
			i++;
			counter++;
		}
	}
	return ;
}

#define addr2int(in_addr) inet_addr(inet_ntoa(in_addr))

char local_ip_0[16] = "192.168.2.1";
char local_ip_1[16] = "192.168.4.1";

void initialize(){
	char filename_table[] = "router_table";
	FILE * fp=NULL;
	if((fp=fopen(filename_table,"r"))==NULL)
		perror("read route table FAILED\n");
	char router_name[7];
		copy_string(router_name,"router0");
	char buf[80];
	int num=0,i;
	fscanf(fp,"%s\n",buf);	
	fscanf(fp, "%d\n",&nr_route_info);
//	printf("%d\n",nr_route_info);
	for(i=0;i<nr_route_info;i++){
		fscanf(fp,"%s %s %s %s",route_tb[i].destination,route_tb[i].gateway,route_tb[i].netmask,route_tb[i].interface);
//		printf("%s\n",route_tb[i].destination);
//		printf("%s\n",route_tb[i].gateway);
}
	fscanf(fp,"%d\n",&nr_arp_table);
//	printf("%d\n",nr_arp_table);
	char mac_addr_str[18];
	for(i =0 ;i<nr_arp_table;i++)
	{	
		fscanf(fp,"%s %s",arp_tb[i].ip_addr,mac_addr_str);
//		printf("%s\n",arp_tb[i].ip_addr);
//		printf("%s\n",mac_addr_str);
		strMac2hexMac(arp_tb[i].mac_addr,mac_addr_str);
//  		int j;
//		for(j=0;j<6;j++)
//		printf("%02x\n",arp_tb[i].mac_addr[j]);
	}
}

int main(void){
	printf("initializing .....\n");
	initialize();
	printf("initialize done\n");

	int sock_fd;
	if((sock_fd=socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP))) < 0)
	{	
		printf("socket create failed\n");
		return -1;
	}
	
	char buffer[BUFFER_SIZE];
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	struct ether_head* eth_header;
	struct ip* ip_header;
	struct icmphdr* icmp_header;
	struct sockaddr_ll dest_addr;
	while(1){
		printf("waiting for data..\n");
		int n_read = recvfrom(sock_fd,buffer,BUFFER_SIZE,0,(struct sockaddr*)&addr,&addr_len);
		printf("recv!\n");
		
		ip_header = (struct ip*)buffer;
		icmp_header = (struct icmphdr*)(buffer + ip_header->ip_len);
		if(strcmp(inet_ntoa(ip_header->ip_src),"127.0.0.1") != 0){
			printf("src : %s\n",inet_ntoa(ip_header->ip_src));
			printf("dst : %s\n",inet_ntoa(ip_header->ip_dst));
		}//judge if is ping the router
		if(strcmp(inet_ntoa(ip_header->ip_dst),local_ip_0) == 0){
			ip_header->ip_dst = ip_header->ip_src;
			inet_aton(local_ip_0, &ip_header->ip_src);
			icmp_header->type = 0;
		}else if(strcmp(inet_ntoa(ip_header->ip_dst),local_ip_1)==0){
			ip_header->ip_dst = ip_header->ip_src;
			inet_aton(local_ip_1,&ip_header->ip_src);
			icmp_header->type=0;
		}
		//send forward
		int i;
		for(i=0;i<nr_route_info;i++){
			int netmask = inet_addr(route_tb[i].netmask);
			int network_number_1=inet_addr(route_tb[i].destination) &netmask;
			int network_number_2=addr2int(ip_header->ip_dst) &netmask;
			
			if(network_number_1==network_number_2){
				const char* if_name=route_tb[i].interface;
				struct ifreq req;
				memset(&req,0,sizeof(req));
				strncpy(req.ifr_name,if_name,IFNAMSIZ-1);
				ioctl(sock_fd,SIOCGIFINDEX,&req);
				int if_index = req.ifr_ifindex;
				
				int j;
				int local = 0;
				
				if(strcmp(route_tb[i].gateway,local_ip_0)==0 || strcmp(route_tb[i].gateway,local_ip_1) == 0)
					local = 1;
				for(j=0;j<nr_arp_table;j++){//local == 0 ,then get the next router mac
					if(((local==0) &&inet_addr(arp_tb[j].ip_addr) == inet_addr(route_tb[i].gateway)) || ((local ==1) && inet_addr(arp_tb[j].ip_addr) == addr2int(ip_header->ip_dst))){
						dest_addr.sll_family = AF_PACKET;
						dest_addr.sll_protocol = htons(ETH_P_IP);
						dest_addr.sll_halen =ETH_ALEN;
						dest_addr.sll_ifindex = if_index;
					
					memcpy(&dest_addr.sll_addr,&arp_tb[j].mac_addr,ETH_ALEN);
				}
			}
			int err = sendto(sock_fd,buffer,ip_header->ip_len + sizeof(struct icmphdr),0,(struct sockaddr*)&dest_addr,sizeof(dest_addr));
			if(err < 0)
				printf("send error\n");
			else
				printf("send success\n");
			break;
		}
	}
	}
	return 0;
}
