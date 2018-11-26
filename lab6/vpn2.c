#include<sys/socket.h>
#include<linux/if_packet.h>
#include<net/if.h>
#include<sys/ioctl.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<net/if_arp.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<unistd.h>
#include<signal.h>
#include<sys/types.h>
#include<setjmp.h>
#include<netdb.h>
#include<memory.h>
#include<linux/if_ether.h>
#include<string.h>
#include<stdio.h>
#include<errno.h>

#define MAX_VPN_NUM 10
#define MAX_ROUTE_INFO 10
#define MAX_ARP_SIZE 10
#define MAX_DEVICE 10
#define MAX_BUFF_SZ 20480
struct route_info
{
	char destination[16];
	char gateway[16];
	char netmask[16];
	char interface[16];
} route_item[MAX_ROUTE_INFO];

int route_item_index = 0;

struct arp_table_item
{
	char ip_addr[16];
	char mac_addr[18];
} arp_table[MAX_ARP_SIZE];

int arp_item_index = 0;

struct device_item
{
	char interface[14];
	char mac_addr[18];
	int is_entrance;
} device[MAX_DEVICE];

int device_index = 0;

struct vpn_item
{
	char dest_ip[16];
	char netmask[16];
	char dest_vpn_ip[16];
} vpn[MAX_VPN_NUM];

int vpn_index = 0;

int sock_fd;
char sendbuffer[MAX_BUFF_SZ];
char recvbuffer[MAX_BUFF_SZ];
struct sockaddr_ll dest_addr;
struct sockaddr_ll src_addr;

//const char local_ip0[32] = "192.168.2.1";
//const char local_ip1[32] = "192.168.3.1";

void init_router_tab();
void init_arp_tab();
void init_device_tab();
void init_vpn_tab();

unsigned short check_sum(unsigned short *addr, int len);
int packet_analyze(const char *buffer, int len);
void myreply(int len);
void myroute(int index, int len);
int isInner(const char *buffer, int len);

void init_router_tab(){
	route_item_index = 2;
	const char dest0[4] = {10, 0, 1, 0};
	const char dest1[4] = {192, 168, 0, 0};
	//const char dest2[4] = {0xc0, 0xa8, 0x4, 0x0};
	const char netmask0[4] = {255, 255, 255, 0};
	const char netmask1[4] = {255, 255, 255, 0};
	//const char netmask2[4] = {0xff, 0xff, 0xff, 0x0};
	const char gateway0[4] = {10, 0, 1, 2};
	const char gateway1[4] = {172, 0, 0, 1};
	//const char gateway2[4] = {0xc0, 0xa8, 0x3, 0x2};
	const char interface0[10] = "eth0";
	const char interface1[10] = "eth1";
	memcpy(route_item[0].destination, dest0, 4);
	memcpy(route_item[1].destination, dest1, 4);
	//memcpy(route_item[2].destination, dest2, 4);
	
	memcpy(route_item[0].netmask, netmask0, 4);
	memcpy(route_item[1].netmask, netmask1, 4);
	//memcpy(route_item[2].netmask, netmask2, 4);

	memcpy(route_item[0].gateway, gateway0, 4);
	memcpy(route_item[1].gateway, gateway1, 4);
	//memcpy(route_item[2].gateway, gateway2, 4);

	memcpy(route_item[0].interface, interface1, 5);
	memcpy(route_item[1].interface, interface0, 5);
	//memcpy(route_item[2].interface, interface1, 5);
}

void init_arp_tab(){
	arp_item_index = 2;
	const char dest_ip0[4] = {10, 0, 1, 2};
	const char dest_ip1[4] = {172, 0, 0, 1};
	const char mac0[8] = {0x0, 0x0c, 0x29, 0x72, 0xac, 0xad};
	const char mac1[8] = {0x0, 0x0c, 0x29, 0x6b, 0xfe, 0x56};
	memcpy(arp_table[0].ip_addr, dest_ip0, 4);
	memcpy(arp_table[1].ip_addr, dest_ip1, 4);

	memcpy(arp_table[0].mac_addr, mac0, 6);
	memcpy(arp_table[1].mac_addr, mac1, 6);
}

void init_device_tab(){
	device_index = 2;
	const char interface0[16] = "eth0";
	const char interface1[16] = "eth1";
	memcpy(device[0].interface, interface0, 5);
	memcpy(device[1].interface, interface1, 5);

	struct ifreq req;
	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, interface0, IFNAMSIZ - 1);
	ioctl(sock_fd, SIOCGIFHWADDR, &req);
	memcpy(device[0].mac_addr, req.ifr_hwaddr.sa_data, ETH_ALEN);

	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, interface1, IFNAMSIZ - 1);
	ioctl(sock_fd, SIOCGIFHWADDR, &req);
	memcpy(device[1].mac_addr, req.ifr_hwaddr.sa_data, ETH_ALEN);
	device[0].is_entrance = 1;
	device[1].is_entrance = 0;
}

void init_vpn_tab(){
	vpn_index = 1;
	const char dest0[4] = {0xa, 0x0, 0x0, 0x0};//10.0.0.0
	const char netmask0[4] = {0xff, 0xff, 0xff, 0x0};//255.255.255.0
	const char dest_vpn0[4] = {0xc0, 0xa8, 0x0, 0x2};//192.168.0.2
	memcpy(vpn[0].dest_ip, dest0, 4);
	memcpy(vpn[0].netmask, netmask0, 4);
	memcpy(vpn[0].dest_vpn_ip, dest_vpn0, 4);
}

unsigned short check_sum(unsigned short *addr, int len){
	int left_bytes = len;
	int sum = 0;
	unsigned short res = 0;
	unsigned short *p = addr;
	while(left_bytes > 1){
		sum += *p;
		p++;
		left_bytes -= 2;
	}
	if(left_bytes == 1){
		*(unsigned char*)(&res) = *(unsigned char*)p;
		sum += res;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum += (sum >> 16);
	res = ~sum;
	return res;
}

int packet_analyze(const char *buffer, int len){
	if(len < 8) return -2;

	struct ip *ip0;
	//struct icmp *icmp0;

	ip0 = (struct ip*)buffer;
	int iphead_len = (ip0->ip_hl << 2);
	//icmp0 = (struct icmp*)(buffer + iphead_len);
	//int proto = ((char*)ip0 + 9)[0];
	//if(ip0->ip_p != IPPROTO_ICMP) return -2;
	//*****************************************************
	unsigned char *p;
	p = (unsigned char*)ip0 + 12;
	struct in_addr*dst_ip;
	printf("From: %d.%d.%d.%d\n", p[0], p[1], p[2], p[3]);
	printf("  To: %d.%d.%d.%d\n", p[4], p[5], p[6], p[7]);
	dst_ip = (struct in_addr*)(p + 4);
	//printf("%x\n", dst_ip[0].s_addr);
	//printf("%x\n", inet_addr(local_ip0));
	//reach destinaiton
	//if(dst_ip[0].s_addr == inet_addr(local_ip0) || dst_ip[0].s_addr == inet_addr(local_ip1))
	//	if(icmp0->icmp_type == ICMP_ECHO)
	//		return -1;
	//	else	return -2;
	//else if(ip0->ip_ttl == 0)	//time to live is 0
	//	return -2;
	//judge whether route or not
	//else
	{
		int i;
		for(i = 0; i < route_item_index; i++){
			unsigned int *in = (unsigned int*)(p + 4);
			unsigned int *a = (unsigned int*)route_item[i].destination;
			unsigned int *b = (unsigned int*)route_item[i].netmask;
			unsigned int temp = *b&*in;
			if(*a == temp)
				return i;
		}
		return -2;
	}	
}

void myroute(int index, int len){
	/*memcpy(sendbuffer, recvbuffer, len);
	struct ip *ip0;
	ip0 = (struct ip*)sendbuffer;
	ip0->ip_ttl --;
	ip0->ip_sum = 0;
	ip0->ip_sum = check_sum((unsigned short*)ip0, ip0->ip_hl << 2);
	*/
	int j;
	for(j = 0; j< arp_item_index; j++){
		if(route_item[index].gateway[0] == arp_table[j].ip_addr[0]
		&& route_item[index].gateway[1] == arp_table[j].ip_addr[1]
		&& route_item[index].gateway[2] == arp_table[j].ip_addr[2]
		&& route_item[index].gateway[3] == arp_table[j].ip_addr[3])
			break;
	}
	if(j >= arp_item_index){
		printf("No such arp item.\n");
		return;
	}
	
	struct ifreq req;
	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, route_item[index].interface, IFNAMSIZ - 1);
	ioctl(sock_fd, SIOCGIFINDEX, &req);
	
	dest_addr.sll_ifindex = req.ifr_ifindex;
	dest_addr.sll_family = AF_PACKET;
	dest_addr.sll_protocol = htons(ETH_P_IP);
	dest_addr.sll_halen = ETH_ALEN;
	memcpy(&dest_addr.sll_addr, arp_table[j].mac_addr, ETH_ALEN);
	if(sendto(sock_fd, sendbuffer, len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr))<0)
		printf("Route failed.\n");
	else printf("Route success.\n");
	printf("\n");
}

int isInner(const char *buffer, int len){
//0---is inner packet
//1---is vpn packet from outside
//2--- do not deal
	struct ip *ip0;
	ip0 = (struct ip*)buffer;
	unsigned char *p;
	p =(unsigned char*)ip0 + 12;
	if(p[0] == 10 && p[1] == 0
	&& p[2] == 1) 
		return 0;

	int i;
	for(i = 0; i < vpn_index; i++)
		if(p[0] == (unsigned char)vpn[i].dest_vpn_ip[0]
		&& p[1] == (unsigned char)vpn[i].dest_vpn_ip[1]
		&& p[2] == (unsigned char)vpn[i].dest_vpn_ip[2]
		&& p[3] == (unsigned char)vpn[i].dest_vpn_ip[3])
			return 1;
	return 2;
}

int repacket(int index1, int len){
	if(index1 == 0){
		memcpy(sendbuffer + 20, recvbuffer, len);
		struct ip *ip0;
		ip0 = (struct ip*)sendbuffer;
		ip0->ip_v = 4;
		ip0->ip_hl = 5;
		ip0->ip_tos = 0;
		ip0->ip_len = 0x6800;
		ip0->ip_id =0;
		ip0->ip_off = 0;
		ip0->ip_ttl = 10;
		ip0->ip_p = IPPROTO_ICMP;
		ip0->ip_sum = 0;
		ip0->ip_src.s_addr = inet_addr("172.0.0.2");
		//ip0->ip_dst.s_addr = inet_addr("192.168.0.2");
		int i;
		char *p = (char*)sendbuffer + 20 + 12 + 4;
		for(i = 0; i < vpn_index; i++){
			unsigned int a = *(unsigned int*)p;
			unsigned int b = *(unsigned int*)vpn[i].netmask;
			unsigned int c = *(unsigned int*)vpn[i].dest_ip;
			unsigned int tmp = a & b;
			if(tmp == c)
				memcpy(&ip0->ip_dst.s_addr, vpn[i].dest_vpn_ip, 4);
		}

		ip0->ip_sum = check_sum((unsigned short*)ip0, 20);
		return len + 20;
	}
	else if(index1 == 1){
		memcpy(sendbuffer, recvbuffer + 20, len - 20);
		return len - 20;
	}
	return -1;
}

int main(){
	sock_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if(sock_fd < 0){ printf("Socket failed.\n"); return -1;}
	init_router_tab();
	init_device_tab();
	init_arp_tab();
	init_vpn_tab();

	while(1){
		socklen_t addr_len = sizeof(src_addr);
		int a = -1;
		a=recvfrom(sock_fd,recvbuffer, MAX_BUFF_SZ, 0, (struct sockaddr *)&src_addr, &addr_len);
		if(a < 0) continue;
		int index1 = isInner(recvbuffer, a);
		printf("index1 = %d\n", index1);
		if(index1 == 2) continue;	
		else a = repacket(index1, a);

		int index = packet_analyze(sendbuffer, a);
		//printf("index= %d, a =%d\n", index, a);	
		//if(index == -1) //reply
			//myreply(a);
		//else 
		if(index >= 0 && index < route_item_index) //route, index为路由表索引
			myroute(index, a);
		
	}
}
