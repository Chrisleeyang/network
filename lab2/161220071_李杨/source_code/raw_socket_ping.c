#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <sys/time.h>
#include <assert.h>
#include <netdb.h>
#include <errno.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define ICMP_HEAD_LEN 8
#define ICMP_DATA_LEN 56
#define ICMP_LEN (ICMP_HEAD_LEN + ICMP_DATA_LEN)
#define SEND_BUFFER_SIZE 128
#define RECV_BUFFER_SIZE 128
#define SEND_NUM 2
#define MAX_WAIT_TIME 3
#define WAIT_TIME 5
extern struct hostent *phost;
extern int sock_icmp;
extern char *IP;
void sendpacket(int sock_icmp, struct sockaddr_in *dest_addr,int nsend);

int recvpacket(int sock_icmp, struct sockaddr_in *dest_addr);

u_int16_t checksum(struct icmp *picmp);

void seticmp(u_int16_t seq);

int unpack(struct timeval *recvtime);

double getrtt(struct timeval *recvtime, struct timeval *sendtime);

void statistics( int signo);

//struct sockaddr_in dest_addr; //ipv4 socket address,for target address
struct timeval firstsendtime; //the begining time ,for caculating the gap of time
struct timeval lastrecvtime;
char sendbuffer[SEND_BUFFER_SIZE];
char recvbuffer[RECV_BUFFER_SIZE];
const char *eth_inf = "eth0";
void get_local_ip(char *ip)
{
	int sd;
	struct ifreq ifr;
	struct sockaddr_in sin;
	sd =socket(AF_INET,SOCK_DGRAM,0);
	if(sd == -1){
		perror("socket");
		return ;
	}
	strncpy(ifr.ifr_name,eth_inf,IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = 0;
	if(ioctl(sd,SIOCGIFADDR,&ifr)<0){
		perror("ioctl");
		return ;
	}
	
	memcpy(&sin,&ifr.ifr_addr,sizeof(sin));
	snprintf(ip,16,"%s",inet_ntoa(sin.sin_addr));
	return ;
}
	
u_int16_t checksum(struct icmp *picmp){
	u_int16_t *data = (u_int16_t*)picmp;
	int len = ICMP_LEN;
	u_int32_t sum = 0;
		
	while(len > 1)
	{	
		sum += *data++;
		len -= 2;
	}
	if(1 == len)
		sum+=*data;
	sum=(sum>>16)+(sum&0xffff);
	sum=(sum>>16)+(sum&0xffff);
	sum =~sum;

	return sum;
}

void seticmp(u_int16_t seq)
{
	struct icmp *picmp;
	struct timeval *ptime;
	
	picmp = (struct icmp*)sendbuffer;
	//code = 0 means that ask for return
	picmp->icmp_type = ICMP_ECHO;
	picmp->icmp_code = 0;
	picmp->icmp_cksum = 0;
	picmp->icmp_seq = seq;
	picmp->icmp_id = getpid();
	ptime = (struct timeval *)picmp->icmp_data;
	gettimeofday(ptime,NULL);
	picmp->icmp_cksum = checksum(picmp);

	if(1 == seq)
		firstsendtime = *ptime;
}

void sendpacket(int sock_icmp,struct sockaddr_in *dest_addr,int nsend)
{
	seticmp(nsend);
	if(sendto(sock_icmp,sendbuffer,ICMP_LEN,0,
			(struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) < 0)
	{
		perror("sendto");
		return ;
	}
}
//get the interval of sending and recving
double getrtt(struct timeval *recvtime,struct timeval *sendtime)
{
	struct timeval sub = *recvtime;
	if((sub.tv_usec -= sendtime->tv_usec) < 0)
	{	
		--(sub.tv_sec);
		sub.tv_usec += 1000000;
	}
	sub.tv_sec -= sendtime->tv_sec;
	return sub.tv_sec *1000.0 + sub.tv_usec/1000.0;
}

int unpack(struct timeval *recvtime)
{
	struct ip *IP = (struct ip *)recvbuffer;
	struct icmp *Icmp;
	int ipheadlen;
	double rtt;
	char localip[16];
	get_local_ip(localip);
	ipheadlen = IP->ip_hl << 2;
	Icmp = (struct icmp *)(recvbuffer + ipheadlen);
//judge if the packet is the reply of self sending packet	
	if((Icmp->icmp_type == ICMP_ECHOREPLY) && Icmp->icmp_id == getpid())
	{
		struct timeval *sendtime = (struct timeval*)Icmp->icmp_data;
		rtt = getrtt(recvtime,sendtime);
		printf("%s\n","send ping success!");		
		printf("from %s\nto %s\nrtt=%.1f ms\n",inet_ntoa(IP->ip_src),localip,rtt);
		return 0;
	}
	return -1;
}
//show the ending static

int recvpacket(int sock_icmp,struct sockaddr_in *dest_addr)
{	
	int recvbytes=0;
	int addrlen =sizeof(struct sockaddr_in);
	struct timeval recvtime;
	
	alarm(WAIT_TIME);
	if((recvbytes = recvfrom(sock_icmp, recvbuffer, RECV_BUFFER_SIZE,0,(struct sockaddr *)dest_addr, &addrlen)) < 0)
	{
		perror("recvfrom");
		return 0;
	}
	
	gettimeofday(&recvtime,NULL);
	lastrecvtime = recvtime;
	
	if(unpack(&recvtime) == -1)
	return -1;
}

struct hostent *phost = NULL;
int sock_icmp;
int nsend =1;
char *IP = NULL;

void call(int argc,char *argv[]){
	struct protoent *protocol;
	struct sockaddr_in dest_addr;

	in_addr_t inaddr;
	if(argc <2)
	{
		printf("usage : %s [hostname/IP address]\n",argv[0]);
		exit(EXIT_FAILURE);
	}	
	if((protocol = getprotobyname("icmp")) == NULL)
	{	
		perror("getprototoname");
		exit(EXIT_FAILURE);
	}

	if((sock_icmp = socket(PF_INET,SOCK_RAW,protocol->p_proto)) <0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}
	dest_addr.sin_family = AF_INET;
	
	if((inaddr = inet_addr(argv[1])) ==INADDR_NONE)
	{
		if((phost = gethostbyname(argv[1])) ==NULL)
		{	
			herror("gethostbyname()");
			exit(EXIT_FAILURE);
		}
		memmove(&dest_addr.sin_addr,phost->h_addr_list[0],phost->h_length);
	}
	else
		memmove(&dest_addr.sin_addr,&inaddr,sizeof(struct in_addr));
//	if(NULL !=phost)
//		printf("PING %s",phost->h_name);
//	else
//		printf("PING %s",argv[1]);
//	printf("(%s) %d bytes of data. \n", inet_ntoa(dest_addr.sin_addr),ICMP_LEN);	
	IP =argv[1];
		int unpack_ret;
		sendpacket(sock_icmp,&dest_addr,nsend);
		unpack_ret =recvpacket(sock_icmp,&dest_addr);
		if(-1 == unpack_ret)
			recvpacket(sock_icmp ,&dest_addr);
	
		sleep(1);
}

int main(int argc, char *argv[])
{
//	char localip[16];
//	get_local_ip(localip);
//	printf("local ip:%s\n",localip);
	call(argc,argv);
	return 0;
}
