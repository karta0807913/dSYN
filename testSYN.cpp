#define BUFFER_SIZE 65535
#define SOURCE_PORT 8234
#define TARGET_PORT 8234

#include<iostream>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<string.h>	//memcpy
#include<strings.h> //bzero function
#include<unistd.h> 	//close function
#include<stdlib.h>	//exit  function

using namespace std;

typedef int SOCKET;

SOCKET rawSocket;

typedef struct _iphdr
{
	unsigned char h_lenver;			//Internet Portocol Version (8 bit)
	unsigned char tos;				//Type of service(not used) (8 bit)
	unsigned short total_len;		//data + header length (16 bit)
	unsigned short ident;			//if you want to cut the package (16 bit)
	unsigned short frag_and_flags;
	unsigned char ttl;				//time to live (8bit)
	unsigned char proto;			/*portocol(4 bit)
									 (e.g. 1 =ICMP, 2 = IGMP, 6 = TCP, 17 = UDP)
									  */
	unsigned short checksum;		//check number(16 bit)(1's cpmplement)
	unsigned int sourceIP;			//this compter ip address(32 bit)
	unsigned int targetIP;			//the target address(32 bit)
	
}IP_HEADER;

typedef struct _tcphdr
{
	unsigned short sourcePort;
	unsigned short targetPort;
	unsigned int sequenceNum;
	unsigned int ackNumber;
	unsigned char th_lenres;
	unsigned char th_flag;
	unsigned short window;
	unsigned short checksum;
	unsigned short urp;
}TCP_HEADER;

typedef struct Pseudo_Header
{
	unsigned long sourceIP;
	unsigned long targetIP;
	unsigned char mbz;
	unsigned char portocol;
	unsigned short tcp_length;
}psd_Header;

psd_Header psdhdr;

void haveError(string str);
void setIPHeader(IP_HEADER &iphdr, unsigned int sourceIP,unsigned int targetIP);
void setTCPHeader(TCP_HEADER &tcphdr, IP_HEADER &iphdr, int sourcePort);
unsigned short checkSum(unsigned short *buffer, int size);
int main(int argc, char **argv){
	char recvBuf[BUFFER_SIZE];
	IP_HEADER iphdr;
	TCP_HEADER tcphdr;
	struct sockaddr_in serv_addr;
	struct addrinfo server;
	struct addrinfo *target;
	//create socket
	rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(rawSocket < 0){
		haveError("Socket Error");
	}
	
	server.ai_family 	= AF_INET;
	
	//get ip adress
	int errorCode = getaddrinfo("127.0.0.1", "8234",&server, &target);
	if(errorCode != 0){
		haveError("get addr error " + errorCode);
		return 0;
	}
	
	for(struct addrinfo *i = target; i != NULL; i = i->ai_next){
		sockaddr_in *address = (sockaddr_in*) i->ai_addr;
		cout << inet_ntoa((*address).sin_addr) << endl;	
	}

	//test sentto functoin
	
	struct sockaddr_in *dest = (sockaddr_in*) target->ai_addr;
	
	setIPHeader(iphdr, (*dest).sin_addr.s_addr, (*dest).sin_addr.s_addr);
	setTCPHeader(tcphdr, iphdr, SOURCE_PORT);
	
	int bOpt = 1;
	errorCode = setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, (char*)&bOpt,
				 sizeof(bOpt));
	if(errorCode < 0){
		haveError("set socket faild");
	}
	
	memcpy(recvBuf, &iphdr, sizeof(iphdr));
	memcpy(recvBuf + sizeof(iphdr), &tcphdr, sizeof(tcphdr));

	sockaddr_in *address = (sockaddr_in*) target->ai_addr;
	errorCode = sendto(rawSocket, recvBuf, sizeof(iphdr) + sizeof(tcphdr),
						0, (sockaddr*) address, sizeof(sockaddr));
	if(errorCode < 0){
		haveError("send msg error");
	}
	
	//sentto function end
	
	SOCKET listener = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	
	//test recv function
	
	bzero((char *) &serv_addr, sizeof(serv_addr));
	sockaddr_in *i 	= (sockaddr_in*)target->ai_addr;
	i->sin_family 	= AF_INET;
	i->sin_port		= htons(SOURCE_PORT);
	
	errorCode = bind(rawSocket, (sockaddr*)i, sizeof(sockaddr));
	if(errorCode != 0){
		haveError("bind() faild");
	}

	cout << "bind() success" << endl;
	
	for(;;){
		errorCode = recv(rawSocket, recvBuf, sizeof(recvBuf),0);
		if(errorCode < 0){
			cout << errorCode << endl;
			haveError("Listen Faild");
		}
		if(recvBuf != NULL){
			for(int index = 0; index < errorCode; ++index)
				cout << recvBuf[index];
			break;
		}
	}

	///end test 
	
	cout << "closing socket" << endl;
	close(rawSocket);
	cout << "closed" << endl;

	return 0;
}

void haveError(string str){
	cout << str << endl;
	close(rawSocket);
	exit(1);
}

void setIPHeader(IP_HEADER &iphdr, unsigned int sourceIP, unsigned int targetIP)
{
	cout << "setting ip header..." << endl;
	iphdr.h_lenver 		= (4 << 4 | sizeof(iphdr) / sizeof(unsigned long));
	iphdr.tos			= 0;
	iphdr.total_len 	= htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER));
	iphdr.ident			= 1;
	iphdr.frag_and_flags= 0;
	iphdr.ttl			= 128;
	iphdr.proto			= IPPROTO_TCP;
	iphdr.checksum		= 0;
	iphdr.sourceIP		= sourceIP;
	iphdr.targetIP		= targetIP;
	cout << "finish" << endl;
}

void setTCPHeader(TCP_HEADER &tcphdr, IP_HEADER &iphdr, int sourcePort){
	
	tcphdr.sourcePort 	= htons(sourcePort);
	tcphdr.th_lenres	= (sizeof(TCP_HEADER) / 4 << 4 | 0);
	tcphdr.window		= htons(16384);
	tcphdr.targetPort	= htons(TARGET_PORT);
	tcphdr.sequenceNum	= htonl(0x28376839);
	tcphdr.ackNumber	= 0;
	tcphdr.th_flag		= 2;
	tcphdr.urp			= 0;
	tcphdr.checksum		= 0;

	unsigned char sum[255];
	//TCP pseudo header
	psdhdr.sourceIP 	= iphdr.sourceIP;
	psdhdr.targetIP		= iphdr.targetIP;
	psdhdr.mbz			= 0;
	psdhdr.portocol		= IPPROTO_TCP;
	psdhdr.tcp_length	= htons(sizeof(TCP_HEADER));
	
	//tcp header check number
	memcpy(sum, &psdhdr, sizeof(psdhdr));
	memcpy(sum + sizeof(psdhdr), &tcphdr, sizeof(tcphdr));
	tcphdr.checksum	= checkSum((unsigned short*)sum, 
								sizeof(tcphdr) + sizeof(psdhdr));
	
	//ip header check number
	int offset = 0;
	memcpy(sum, &iphdr, sizeof(iphdr));
	offset += sizeof(iphdr);
	memcpy(sum + offset, &tcphdr, sizeof(tcphdr));
	offset += sizeof(tcphdr);
	memset(sum + offset, 0, 4);
	iphdr.checksum = checkSum((unsigned short*)sum, offset);
}

unsigned short checkSum(unsigned short *buffer, int size)
{
	unsigned long cksum = 0;

	while(size > 1){
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if(size != 0){
		cksum += *(unsigned char*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}

