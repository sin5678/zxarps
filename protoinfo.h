//////////////////////////////////////////////////
// protoinfo.h文件

/*

定义协议格式
定义协议中使用的宏

*/


#ifndef __PROTOINFO_H__
#define __PROTOINFO_H__


#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_ARP   0x0806
#define	ARP_REPLY	 0x0002			/* ARP reply */
#define ARPHRD_ETHER 	1
#define ARP_LEN		 48

#define HEAD_LEN           54
#define TCP_MAXLEN       1460
#define PACKET_MAXLEN    1514
// 协议
#define PROTO_TCP     0x6
#define PROTO_UDP     0x11

typedef BYTE u_char;
typedef BYTE UCHAR;

#pragma pack(push, 1)//取消内存大小自动对齐

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;


typedef struct _ETHeader         // 14字节的以太头
{
	UCHAR	dhost[6];			// 目的MAC地址destination mac address
	UCHAR	shost[6];			// 源MAC地址source mac address
	USHORT	type;				// 下层协议类型，如IP（ETHERTYPE_IP）、ARP（ETHERTYPE_ARP）等
} ETHeader, *PETHeader;

typedef struct _ARPHeader		// 28字节的ARP头
{
	USHORT	hrd;				//	硬件地址空间，以太网中为ARPHRD_ETHER
	USHORT	eth_type;			//  以太网类型，ETHERTYPE_IP ？？
	UCHAR	maclen;				//	MAC地址的长度，为6
	UCHAR	iplen;				//	IP地址的长度，为4
	USHORT	opcode;				//	操作代码，ARPOP_REQUEST为请求，ARPOP_REPLY为响应
	UCHAR	smac[6];			//	源MAC地址
	ULONG	saddr;			//	源IP地址
	UCHAR	dmac[6];			//	目的MAC地址
	ULONG	daddr;			//	目的IP地址
} ARPHeader, *PARPHeader;

typedef struct _IPHeader		// 20字节的IP头
{
    UCHAR     iphVerLen;      // 版本号和头长度（各占4位）
    UCHAR     ipTOS;          // 服务类型 
    USHORT    ipLength;       // 封包总长度，即整个IP报的长度
    USHORT    ipID;			  // 封包标识，惟一标识发送的每一个数据报
    USHORT    ipFlags;	      // 标志
    UCHAR     ipTTL;	      // 生存时间，就是TTL
    UCHAR     ipProtocol;     // 协议，可能是TCP、UDP、ICMP等
    USHORT    ipChecksum;     // 校验和
	union {
		unsigned int   ipSource;
		ip_address ipSourceByte;
	};
	union {
		unsigned int   ipDestination;
		ip_address ipDestinationByte;
	};
} IPHeader, *PIPHeader; 

typedef struct _TCPHeader		// 20字节的TCP头
{
	USHORT	sourcePort;			// 16位源端口号
	USHORT	destinationPort;	// 16位目的端口号
	ULONG	sequenceNumber;		// 32位序列号
	ULONG	acknowledgeNumber;	// 32位确认号
	UCHAR	dataoffset;			// 高4位表示数据偏移
	UCHAR	flags;				// 6位标志位
								//FIN - 0x01
								//SYN - 0x02
								//RST - 0x04 
								//PUSH- 0x08
								//ACK- 0x10
								//URG- 0x20
								//ACE- 0x40
								//CWR- 0x80

	USHORT	windows;			// 16位窗口大小
	USHORT	checksum;			// 16位校验和
	USHORT	urgentPointer;		// 16位紧急数据偏移量 
} TCPHeader, *PTCPHeader;

typedef struct _udphdr	//定义UDP首部 
{ 
	unsigned short uh_sport;	//16位源端口 
	unsigned short uh_dport;	//16位目的端口 
	unsigned short uh_len;	//16位长度 
	unsigned short uh_sum;	//16位校验和 
}UDPHEADER, *PUDPHeader;

typedef struct _ACKPacket
{
	ETHeader	eh;
	IPHeader	ih;
	TCPHeader	th;
}ACKPacket;
/*
typedef struct _psd
{
	unsigned int ipSource;
	unsigned int ipDestination;
	unsigned char zero;
	unsigned char ipProtocol;
	unsigned short tcp_len;
}PSD,*PPSD;
*/
typedef struct _psd
{
    unsigned int   saddr;
    unsigned int   daddr;
    char           mbz;
    char           ptcl;
    unsigned short udpl;
}PSD,*PPSD;

typedef struct _dns
{
  unsigned short id;  //标识，通过它客户端可以将DNS的请求与应答相匹配；

  unsigned short flags;  //标志：[QR | opcode | AA| TC| RD| RA | zero | rcode ]
                         //1 & htons(0x8000)
                         //4 & htons(0x7800)
                         //1 & htons(0x400)
                         //1 & htons(0x200)
                         //1 & htons(0x100)
                         //1 & htons(0x80)
                         //3
                         //4 & htons(0xF)

  unsigned short quests;  //问题数目；

  unsigned short answers;  //资源记录数目；

  unsigned short author;  //授权资源记录数目；

  unsigned short addition;  //额外资源记录数目；

}TCPIP_DNS,*PDNS;
//在16位的标志中：QR位判断是查询/响应报文，opcode区别查询类型，AA判断是否为授权回答，TC判断是否可截断，RD判断是否期望递归查询，RA判断是否为可用递归，zero必须为0，rcode为返回码字段。

//DNS查询数据报：
typedef struct query
{
  //unsigned char  *name;  //查询的域名,不定长,这是一个大小在0到63之间的字符串；

  unsigned short type;  //查询类型，大约有20个不同的类型

  unsigned short classes;  //查询类,通常是A类既查询IP地址。

}QUERY,*PQUERY;

//DNS响应数据报：
typedef struct response
{
  unsigned short name;   //查询的域名

  unsigned short type;  //查询类型

  unsigned short classes;  //类型码

  unsigned int   ttl;  //生存时间

  unsigned short length;  //资源数据长度

  unsigned int   addr;  //资源数据

}RESPONSE,*PRESPONSE;


#pragma pack(pop)

#endif // __PROTOINFO_H__

