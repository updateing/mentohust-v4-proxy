/* -*- Mode: C; tab-width: 4; -*- */
/*
* Copyright (C) 2009, HustMoon Studio
*
* 文件名称：myconfig.c
* 摘	要：初始化认证参数
* 作	者：HustMoon@BYHH
* 邮	箱：www.ehust@gmail.com
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#else
static const char *VERSION = "0.3.1";
static const char *PACKAGE_BUGREPORT = "http://code.google.com/p/mentohust/issues/list";
static const char *CREDIT_ADDITION = "V4 Algorithm by Hu Yunrui, new features by Hamster Tian";
#endif

#include "myconfig.h"
#include "i18n.h"
#include "myini.h"
#include "myfunc.h"
#include "dlfunc.h"
#include "logging.h"
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <termios.h>

#ifndef NO_GETOPT_LONG
#include <getopt.h>
#endif

#define ACCOUNT_SIZE		65	/* 用户名密码长度*/
#define NIC_SIZE			16	/* 网卡名最大长度 */
#define SERVICE_SIZE		127	/* 服务名最大长度 */
#define MAX_PATH			255	/* FILENAME_MAX */
#define D_TIMEOUT			8	/* 默认超时间隔 */
#define D_ECHOINTERVAL		30	/* 默认心跳间隔 */
#define D_RESTARTWAIT		15	/* 默认重连间隔 */
#define D_STARTMODE			0	/* 默认组播模式 */
#define D_DHCPMODE			0	/* 默认DHCP模式 */
#define D_DAEMONMODE		0	/* 默认daemon模式 */
#define D_MAXFAIL			8	/* 默认允许失败次数 */
#define D_RESTARTONLOGOFF	1	/* 默认掉线后重连 */
#define D_MAXRETRIES		0	/* 默认认证服务器无响应时允许重试的次数,0为无限 */
#define D_PROXYMODE     	0	/* 默认禁用代理模式 */
#define D_SUCCESS_COUNT    	1	/* 默认代理需求成功次数 */
#define D_SERVICENAME		"internet"	/* 默认要登录的服务名 */

#define ECHOFLAGS (ECHO|ECHOE|ECHOK|ECHONL)    /* 控制台输入密码时的模式*/

#ifdef MAC_OS
static const char *D_DHCPSCRIPT = "dhcping -v -t 15";	/* 默认DHCP脚本 */
#else
static const char *D_DHCPSCRIPT = "dhclient";	/* 默认DHCP脚本 */
#endif
static const char *CFG_FILE = "/etc/mentohust.conf";	/* 配置文件 */
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)	/* 创建掩码 */

#ifndef NO_NOTIFY
#define D_SHOWNOTIFY		5	/* 默认Show Notify模式 */
int showNotify = D_SHOWNOTIFY;	/* 显示通知 */
#endif

extern int bufType;	/*0内置xrgsu 1内置Win 2仅文件 3文件+校验*/
extern u_char version[];	/* 版本 */
char userName[ACCOUNT_SIZE] = "";	/* 用户名 */
char password[ACCOUNT_SIZE] = "";	/* 密码 */
char nic[NIC_SIZE] = "";	/* 发出认证数据包的网卡名（WAN） */
char nicLan[NIC_SIZE] = "";	/* 监听认证数据包的网卡名（LAN，仅在代理模式下使用） */
char dataFile[MAX_PATH] = "";	/* 数据文件 */
char dhcpScript[MAX_PATH] = "";	/* DHCP脚本 */
char serviceName[SERVICE_SIZE] = ""; /* 需要登陆到的服务名 */
char pidFile[MAX_PATH] = "/var/run/mentohust.pid"; /* 锁文件 */
u_int32_t ip = 0;	/* 本机IP */
u_int32_t mask = 0;	/* 子网掩码 */
u_int32_t gateway = 0;	/* 网关 */
u_int32_t dns = 0;	/* DNS */
u_int32_t pingHost = 0;	/* ping */
u_char localMAC[6];	/* 本机MAC（WAN） */
u_char destMAC[6];	/* 服务器MAC */
unsigned timeout = D_TIMEOUT;	/* 超时间隔 */
unsigned echoInterval = D_ECHOINTERVAL;	/* 心跳间隔 */
unsigned restartWait = D_RESTARTWAIT;	/* 失败等待 */
unsigned startMode = D_STARTMODE;	/* 组播模式 */
unsigned dhcpMode = D_DHCPMODE;	/* DHCP模式 */
unsigned maxFail = D_MAXFAIL;	/* 允许失败次数 */
unsigned restartOnLogOff = D_RESTARTONLOGOFF; /* 掉线后是否重连 */
unsigned maxRetries = D_MAXRETRIES; /* 认证服务器无响应时最大重试次数 */
unsigned proxyMode = D_PROXYMODE;	/* 代理模式开关 */
unsigned proxyRequireSuccessCount = D_SUCCESS_COUNT; /* 关闭监听前需要收到的Success次数 */
pcap_t *hPcap = NULL;	/* 用于发出认证数据包的Pcap句柄（WAN） */
pcap_t *hPcapLan = NULL;	/* 用于监听认证数据包的Pcap句柄（LAN，仅在代理模式下使用） */
int lockfd = -1;	/* 锁文件描述符 */

static int readConfigFile(int *daemonMode);	/* 读取配置文件来初始化 */
static void readArg(char argc, char **argv, int *saveFlag, int *exitFlag, int *daemonMode);	/* 读取命令行参数来初始化 */
static void showHelp(const char *fileName);	/* 显示帮助信息 */
static int askSelectAdapter();	/* 让用户选择网卡名 */
static void printConfig();	/* 显示初始化后的认证参数 */
static int openPcap();	/* 初始化pcap、设置过滤器 */
static void saveConfig(int daemonMode);	/* 保存参数 */
static void applyDaemonMode(int daemonMode); /* 应用是否后台的设置 */
static void checkRunningInstance(int exitFlag);	/* 检测是否有已运行的实例，并按要求终止 */
static void lockPidFile();	/* PID文件上锁 */
#ifdef __UCLIBC__
static int uclibc_daemon(int nochdir, int noclose); /* uClibc中daemon后pthread_create阻塞的解决办法 */
#endif

#ifndef NO_ENCODE_PASS
static const unsigned char base64Tab[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};
static const char xorRuijie[] = {"~!:?$*<(qw2e5o7i8x12c6m67s98w43d2l45we82q3iuu1z4xle23rt4oxclle34e54u6r8m"};

static int encodePass(char *dst, const char *osrc) {
    unsigned char in[3], buf[70];
	unsigned char *src = buf;
	int sz = strlen(osrc);
    int i, len;
	if (sizeof(xorRuijie) < sz)
		return -1;
	for(i=0; i<sz; i++)
		src[i] = osrc[i] ^ xorRuijie[i];
    while (sz > 0) {
        for (len=0, i=0; i<3; i++, sz--) {
			if (sz > 0) {
				len++;
				in[i] = src[i];
            } else in[i] = 0;
        }
        src += 3;
        if (len) {
			dst[0] = base64Tab[ in[0] >> 2 ];
			dst[1] = base64Tab[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
			dst[2] = len > 1 ? base64Tab[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=';
			dst[3] = len > 2 ? base64Tab[ in[2] & 0x3f ] : '=';
            dst += 4;
        }
    }
    *dst = '\0';
	return 0;
}

static int decodePass(char *dst, const char *src) {
	unsigned esi = 0, idx = 0;
	int i=0, j=0, equal=0;
	for(; src[i]!='\0'; i++) {
		if (src[i] == '=') {
			if (++equal > 2)
				return -1;
		} else {
			for(idx=0; base64Tab[idx]!='\0'; idx++) {
				if(base64Tab[idx] == src[i])
					break;
			}
			if (idx == 64)
				return -1;
			esi += idx;
		}
		if(i%4 == 3) {
			dst[j++] = (char)(esi>>16);
			if(equal < 2)
				dst[j++] = (char)(esi>>8);
			if(equal < 1)
				dst[j++] = (char)esi;
			esi = 0;
			equal = 0;
		}
		esi <<= 6;
	}
	if (i%4!=0 || sizeof(xorRuijie)<j)
		return -1;
	for(i=0; i<j; i++)
		dst[i] ^= xorRuijie[i];
	dst[j] = '\0';
	return 0;
}
#endif

int getpasswd(char  passwd[])
{
    int ret=0;
	struct termios termios_buf;
	
	if(tcgetattr(STDIN_FILENO,&termios_buf)!=0)
	{
		perror(_("获取终端属性失败"));
		return -1;
	}
	
	termios_buf.c_lflag &= ~ECHOFLAGS;
	
	if(tcsetattr(STDIN_FILENO,TCSAFLUSH,&termios_buf)!=0)
	{
		perror(_("设置终端属性失败"));
		return -2;
	}
	
	if(passwd!=NULL){
	    ret=scanf("%s", passwd);
	}
	
    //printf("\nYour passwd is %s\n",passwd);

	if(tcgetattr(STDIN_FILENO,&termios_buf)!=0)
	{
		perror(_("获取终端属性失败"));
		return -1;
	}
	
	termios_buf.c_lflag |= ECHOFLAGS;
	
	if(tcsetattr(STDIN_FILENO,TCSAFLUSH,&termios_buf)!=0)
	{
		perror(_("设置终端属性失败"));
		return -2;
	}
	
	return ret>0?0:1;
}


void initConfig(int argc, char **argv)
{
	int saveFlag = 0;	/* 是否需要保存参数 */
	int exitFlag = 0;	/* 0Nothing 1退出 2重启 */
	int daemonMode = D_DAEMONMODE;	/* 是否后台运行 */
	void customizeServiceName(char* service); /* myconfig.c中用于更改服务名的函数 */

	/* 只在标准输出上打印 */
	printf(_("\n欢迎使用MentoHUST\t版本: %s\n"
			"Copyright (C) 2009-2010 HustMoon Studio\n"
			"人到华中大，有甜亦有辣。明德厚学地，求是创新家。\n"
			"%s\n"
			"Bug report to %s\n\n"), VERSION, CREDIT_ADDITION, PACKAGE_BUGREPORT);

	/* 环境初始化任务都提前到认证任务之前完成 */
	set_log_destination(LOG_TO_CONSOLE);
	saveFlag = (readConfigFile(&daemonMode)==0 ? 0 : 1);
	readArg(argc, argv, &saveFlag, &exitFlag, &daemonMode);
	checkRunningInstance(exitFlag);
	applyDaemonMode(daemonMode);
	lockPidFile();

	/* 只在日志上打印 */
	print_log_raw("========================\n", VERSION);
	print_log(_(">> MentoHUST %s 已启动\n"), VERSION);

#ifndef NO_DYLOAD
	if (load_libpcap() == -1) {
#ifndef NO_NOTIFY
		if (showNotify && show_notify(_("MentoHUST - 错误提示"),
			_("载入libpcap失败, 请检查该库文件！"), 1000*showNotify) < 0)
			showNotify = 0;
#endif
		exit(EXIT_FAILURE);
	}
#endif
	if (nic[0] == '\0')
	{
		saveFlag = 1;
		if (askSelectAdapter() == -1) {	/* 找不到（第一块）网卡？ */
#ifndef NO_NOTIFY
		if (showNotify && show_notify(_("MentoHUST - 错误提示"),
			_("找不到网卡！"), 1000*showNotify) < 0)
			showNotify = 0;
#endif
			exit(EXIT_FAILURE);
		}
	}
	if (proxyMode != 0 && nicLan[0] == '\0')
	{
		print_log(_("!! 代理模式下必须在命令行上指定LAN网卡（-z）！\n"));
		exit(EXIT_FAILURE);
	}
	if (proxyMode == 0 && (userName[0]=='\0' || password[0]=='\0'))	/* 不使用代理时，未写用户名密码？ */
	{
		saveFlag = 1;
		printf(_("?? 请输入用户名: "));
		scanf("%s", userName);
		
		printf(_("?? 请输入密码: "));
		//scanf("%s", password);
		getpasswd(password);
		//last newline eaten by scanf in getpasswd
		printf("\n");
		
		printf(_("?? 请选择组播地址(0标准 1锐捷私有 2赛尔): "));
		scanf("%u", &startMode);
		startMode %= 3;
		printf(_("?? 请选择DHCP方式(0不使用 1二次认证 2认证后 3认证前): "));
		scanf("%u", &dhcpMode);
		dhcpMode %= 4;
	}
	if (startMode%3==2 && gateway==0)	/* 赛尔且未填写网关地址 */
	{
		gateway = ip;	/* 据说赛尔的网关是ip前三字节，后一字节是2 */
		((u_char *)&gateway)[3] = 0x02;
	}
	if (dhcpScript[0] == '\0')	/* 未填写DHCP脚本？ */
		strcpy(dhcpScript, D_DHCPSCRIPT);
	if (serviceName[0] == '\0') /* 未填写服务名？ */
		strcpy(serviceName, D_SERVICENAME);
	customizeServiceName(serviceName);
	newBuffer();
	printConfig();
	if (fillHeader()==-1 || openPcap()==-1) {	/* 获取IP、MAC，打开网卡 */
#ifndef NO_NOTIFY
		if (showNotify && show_notify(_("MentoHUST - 错误提示"),
			_("获取MAC地址或打开网卡失败！"), 1000*showNotify) < 0)
			showNotify = 0;
#endif
		exit(EXIT_FAILURE);
	}
	if (saveFlag)
		saveConfig(daemonMode);
}

static int readConfigFile(int *daemonMode)
{
	char tmp[16], *buf;
	if (loadFile(&buf, CFG_FILE) < 0)
		return -1;
	getString(buf, "MentoHUST", "Username", "", userName, sizeof(userName));
#ifdef NO_ENCODE_PASS
	getString(buf, "MentoHUST", "Password", "", password, sizeof(password));
#else
	char pass[ACCOUNT_SIZE*4/3+1];
	getString(buf, "MentoHUST", "Password", "", pass, sizeof(pass));
	if (pass[0] == ' ') {
		decodePass(password, pass+1);
	} else {
		strncpy(password, pass, sizeof(password)-1);
		encodePass(pass+1, password);
		pass[0] = ' ';
		setString(&buf, "MentoHUST", "Password", pass);
		saveFile(buf, CFG_FILE);
	}
#endif
	getString(buf, "MentoHUST", "Nic", "", nic, sizeof(nic));
	getString(buf, "MentoHUST", "Datafile", "", dataFile, sizeof(dataFile));
	getString(buf, "MentoHUST", "DhcpScript", "", dhcpScript, sizeof(dhcpScript));
	getString(buf, "MentoHUST", "Version", "", tmp, sizeof(tmp));
	getString(buf, "MentoHUST", "ServiceName", D_SERVICENAME, serviceName, sizeof(serviceName));
	if (strlen(tmp) >= 3) {
		unsigned ver[2];
		if (sscanf(tmp, "%u.%u", ver, ver+1)!=EOF && ver[0]!=0) {
			version[0] = ver[0];
			version[1] = ver[1];
			bufType = 1;
		}
	}
	getString(buf, "MentoHUST", "IP", "255.255.255.255", tmp, sizeof(tmp));
	ip = inet_addr(tmp);
	getString(buf, "MentoHUST", "Mask", "255.255.255.255", tmp, sizeof(tmp));
	mask = inet_addr(tmp);
	getString(buf, "MentoHUST", "Gateway", "0.0.0.0", tmp, sizeof(tmp));
	gateway = inet_addr(tmp);
	getString(buf, "MentoHUST", "DNS", "0.0.0.0", tmp, sizeof(tmp));
	dns = inet_addr(tmp);
	getString(buf, "MentoHUST", "PingHost", "0.0.0.0", tmp, sizeof(tmp));
	pingHost = inet_addr(tmp);
	timeout = getInt(buf, "MentoHUST", "Timeout", D_TIMEOUT) % 100;
	echoInterval = getInt(buf, "MentoHUST", "EchoInterval", D_ECHOINTERVAL) % 1000;
	restartWait = getInt(buf, "MentoHUST", "RestartWait", D_RESTARTWAIT) % 100;
	startMode = getInt(buf, "MentoHUST", "StartMode", D_STARTMODE) % 3;
	dhcpMode = getInt(buf, "MentoHUST", "DhcpMode", D_DHCPMODE) % 4;
#ifndef NO_NOTIFY
	showNotify = getInt(buf, "MentoHUST", "ShowNotify", D_SHOWNOTIFY) % 21;
#endif
	*daemonMode = getInt(buf, "MentoHUST", "DaemonMode", D_DAEMONMODE) % 4;
	restartOnLogOff = getInt(buf, "MentoHUST", "RestartOnLogOff", D_RESTARTONLOGOFF);
	maxFail = getInt(buf, "MentoHUST", "MaxFail", D_MAXFAIL);
	maxRetries = getInt(buf, "MentoHUST", "MaxRetries", D_MAXRETRIES);
	free(buf);
	return 0;
}

static void readArg(char argc, char **argv, int *saveFlag, int *exitFlag, int *daemonMode)
{
#ifndef NO_GETOPT_LONG
    int opt = 0;
    int longIndex = 0;
    unsigned ver[2]; /* -v buffer */
    static const char* shortOpts = "hk::wu:p:n:i:m:g:s:o:t:e:r:l:x:a:d:b:"
#ifndef NO_NOTIFY
        "y:"
#endif
        "v:f:c:z:j:q:";
    static const struct option longOpts[] = {
	    { "help", no_argument, NULL, 'h' },
	    { "kill", optional_argument, NULL, 'k' },
	    { "write", no_argument, NULL, 'w' },
	    { "username", required_argument, NULL, 'u' },
	    { "password", required_argument, NULL, 'p' },
	    { "nic", required_argument, NULL, 'n' },
	    { "ip", required_argument, NULL, 'i' },
	    { "mask", required_argument, NULL, 'm' },
	    { "gateway", required_argument, NULL, 'g' },
	    { "dns", required_argument, NULL, 's' },
	    { "ping-host", required_argument, NULL, 'o' },
	    { "auth-timeout", required_argument, NULL, 't' },
	    { "heartbeat", required_argument, NULL, 'e' },
	    { "wait-after-fail", required_argument, NULL, 'r' },
	    { "max-fail", required_argument, NULL, 'l' },
	    { "no-auto-reauth", required_argument, NULL, 'x' },
	    { "eap-bcast-addr", required_argument, NULL, 'a' },
	    { "dhcp-type", required_argument, NULL, 'd' },
	    { "daemonize", required_argument, NULL, 'b' },
#ifndef NO_NOTIFY
	    { "notify", required_argument, NULL, 'y' },
#endif
	    { "fake-supplicant-version", required_argument, NULL, 'v' },
	    { "template-file", required_argument, NULL, 'f' },
	    { "dhcp-script", required_argument, NULL, 'c' },
	    { "proxy-lan-iface", required_argument, NULL, 'z' },
	    { "proxy-require-success", required_argument, NULL, 'j' },
	    { "decode-config", required_argument, NULL, 'q' },
	    { "max-retries", required_argument, NULL, 0},
	    { "service", required_argument, NULL, 0},
	    { "pid-file", required_argument, NULL, 0},
	    { NULL, no_argument, NULL, 0 }
    };

    opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
#define COPY_ARG_TO(char_array) strncpy(char_array, optarg, sizeof(char_array) - 1);
    while (opt != -1) {
        switch (opt) {
            case 'h':
                showHelp(argv[0]); /* 调用本函数将退出程序 */
            case 'k':
                if (optarg == NULL)
                    *exitFlag = 1; /* 结束其他实例并退出 */
                else
                    *exitFlag = 2; /* 结束其他实例，本实例继续运行 */
                break;
            case 'w':
                *saveFlag = 1;
                break;
            case 'u':
                COPY_ARG_TO(userName);
                break;
            case 'p':
                COPY_ARG_TO(password);
                break;
            case 'n':
                COPY_ARG_TO(nic);
                break;
            case 'i':
                ip = inet_addr(optarg);
                break;
            case 'm':
                mask = inet_addr(optarg);
                break;
            case 'g':
                gateway = inet_addr(optarg);
                break;
            case 's':
                dns = inet_addr(optarg);
                break;
            case 'o':
                pingHost = inet_addr(optarg);
                break;
            case 't':
                timeout = atoi(optarg); /* 此处不设置限制，但原始的代码中有最大99秒的限制 */
                break;
            case 'e':
                echoInterval = atoi(optarg); /* 同上 */
                break;
            case 'r':
                restartWait = atoi(optarg); /* 同上 */
                break;
            case 'l':
                maxFail = atoi(optarg);
                break;
            case 'x':
                restartOnLogOff = atoi(optarg);
                break;
            case 'a':
                startMode = atoi(optarg) % 3;
                break;
            case 'd':
                dhcpMode = atoi(optarg) % 4;
                break;
            case 'b':
                *daemonMode = atoi(optarg) % 4;
                break;
#ifndef NO_NOTIFY
            case 'y':
                showNotify = atoi(optarg) % 21; /* 此处限制不知原因，程序中并未进行大小判断，保留 */
                break;
#endif
            case 'v':
                if (sscanf(optarg, "%u.%u", ver, ver + 1) != EOF) {
                    if (ver[0] == 0) {
                        bufType = 0;
                    } else {
                        version[0] = ver[0];
                        version[1] = ver[1];
                        bufType = 1;
                    }
                }
                break;
            case 'f':
                COPY_ARG_TO(dataFile);
                break;
            case 'c':
                COPY_ARG_TO(dhcpScript);
                break;
            case 'z':
                proxyMode = 1;
                COPY_ARG_TO(nicLan);
                break;
            case 'j':
                proxyRequireSuccessCount = atoi(optarg);
                break;
            case 'q':
                printSuConfig(optarg);
                exit(EXIT_SUCCESS);
            case 0: /* 超出26个字母的选项，没有短选项与其对应 */
#define IF_ARG(arg_name) (strcmp(longOpts[longIndex].name, arg_name) == 0)
                if (IF_ARG("max-retries")) {
                    maxRetries = atoi(optarg);
                } else if (IF_ARG("service")) {
                    COPY_ARG_TO(serviceName);
                } else if (IF_ARG("pid-file")) {
                    COPY_ARG_TO(pidFile);
                }
                break;
            default:
                break;
        }
        opt = getopt_long(argc, argv, shortOpts, longOpts, &longIndex);
    }
#else
	char *str, c;
	int i;
	for (i=1; i<argc; i++)
	{
		str = argv[i];
		if (str[0]!='-' && str[0]!='/')
			continue;
		c = str[1];
		if (c=='h' || c=='?' || strcmp(str, "--help")==0)
			showHelp(argv[0]);
        else if (c == 'q') {
            printSuConfig(str+2);
            exit(EXIT_SUCCESS);
        }
		else if (c == 'w')
			*saveFlag = 1;
		else if (c == 'k') {
			if (strlen(str) > 2)
				*exitFlag = 2;
			else {
				*exitFlag = 1;
				return;
			}
		}
		else if (strlen(str) > 2) {
			if (c == 'u')
				strncpy(userName, str+2, sizeof(userName)-1);
			else if (c == 'p')
				strncpy(password, str+2, sizeof(password)-1);
			else if (c == 'n')
				strncpy(nic, str+2, sizeof(nic)-1);
			else if (c == 'f')
				strncpy(dataFile, str+2, sizeof(dataFile)-1);
			else if (c == 'c')
				strncpy(dhcpScript, str+2, sizeof(dhcpScript)-1);
			else if (c=='v' && strlen(str+2)>=3) {
				unsigned ver[2];
				if (sscanf(str+2, "%u.%u", ver, ver+1) != EOF) {
					if (ver[0] == 0)
						bufType = 0;
					else {
						version[0] = ver[0];
						version[1] = ver[1];
						bufType = 1;
					}
				}
			}
			else if (c == 'i')
				ip = inet_addr(str+2);
			else if (c == 'm')
				mask = inet_addr(str+2);
			else if (c == 'g')
				gateway = inet_addr(str+2);
			else if (c == 's')
				dns = inet_addr(str+2);
			else if (c == 'o')
				pingHost = inet_addr(str+2);
			else if (c == 't')
				timeout = atoi(str+2) % 100;
			else if (c == 'e')
				echoInterval = atoi(str+2) % 1000;
			else if (c == 'r')
				restartWait = atoi(str+2) % 100;
			else if (c == 'a')
				startMode = atoi(str+2) % 3;
			else if (c == 'd')
				dhcpMode = atoi(str+2) % 4;
#ifndef NO_NOTIFY
			else if (c == 'y')
				showNotify = atoi(str+2) % 21;
#endif
			else if (c == 'b')
				*daemonMode = atoi(str+2) % 4;
			else if (c == 'l')
				maxFail = atoi(str+2);
			else if (c == 'z') {
				proxyMode = 1;
				strncpy(nicLan, str+2, sizeof(nicLan)-1);
			}
			else if (c == 'j')
				proxyRequireSuccessCount = atoi(str+2);
			else if (c == 'x')
				restartOnLogOff = atoi(str+2);
			else
				print_log(_("!! 未知选项: %s\n"), str);
		}
	}
#endif
}

static void showHelp(const char *fileName)
{
	char *helpString =
		_("用法:\t%s [-选项][参数] 或 [-选项] [参数] 或 [--长选项] [参数]\n选项:"
#ifndef NO_GETOPT_LONG
        "\t--help"
#endif
		"\t-h 显示本帮助信息\n"
#ifndef NO_GETOPT_LONG
        "\t--kill"
#endif
		"\t-k -k(退出程序) 其他(重启程序)\n"
#ifndef NO_GETOPT_LONG
        "\t--write"
#endif
		"\t-w 保存参数到配置文件\n"
#ifndef NO_GETOPT_LONG
        "\t--username"
#endif
		"\t-u 用户名\n"
#ifndef NO_GETOPT_LONG
        "\t--password"
#endif
		"\t-p 密码\n"
#ifndef NO_GETOPT_LONG
        "\t--nic"
#endif
		"\t-n 网卡名\n"
#ifndef NO_GETOPT_LONG
        "\t--ip"
#endif
		"\t-i IP[默认本机IP]\n"
#ifndef NO_GETOPT_LONG
        "\t--mask"
#endif
		"\t-m 子网掩码[默认本机掩码]\n"
#ifndef NO_GETOPT_LONG
        "\t--gateway"
#endif
		"\t-g 网关[默认0.0.0.0]\n"
#ifndef NO_GETOPT_LONG
        "\t--dns"
#endif
		"\t-s DNS[默认0.0.0.0]\n"
#ifndef NO_GETOPT_LONG
        "\t--ping-host"
#endif
		"\t-o Ping主机[默认0.0.0.0，表示关闭该功能]\n"
#ifndef NO_GETOPT_LONG
        "\t--auth-timeout"
#endif
		"\t-t 认证超时(秒)[默认8]\n"
#ifndef NO_GETOPT_LONG
        "\t--heartbeat"
#endif
		"\t-e 心跳间隔(秒)[默认30]\n"
#ifndef NO_GETOPT_LONG
        "\t--wait-after-fail"
#endif
		"\t-r 失败等待(秒)[默认15]\n"
#ifndef NO_GETOPT_LONG
        "\t--max-fail"
#endif
		"\t-l 允许失败次数[0表示无限制，默认8]\n"
#ifndef NO_GETOPT_LONG
        "\t--no-auto-reauth"
#endif
		"\t-x 掉线后是否自动重连: 0(不重连) 1(重连) [默认1]\n"
#ifndef NO_GETOPT_LONG
        "\t--eap-bcast-addr"
#endif
		"\t-a 组播地址: 0(标准) 1(锐捷) 2(赛尔) [默认0]\n"
#ifndef NO_GETOPT_LONG
        "\t--dhcp-type"
#endif
		"\t-d DHCP方式: 0(不使用) 1(二次认证) 2(认证后) 3(认证前) [默认0]\n"
#ifndef NO_GETOPT_LONG
        "\t--daemonize"
#endif
		"\t-b 是否后台运行: 0(否) 1(是，关闭输出) 2(是，保留输出) 3(是，输出到文件) [默认0]\n"
#ifndef NO_NOTIFY
#ifndef NO_GETOPT_LONG
        "\t--notify"
#endif
		"\t-y 是否显示通知: 0(否) 1~20(是) [默认5]\n"
#endif
#ifndef NO_GETOPT_LONG
        "\t--fake-supplicant-version"
#endif
		"\t-v 客户端版本号[默认0.00表示兼容xrgsu]\n"
#ifndef NO_GETOPT_LONG
        "\t--template-file"
#endif
		"\t-f 自定义数据文件[默认不使用]\n"
#ifndef NO_GETOPT_LONG
        "\t--dhcp-script"
#endif
		"\t-c DHCP脚本[默认dhclient]\n"
#ifndef NO_GETOPT_LONG
        "\t--proxy-lan-iface"
#endif
		"\t-z 认证代理模式下监听认证数据包的网卡名（设置此项即表示开启代理模式）\n"
#ifndef NO_GETOPT_LONG
        "\t--proxy-require-success"
#endif
		"\t-j 认证代理模式下关闭LAN监听线程前需要收到的Success包次数 [默认1]\n"
#ifndef NO_GETOPT_LONG
        "\t--decode-config"
#endif
		"\t-q 显示SuConfig.dat的内容(如-q/path/SuConfig.dat)\n"
#ifndef NO_GETOPT_LONG
		/* 从这里开始就是必须使用长选项的参数了 */
		"\t--max-retries 在得到认证成功或失败的结果前，最多重试的次数，0表示无限重试 [默认0]\n"
		"\t--service 要登陆到的服务名 [默认internet]\n"
		"\t--pid-file PID文件存放路径，设为none可禁用PID文件锁检查 [默认/var/run/mentohust.pid]\n"
#endif
		"例如:\t%s -u username -p password -n eth0 -i 192.168.0.1 -m 255.255.255.0 -g 0.0.0.0 -s 0.0.0.0 -o 0.0.0.0 -t 8 -e 30 -r 15 -a 0 -d 1 -b 0 -v 4.10 -f default.mpf -c dhclient\n"
		"关于代理模式：此模式下MentoHUST将不会自己发起认证，而是修改LAN内捕获到的认证数据包的源MAC并转发至WAN，使得本机认证通过。\n"
		"代理模式下用户名、密码、掉线重连方式（-u、-p、-x）无效，可不指定。由于Start包为自行构造，仍然需要指定DHCP方式和组播地址（-d、-a）。\n"
		"代理模式示例:\t%s --proxy-lan-iface br0 --nic eth0 --eap-bcast-addr 1 --dhcp-type 2 -proxy-require-success 2\n"
		"注意：使用时请确保是以root权限运行！\n\n");
	printf(helpString, fileName, fileName, fileName);
	//cancel the registered funciton:atexit(exit_handle)
	exit(EXIT_SUCCESS);
}

static int askSelectAdapter()
{
	pcap_if_t *alldevs, *d;
	int num = 0, avail = 0, i;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf)==-1 || alldevs==NULL)
	{
		printf(_("!! 查找网卡失败: %s\n"), errbuf);
		return -1;
	}
	for (d=alldevs; d!=NULL; d=d->next)
	{
		num++;
		if (!(d->flags & PCAP_IF_LOOPBACK) && strcmp(d->name, "any")!=0)
		{
			printf(_("** 网卡[%d]:\t%s\n"), num, d->name);
			avail++;
			i = num;
		}
	}
	if (avail == 0)
	{
		pcap_freealldevs(alldevs);
		printf(_("!! 找不到网卡！\n"));
		return -1;
	}
	if (avail > 1)
	{
		printf(_("?? 请选择网卡[1-%d]: "), num);
		scanf("%d", &i);
		if (i < 1)
			i = 1;
		else if (i > num)
			i = num;
	}
	printf(_("** 您选择了第[%d]块网卡。\n"), i);
	for (d=alldevs; i>1; d=d->next, i--);
	strncpy(nic, d->name, sizeof(nic)-1);
	pcap_freealldevs(alldevs);
	return 0;
}

static void printConfig()
{
	char *addr[] = {_("标准"), _("锐捷"), _("赛尔")};
	char *dhcp[] = {_("不使用"), _("二次认证"), _("认证后"), _("认证前")};
	if (proxyMode == 0) {
		print_log(_("** 用户名:\t%s\n"), userName);
		/* printf("** 密码:\t%s\n", password); */
		print_log(_("** 网卡: \t%s\n"), nic);
		print_log(_("** 服务名:\t%s\n"), serviceName);
		print_log(_("** 掉线后重连:\t%s\n"), restartOnLogOff ? "是" : "否");
	} else {
		print_log(_("** 已启用代理模式\n"));
		print_log(_("** WAN网卡: \t%s\n"), nic);
		print_log(_("** LAN网卡: \t%s\n"), nicLan);
		print_log(_("** 成功要求: \t%d次\n"), proxyRequireSuccessCount);
	}
	if (gateway)
		print_log(_("** 网关地址:\t%s\n"), formatIP(gateway));
	if (dns)
		print_log(_("** DNS地址:\t%s\n"), formatIP(dns));
	if (pingHost)
		print_log(_("** 智能重连:\t%s\n"), formatIP(pingHost));
	print_log(_("** 认证超时:\t%u秒\n"), timeout);
	print_log(_("** 心跳间隔:\t%u秒\n"), echoInterval);
	print_log(_("** 失败等待:\t%u秒\n"), restartWait);
	if (maxFail)
		print_log(_("** 允许失败:\t%u次\n"), maxFail);
	if (maxRetries > 0)
		print_log(_("** 允许重试:\t%u次\n"), maxRetries);
	else
		print_log(_("** 允许重试:\t无限\n"));
	print_log(_("** 组播地址:\t%s\n"), addr[startMode]);
	print_log(_("** DHCP方式:\t%s\n"), dhcp[dhcpMode]);
#ifndef NO_NOTIFY
	if (showNotify)
		print_log(_("** 通知超时:\t%d秒\n"), showNotify);
#endif
	if (bufType >= 2)
		print_log(_("** 数据文件:\t%s\n"), dataFile);
	if (dhcpMode != 0)
    {
		print_log(_("** DHCP脚本:\t%s\n"), dhcpScript);
    }
}

static int openPcap()
{
	char buf[PCAP_ERRBUF_SIZE], *fmt;
	struct bpf_program fcode;
	if ((hPcap = pcap_open_live(nic, 2048, startMode >= 3  , 1000, buf)) == NULL)
	{
		printf(proxyMode == 0 ? _("!! 打开网卡%s失败: %s\n") : _("!! 打开WAN网卡%s失败: %s\n")
				, nic, buf);
		return -1;
	}
	// TODO 在LAN接口上暂时强制使用混杂模式
	if (proxyMode != 0 && ((hPcapLan = pcap_open_live(nicLan, 2048, 1, 1000, buf)) == NULL))
	{
		print_log(_("!! 打开LAN网卡%s失败: %s\n"), nicLan, buf);
		return -1;
	}
	fmt = formatHex(localMAC, 6);
#ifndef NO_ARP
	sprintf(buf, "((ether proto 0x888e and (ether dst %s or ether dst 01:80:c2:00:00:03)) "
			"or ether proto 0x0806) and not ether src %s", fmt, fmt);
#else
	sprintf(buf, "ether proto 0x888e and (ether dst %s or ether dst 01:80:c2:00:00:03) "
			"and not ether src %s", fmt, fmt);
#endif
	if (pcap_compile(hPcap, &fcode, buf, 0, 0xffffffff) == -1
			|| pcap_setfilter(hPcap, &fcode) == -1)
	{
		print_log(_("!! 设置pcap过滤器失败: %s\n"), pcap_geterr(hPcap));
		return -1;
	}
	pcap_freecode(&fcode);
	if (proxyMode != 0) {
		strcpy(buf, "ether proto 0x888e");
		if (pcap_compile(hPcapLan, &fcode, buf, 0, 0xffffffff) == -1
				|| pcap_setfilter(hPcapLan, &fcode) == -1)
		{
			print_log(_("!! 为LAN设置pcap过滤器失败: %s\n"), pcap_geterr(hPcapLan));
			return -1;
		}
		pcap_freecode(&fcode);
	}
	return 0;
}

static void saveConfig(int daemonMode)
{
	char *buf;
	if (loadFile(&buf, CFG_FILE) < 0) {
		buf = (char *)malloc(1);
		buf[0] = '\0';
	}
	setString(&buf, "MentoHUST", "DhcpScript", dhcpScript);
	setString(&buf, "MentoHUST", "DataFile", dataFile);
	if (bufType != 0) {
		char ver[10];
		sprintf(ver, "%u.%u", version[0], version[1]);
		setString(&buf, "MentoHUST", "Version", ver);
	} else
		setString(&buf, "MentoHUST", "Version", "0.00");
#ifndef NO_NOTIFY
	setInt(&buf, "MentoHUST", "ShowNotify", showNotify);
#endif
	setInt(&buf, "MentoHUST", "DaemonMode", daemonMode);
	setInt(&buf, "MentoHUST", "DhcpMode", dhcpMode);
	setInt(&buf, "MentoHUST", "StartMode", startMode);
	setInt(&buf, "MentoHUST", "MaxFail", maxFail);
	setInt(&buf, "MentoHUST", "RestartOnLogOff", restartOnLogOff);
	setInt(&buf, "MentoHUST", "RestartWait", restartWait);
	setInt(&buf, "MentoHUST", "EchoInterval", echoInterval);
	setInt(&buf, "MentoHUST", "Timeout", timeout);
	setInt(&buf, "MentoHUST", "MaxRetries", maxRetries);
	setString(&buf, "MentoHUST", "PingHost", formatIP(pingHost));
	setString(&buf, "MentoHUST", "DNS", formatIP(dns));
	setString(&buf, "MentoHUST", "Gateway", formatIP(gateway));
	setString(&buf, "MentoHUST", "Mask", formatIP(mask));
	setString(&buf, "MentoHUST", "IP", formatIP(ip));
	setString(&buf, "MentoHUST", "Nic", nic);
#ifdef NO_ENCODE_PASS
	setString(&buf, "MentoHUST", "Password", password);
#else
	char pass[ACCOUNT_SIZE*4/3+1];
	encodePass(pass+1, password);
	pass[0] = ' ';
	setString(&buf, "MentoHUST", "Password", pass);
#endif
	setString(&buf, "MentoHUST", "Username", userName);
	if (saveFile(buf, CFG_FILE) != 0)
		print_log(_("!! 保存认证参数到%s失败！\n"), CFG_FILE);
	else
		print_log(_("** 认证参数已成功保存到%s.\n"), CFG_FILE);
	free(buf);
}

static void applyDaemonMode(int daemonMode) {
	if (daemonMode) {
		printf(_(">> 进入后台运行模式，使用参数-k可退出认证。\n"));
#ifndef __UCLIBC__
		if (daemon(0, (daemonMode+1)%2))
#else
		if (uclibc_daemon(0, (daemonMode+1)%2))
#endif
			perror(_("!! 后台运行失败"));
		else if (daemonMode == 3) {
			/* 更改日志输出到文件 */
			set_log_destination(LOG_TO_FILE);
		}
	}
}

inline int isPidFileEnabled(char* pidFilePath)
{
	return strncmp(pidFilePath, "none", 4);
}

static void acquirePidFileLock(struct flock* fl)
{
	if (lockfd < 0) {
		lockfd = open (pidFile, O_RDWR|O_CREAT, LOCKMODE);
		if (lockfd < 0) {
			perror(_("!! 打开锁文件失败"));
			goto error_exit;
		}
	}
	fl->l_start = 0;
	fl->l_whence = SEEK_SET;
	fl->l_len = 0;
	fl->l_type = F_WRLCK;
	if (fcntl(lockfd, F_GETLK, fl) < 0) {
		perror(_("!! 获取文件锁失败"));
		goto error_exit;
	}
	return;

error_exit:
#ifndef NO_NOTIFY
	if (showNotify && show_notify(_("MentoHUST - 错误提示"),
		_("操作锁文件失败，请检查是否为root权限！"), 1000*showNotify) < 0)
		showNotify = 0;
#endif
	exit(EXIT_FAILURE);
}

static void checkRunningInstance(int exitFlag)
{
	if (!isPidFileEnabled(pidFile)) {
		print_log("!! 已禁用PID检查，请确保没有其他实例干扰认证进程\n");
		return;
	}

	struct flock fl;
	acquirePidFileLock(&fl);

	if (exitFlag) {
		if (fl.l_type != F_UNLCK) {
			printf(_(">> 已发送退出信号给MentoHUST进程(PID=%d).\n"), fl.l_pid);
			if (kill(fl.l_pid, SIGINT) == -1)
				perror(_("!! 结束进程失败"));
		}
		else
			printf(_("!! 没有MentoHUST正在运行！\n"));
		if (exitFlag == 1)
			exit(EXIT_SUCCESS);
	}
	else if (fl.l_type != F_UNLCK) {
		printf(_("!! MentoHUST已经运行(PID=%d)!\n"), fl.l_pid);
		exit(EXIT_FAILURE);
	}
	return;
}

static void lockPidFile() {
	if (!isPidFileEnabled(pidFile)) {
		// 此处不需要提示
		return;
	}

	struct flock fl;
	acquirePidFileLock(&fl);

	fl.l_type = F_WRLCK;
	fl.l_pid = getpid();
	if (fcntl(lockfd, F_SETLKW, &fl) < 0) {
		perror(_("!! 加锁失败"));
		goto error_exit;
	}
	return;

error_exit:
#ifndef NO_NOTIFY
	if (showNotify && show_notify(_("MentoHUST - 错误提示"),
		_("操作锁文件失败，请检查是否为root权限！"), 1000*showNotify) < 0)
		showNotify = 0;
#endif
	exit(EXIT_FAILURE);
}

#ifdef __UCLIBC__
/*
	uClibc中daemon的实现存在问题，会导致daemon后pthread_create阻塞父线程。
	手动实现daemon即可解决此问题。
*/
static int uclibc_daemon(int nochdir,  int noclose)
{
	pid_t pid;
	if (!nochdir && chdir("/") != 0)
		return -1;

	if (!noclose)
	{
		int fd = open("/dev/null", O_RDWR);
		if (fd  <  0)
			return -1;

		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
	}

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid > 0)
		_exit(0);

   if (setsid() < 0)
      return -1;
   return 0;
}
#endif
