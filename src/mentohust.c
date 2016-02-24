/* -*- Mode: C; tab-width: 4; -*- */
/*
* Copyright (C) 2009, HustMoon Studio
*
* 文件名称：mentohust.c
* 摘	要：MentoHUST主函数
* 作	者：HustMoon@BYHH
* 邮	箱：www.ehust@gmail.com
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "myconfig.h"
#include "i18n.h"
#include "mystate.h"
#include "myfunc.h"
#include "dlfunc.h"
#include "util.h"
#include "packet_header.h"
#include "proxy_util.h"
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>

extern pcap_t *hPcap, *hPcapLan;
extern volatile int state;
extern u_char *fillBuf;
extern const u_char *capBuf;
extern unsigned startMode, dhcpMode, maxFail, restartOnLogOff;
extern unsigned proxyMode, proxyClientRequested, proxySuccessCount, proxyRequireSuccessCount;
extern u_char destMAC[], localMAC[], clientMAC[], lastSuccessClientMAC[];
extern int lockfd;
#ifndef NO_NOTIFY
extern int showNotify;
#endif
#ifndef NO_ARP
extern u_int32_t rip, gateway;
extern u_char gateMAC[];
#endif

static void* wan_thread(); /* WAN线程，调用pcap_loop */
static void* lan_thread(); /* LAN线程，调用pcap_loop，仅在代理模式下使用 */
static void exit_handle(void);	/* 退出回调 */
static void sig_handle(int sig);	/* 信号回调 */
static void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *buf);	/* pcap_loop回调（WAN） */
static void pcap_handle_lan(u_char *user, const struct pcap_pkthdr *h, const u_char *buf);	/* pcap_loop回调（LAN，仅在代理模式下使用） */
static void showRuijieMsg(const u_char *buf, unsigned bufLen);	/* 显示锐捷服务器提示信息 */
static void showCernetMsg(const u_char *buf);	/* 显示赛尔服务器提示信息 */

int main(int argc, char **argv)
{
    pthread_t thread_lan;
    void *retval; // pthread线程的返回值，本程序中没有实际用处

#ifdef ENABLE_NLS
	textdomain(GETTEXT_PACKAGE);
	setlocale(LC_ALL, "");
#endif
	atexit(exit_handle);
	initConfig(argc, argv);
	signal(SIGALRM, sig_handle);	/* 定时器 */
	signal(SIGHUP, sig_handle);	 /* 注销时 */
	signal(SIGINT, sig_handle);	 /* Ctrl+C */
	signal(SIGQUIT, sig_handle);	/* Ctrl+\ */
	signal(SIGTSTP, sig_handle);	/* Ctrl+Z */
	signal(SIGTERM, sig_handle);	/* 被结束时 */
	if (dhcpMode == 3)	  /* 认证前DHCP */
		switchState(ID_DHCP);
	else
		if (proxyMode == 0)
			switchState(ID_START);	/* 不使用代理时直接开始认证 */
		else
			switchState(ID_WAITCLIENT); /* 开启代理时等待客户端认证 */
	if (proxyMode == 0) {
		wan_thread(); // 非代理模式，直接执行，不使用多线程
	} else { // 代理模式，为LAN多开一个线程
		pthread_create(&thread_lan, NULL, lan_thread, 0);
		wan_thread();
		pthread_join(thread_lan, &retval);
	}
	exit(EXIT_FAILURE);
}

static void* wan_thread()
{
	char err[100];
	char* err_base[2] = { _("!! 捕获数据包失败，请检查网络连接！\n"),
						  _("!! 从WAN捕获数据包失败，请检查网络连接！\n") };
	sprintf(err, "[%s] %s", get_formatted_date(), err_base[proxyMode == 1]);
	if (-1 == pcap_loop(hPcap, -1, pcap_handle, NULL)) { /* 开始捕获数据包 */
		printf("%s", err);
#ifndef NO_NOTIFY
		if (showNotify && show_notify(_("MentoHUST - 错误提示"),
			err_base[proxyMode == 1], 1000*showNotify) < 0)
			showNotify = 0;
#endif
	}
	return 0;
}

static void* lan_thread()
{
	if (-1 == pcap_loop(hPcapLan, -1, pcap_handle_lan, NULL)) { /* 开始捕获数据包 */
		printf(_("[%s] !! 从LAN捕获数据包失败，请检查网络连接！\n"), get_formatted_date());
#ifndef NO_NOTIFY
		if (showNotify && show_notify(_("MentoHUST - 错误提示"),
			_("!! 从LAN捕获数据包失败，请检查网络连接！\n"), 1000*showNotify) < 0)
			showNotify = 0;
#endif
	}
	return 0;
}

static void exit_handle(void)
{
	if (state != ID_DISCONNECT)
		switchState(ID_DISCONNECT);
	if (hPcap != NULL)
		pcap_close(hPcap);
	if (hPcapLan != NULL)
		pcap_close(hPcapLan);
	if (fillBuf != NULL)
		free(fillBuf);
	if (lockfd > -1)
		close(lockfd);
#ifndef NO_NOTIFY
	free_libnotify();
#endif
#ifndef NO_DYLOAD
	free_libpcap();
#endif
	printf(_("[%s] >> 认证已退出。\n"), get_formatted_date());
}

static void sig_handle(int sig)
{
	if (sig == SIGALRM)	 /* 定时器 */
	{
		if (-1 == switchState(state))
		{
			pcap_breakloop(hPcap);
			printf(_("[%s] !! 发送数据包失败, 请检查网络连接！\n"), get_formatted_date());
#ifndef NO_NOTIFY
			if (showNotify && show_notify(_("MentoHUST - 错误提示"),
				_("发送数据包失败, 请检查网络连接！"), 1000*showNotify) < 0)
				showNotify = 0;
#endif
			exit(EXIT_FAILURE);
		}
	}
	else	/* 退出 */
	{
		pcap_breakloop(hPcap);
		if (hPcapLan != NULL) pcap_breakloop(hPcapLan);
		exit(EXIT_SUCCESS);
	}
}

static void pcap_handle_lan(u_char *user, const struct pcap_pkthdr *h, const u_char *buf)
{
	PACKET_HEADER* hdr = (PACKET_HEADER*)buf;
	int eap_type_int; // EAP中的type
	int eapol_type_int = hdr->eapol_hdr.type;
	MAC_CHECK_STATUS mac_status = proxy_check_mac_integrity(buf);

	switch (eapol_type_int) {
	case EAPOL_START:
		switch (mac_status) {
		case MAC_NOT_DEFINED:
			proxy_store_client_mac(buf); // 锁定客户端的MAC地址，以防不同设备的认证流程干扰
			printf(_("[%s] >> 客户端%s正在发起认证\n"), get_formatted_date(), formatHex(clientMAC, 6));
			proxyClientRequested = 1;
			switchState(ID_START);
			break;
		case MAC_CHECK_PASSED:
			if (proxySuccessCount < proxySuccessCount && (state == ID_ECHO || state == ID_WAITECHO)) {
				printf(_("[%s] !! 客户端在认证完成后发送Start包，忽略\n"), get_formatted_date());
				goto DONE;
			} else {
				/* 这里一般是多次认证（-j参数大于1时） */
				printf(_("[%s] >> 客户端%s再次发起认证\n"), get_formatted_date(), formatHex(clientMAC, 6));
				switchState(ID_START);
			}
			break;
		case MAC_CHECK_FAILED:
			goto PROXY_INTERRUPTED;
		}
		break;
	case EAPOL_LOGOFF:
		switch (mac_status) {
		case MAC_CHECK_FAILED:
			goto PROXY_INTERRUPTED;
		case MAC_NOT_DEFINED:
			goto DONE;
		case MAC_CHECK_PASSED:
			printf(_("[%s] !! 客户端要求断开认证，将忽略此请求\n"), get_formatted_date());
			goto DONE;
		}
	case EAP_PACKET:
		switch (mac_status) {
		case MAC_CHECK_FAILED:
			goto PROXY_INTERRUPTED;
		case MAC_NOT_DEFINED:
			goto DONE;
		case MAC_CHECK_PASSED:
			eap_type_int = hdr->eap_hdr.type;
			switch (eap_type_int) {
			case IDENTITY:
				printf(_("[%s] >> 客户端已发送用户名\n"), get_formatted_date());
				break;
			case MD5_CHALLENGE:
				printf(_("[%s] >> 客户端已发送密码\n"), get_formatted_date());
				break;
			}
			break;
		}
	}

	/*
	所有不需代理的情况均已处理完毕，
	现在将客户端发来的数据包中源MAC改为本设备的并发送出去
	*/
	proxy_send_to_wan(buf, h->len);
	goto DONE;

PROXY_INTERRUPTED:
	printf(_("[%s] !! 认证流程受到来自%s的干扰！\n"), get_formatted_date(), formatHex(hdr->eth_hdr.src_mac, 6));
DONE:
	return;
}

static void pcap_handle(u_char *user, const struct pcap_pkthdr *h, const u_char *buf)
{
	static unsigned failCount = 0;
	pthread_t thread_lan;

#ifndef NO_ARP
	if (buf[0x0c]==0x88 && buf[0x0d]==0x8e) {
#endif
		if (memcmp(destMAC, buf+6, 6)!=0 && startMode>2)	/* 服务器MAC地址不符 */
			return;
		capBuf = buf;
		if (buf[0x0F]==0x00 && buf[0x12]==0x01 && buf[0x16]==0x01) {	/* 验证用户名 */
			if (startMode < 3) {
				memcpy(destMAC, buf+6, 6);
				printf(_("[%s] ** 认证MAC:\t%s\n"), get_formatted_date(), formatHex(destMAC, 6));
				startMode += 3;	/* 标记认证服务器MAC为已获取，可以锁定 */
			}
			if (proxyMode == 0) {
				if (startMode==3 && memcmp(buf+0x17, "User name", 9)==0)	/* 塞尔 */
					startMode = 5;
				switchState(ID_IDENTITY);
			} else {
				if (proxyClientRequested == 1) {
					printf(_("[%s] >> 服务器已请求用户名\n"), get_formatted_date());
					proxy_send_to_lan(buf, h->len);
				} else {
					printf(_("[%s] !! 在代理认证完成后收到用户名请求，将重启认证！\n"), get_formatted_date());
					switchState(ID_WAITCLIENT);
				}
			}
		}
		else if (buf[0x0F]==0x00 && buf[0x12]==0x01 && buf[0x16]==0x04)	{ /* 验证密码 */
			if (proxyMode == 0) {
				switchState(ID_CHALLENGE);
			} else {
				if (proxyClientRequested == 1) {
					printf(_("[%s] >> 服务器已请求密码\n"), get_formatted_date());
					proxy_send_to_lan(buf, h->len);
				} else {
					printf(_("[%s] !! 在代理认证完成后收到密码请求，将重启认证！\n"), get_formatted_date());
					switchState(ID_WAITCLIENT);
				}
			}
		}
		else if (buf[0x0F]==0x00 && buf[0x12]==0x03) {	/* 认证成功 */
			printf(_("[%s] >> 认证成功!\n"), get_formatted_date());
			failCount = 0;
			proxySuccessCount++;
			if (proxyMode != 0) {
				proxy_send_to_lan(buf, h->len);
				if (proxySuccessCount >= proxyRequireSuccessCount) {
					pcap_breakloop(hPcapLan);
					proxyClientRequested = 0;
					proxySuccessCount = 0;
					memcpy(lastSuccessClientMAC, clientMAC, 6); // 备份本次认证成功的客户端MAC，用于通知掉线
					proxy_clear_client_mac(); // 重设MAC地址，以备下次使用不同客户端认证用
					printf(_("[%s] >> 已关闭LAN监听线程\n"), get_formatted_date());
				}
			}
			if (!(startMode%3 == 2)) {
				getEchoKey(buf);
			}
			showRuijieMsg(buf, h->caplen);
			if (dhcpMode==1 || dhcpMode==2)	/* 二次认证第一次或者认证后 */
				switchState(ID_DHCP);
			else if (startMode%3 == 2)
				switchState(ID_WAITECHO);
			else
				switchState(ID_ECHO);
		}
		else if (buf[0x0F]==0x00 && buf[0x12]==0x01 && buf[0x16]==0x02)	/* 显示赛尔提示信息 */
			showCernetMsg(buf);
		else if (buf[0x0F] == 0x05)	/* (赛尔)响应在线 */
			switchState(ID_ECHO);
		else if (buf[0x0F]==0x00 && buf[0x12]==0x04) {  /* 认证失败或被踢下线 */
			if (state==ID_WAITECHO || state==ID_ECHO) {
				if (proxyMode == 0) {
					printf(_("[%s] >> 认证掉线！\n"), get_formatted_date());
					showRuijieMsg(buf, h->caplen);
					if (restartOnLogOff) {
						printf(_("[%s] >> 正在重新认证...\n"), get_formatted_date());
						switchState(ID_START);					
					} else {
						exit(1);
					}
				} else {
					pthread_create(&thread_lan, NULL, lan_thread, 0);
					printf(_("[%s] >> 认证掉线，已发回客户端并重新启用对LAN的监听\n"), get_formatted_date());
					showRuijieMsg(buf, h->caplen);
					// clientMAC已经在成功时被清除了，所以使用lastSuccessClientMAC发送，发完清除
					memmove(clientMAC, lastSuccessClientMAC, 6);
					proxy_send_to_lan(buf, h->len);
					proxy_clear_client_mac();
					switchState(ID_WAITCLIENT);
				}
			}
			else if (buf[0x1b]!=0 || startMode%3==2) {
				printf(_("[%s] >> 认证失败!\n"), get_formatted_date());
				showRuijieMsg(buf, h->caplen);
				if (maxFail && ++failCount>=maxFail) {
					printf(_("[%s] >> 连续认证失败%u次，退出认证。\n"), get_formatted_date(), maxFail);
					exit(EXIT_SUCCESS);
				}
				restart();
			} else {
				if (proxyMode == 0)
					switchState(ID_START);
				else
					switchState(ID_WAITCLIENT);
			}
		}
#ifndef NO_ARP
	} else if (gateMAC[0]!=0xFE && buf[0x0c]==0x08 && buf[0x0d]==0x06) {
		if (*(u_int32_t *)(buf+0x1c) == gateway) {
			char str[50];
			if (gateMAC[0] == 0xFF) {
				memcpy(gateMAC, buf+0x16, 6);
				printf(_("** 网关MAC:\t%s\n"), formatHex(gateMAC, 6));
				sprintf(str, "arp -s %s %s", formatIP(gateway), formatHex(gateMAC, 6));
				system(str);
			} else if (buf[0x15]==0x02 && *(u_int32_t *)(buf+0x26)==rip
				&& memcmp(gateMAC, buf+0x16, 6)!=0) {
				printf(_("** ARP欺骗:\t%s\n"), formatHex(buf+0x16, 6));
#ifndef NO_NOTIFY
				if (showNotify) {
					sprintf(str, _("欺骗源: %s"), formatHex(buf+0x16, 6));
					if (show_notify(_("MentoHUST - ARP提示"), str, 1000*showNotify) < 0)
						showNotify = 0;
				}
#endif
			}
		}
	}
#endif
}

static void showRuijieMsg(const u_char *buf, unsigned bufLen)
{
	char *serverMsg;
	int length = buf[0x1b];
	if (length > 0) {
		for (serverMsg=(char *)(buf+0x1c); *serverMsg=='\r'||*serverMsg=='\n'; serverMsg++,length--);	/* 跳过开头的换行符 */
		if (strlen(serverMsg) < length)
			length = strlen(serverMsg);
		if (length>0 && (serverMsg=gbk2utf(serverMsg, length))!=NULL) {
			if (strlen(serverMsg)) {
				printf(_("[%s] $$ 系统提示:\n%s\n"), get_formatted_date(), serverMsg);
#ifndef NO_NOTIFY
				if (showNotify && show_notify(_("MentoHUST - 系统提示"),
					serverMsg, 1000*showNotify) < 0)
					showNotify = 0;
#endif
			}
			free(serverMsg);
		}
	}
	if ((length=0x1c+buf[0x1b]+0x69+39) < bufLen) {
		serverMsg=(char *)(buf+length);
		if (buf[length-1]-2 > bufLen-length)
			length = bufLen - length;
		else
			length = buf[length-1]-2;
		for (; *serverMsg=='\r'||*serverMsg=='\n'; serverMsg++,length--);
		if (length>0 && (serverMsg=gbk2utf(serverMsg, length))!=NULL) {
			if (strlen(serverMsg)) {
				printf(_("[%s] $$ 计费提示:\n%s\n"), get_formatted_date(), serverMsg);
#ifndef NO_NOTIFY
				if (showNotify && show_notify(_("MentoHUST - 计费提示"),
					serverMsg, 1000*showNotify) < 0)
					showNotify = 0;
#endif
			}
			free(serverMsg);
		}
	}
}

static void showCernetMsg(const u_char *buf)
{
	char *serverMsg = (char *)(buf+0x17);
	int length = ntohs(*(u_int16_t *)(buf+0x14)) - 5;
	if (strlen(serverMsg) < length)
		length = strlen(serverMsg);
	if (length>0 && (serverMsg=gbk2utf(serverMsg, length))!=NULL)
	{
		printf(_("$$ 系统提示:\t%s\n"), serverMsg);
#ifndef NO_NOTIFY
			if (showNotify && show_notify(_("MentoHUST - 系统提示"),
				serverMsg, 1000*showNotify) < 0)
				showNotify = 0;
#endif
		free(serverMsg);
	}
}
