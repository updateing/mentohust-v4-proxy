/* -*- Mode: C; tab-width: 4; -*- */
/*
* Copyright (C) 2016, Hamster Tian
*
* 文件名称：proxy_util.c
* 摘	要：MentoHUST代理认证功能辅助函数
* 作	者：Hamster Tian
* 邮	箱：haotia@gmail.com
*/

#include <proxy_util.h>

#define SOURCE_MAC_OFFSET 6

u_char clientMAC[6];	/* 当前正在认证的客户端MAC，仅在代理模式下使用 */

MAC_CHECK_STATUS proxy_check_mac_intergrity(u_char* packet)
{
	if (memcmp(clientMAC, "\0\0\0\0\0\0", 6) == 0)
		return MAC_NOT_DEFINED;

	if (memcmp(clientMAC, ((PACKET_HEADER*)packet)->eth_hdr.src_mac, 6) == 0)
		return MAC_CHECK_PASSED;

	return MAC_CHECK_FALIED;
}

void proxy_store_client_mac(u_char* packet)
{
	memmove(clientMAC, packet + SOURCE_MAC_OFFSET, 6);
}

void proxy_clear_client_mac()
{
	memset(clientMAC, 0, 6);
}

void proxy_send_to_wan(u_char* packet, int len)
{
	u_char* mod_buf = malloc(len);
	memmove(mod_buf, buf, len);
	memmove(mod_buf + 6, localMAC, 6);
	pcap_sendpacket(hPcap, mod_buf, len);
	free(mod_buf);
}
