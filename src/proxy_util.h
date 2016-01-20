/* -*- Mode: C; tab-width: 4; -*- */
/*
* Copyright (C) 2016, Hamster Tian
*
* 文件名称：proxy_util.h
* 摘	要：MentoHUST代理认证功能辅助函数、结构
* 作	者：Hamster Tian
* 邮	箱：haotia@gmail.com
*/

#ifndef MH_PROXY_UTIL_H
#define MH_PROXY_UTIL_H

#include <sys/types.h>

/* 客户端MAC地址校验结果 */
typedef enum _MAC_CHECK_STATUS
{
	MAC_NOT_DEFINED, /* 未存储MAC地址 */
	MAC_CHECK_FAILED, /* 数据包中MAC地址与已存储的MAC地址不符 */
	MAC_CHECK_PASSED /* 数据包中的MAC地址与已存储的MAC地址一致 */
} MAC_CHECK_STATUS;

void proxy_store_client_mac(u_char* packet); // 存储当前数据包中的源MAC地址（用于在一次认证流程中锁定客户端）
void proxy_clear_client_mac(); // 清除已储存的MAC地址，为下次认证做准备
MAC_CHECK_STATUS proxy_check_mac_intergrity(u_char* packet); // 检查当前数据包中的源MAC地址是否与已储存的地址相同
#endif
