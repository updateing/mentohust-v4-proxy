/* -*- Mode: C; tab-width: 4; -*- */
/*
* 文件名称：util.c
* 摘	要：MentoHUST认证无关的杂项功能
* 作	者：updateing@HUST
* 邮	箱：haotia@gmail.com
*/

#include <time.h>
#include <stdio.h>
#include <string.h>

char time_buffer[20]; // Buffer for time output

char* get_formatted_date() {
	time_t time_tmp;
	struct tm* time_s;

	time(&time_tmp);
	time_s = localtime(&time_tmp);

	sprintf(time_buffer, "%d/%d/%d %d:%02d:%02d", time_s->tm_year + 1900, time_s->tm_mon + 1,
				time_s->tm_mday, time_s->tm_hour, time_s->tm_min, time_s->tm_sec);
	return time_buffer;
}
