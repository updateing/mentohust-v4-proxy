/* -*- Mode: C; tab-width: 4; -*- */
/*
* 文件名称：logging.c
* 摘	要：MentoHUST日志功能
* 作	者：updateing@HUST
* 邮	箱：haotia@gmail.com
*/

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "logging.h"

static char g_time_buffer[20]; // Buffer for time output

#define LOG_FORMAT_BUFFER_SIZE 1024

static char* get_formatted_date() {
	time_t time_tmp;
	struct tm* time_s;

	time(&time_tmp);
	time_s = localtime(&time_tmp);

	sprintf(g_time_buffer, "%d/%d/%d %d:%02d:%02d", time_s->tm_year + 1900, time_s->tm_mon + 1,
				time_s->tm_mday, time_s->tm_hour, time_s->tm_min, time_s->tm_sec);
	return g_time_buffer;
}

/*
 * 主要是为了增加日期
 */
void print_log(const char* log_format, ...) {
    char format_buffer[LOG_FORMAT_BUFFER_SIZE];
    va_list argptr;

    va_start(argptr, log_format);
    snprintf(format_buffer, LOG_FORMAT_BUFFER_SIZE, "[%s] %s", get_formatted_date(), log_format);
    vfprintf(stdout, format_buffer, argptr);
    va_end(argptr);
}
