bin_PROGRAMS = mentohust

LDADD += -lpthread

sysconfdir = /etc

dist_sysconf_DATA = mentohust.conf

mentohust_SOURCES = myini.c md5.c mycheck.c dlfunc.c myfunc.c mystate.c myconfig.c mentohust.c proxy_util.c

mentohust_SOURCES += i18n.h types.h myini.h md5.h mycheck.h dlfunc.h myfunc.h mystate.h myconfig.h proxy_util.h

mentohust_LDADD = $(LDADD)

