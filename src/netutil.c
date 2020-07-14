#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

#include "ishoal.h"

char *ip_str(ipaddr_t addr)
{
	return inet_ntoa((struct in_addr){ addr });
}

char *mac_str(macaddr_t addr)
{
	static char str[18];
	snprintf(str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		 addr[0],
		 addr[1],
		 addr[2],
		 addr[3],
		 addr[4],
		 addr[5]);
	return str;
}
