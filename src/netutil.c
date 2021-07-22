#include "features.h"

#include <arpa/inet.h>
#include <stdio.h>

#include "ishoal.h"

void ip_str(const ipaddr_t addr, char *str)
{
	uint32_t addr_h = ntohl(addr);
	snprintf(str, IP_STR_BULEN, "%hhu.%hhu.%hhu.%hhu",
		 (uint8_t)((addr_h & 0xFF000000) >> 24),
		 (uint8_t)((addr_h & 0x00FF0000) >> 16),
		 (uint8_t)((addr_h & 0x0000FF00) >> 8),
		 (uint8_t)(addr_h & 0x000000FF));
}

void mac_str(const macaddr_t addr, char *str)
{
	snprintf(str, MAC_STR_BULEN, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		 addr[0],
		 addr[1],
		 addr[2],
		 addr[3],
		 addr[4],
		 addr[5]);
}
