#include <asm/types.h>
#include <arpa/inet.h>
#include <dialog.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>

#include "../src/version.h"

#define max(a,b) ((a)>(b)?(a):(b))

typedef uint32_t ipaddr_t;
typedef unsigned char macaddr_t[ETH_ALEN];

#define CONF_PATH "/etc/ishoal-ipconf"
#define BROADCAST_MAC ((macaddr_t){0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
#define IP_STR_BULEN 16

struct arp_ipv4_payload {
	macaddr_t	ar_sha;
	ipaddr_t	ar_sip;
	macaddr_t	ar_tha;
	ipaddr_t	ar_tip;
} __attribute__((packed));

struct arppkt {
	struct ethhdr eth;
	struct arphdr arph;
	struct arp_ipv4_payload arppl;
} __attribute__((packed));

static struct ishoal_ipconf_conf {
	bool dynamic;
	ipaddr_t ipaddr;
	ipaddr_t netmask;
	ipaddr_t gateway;
} __attribute__((packed)) conf;

static enum ishoal_ipconf_mode {
	MODE_INIT,
	MODE_RECONF,
} mode;

static char *iface;
static int ifindex;
static macaddr_t macaddr;
static int sock;

struct termios start_termios, run_termios;

__attribute__ ((format(printf, 1, 2)))
static void fprintf_exit(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

static void perror_exit(char *msg)
{
	perror(msg);
	exit(1);
}

static void mk_sockaddr_in(struct sockaddr *dst, ipaddr_t addr)
{
	dst->sa_family = AF_INET;
	((struct sockaddr_in *)dst)->sin_addr.s_addr = addr;
}

static bool if_is_up(void)
{
	char path[PATH_MAX];
	snprintf(path, PATH_MAX, "/sys/class/net/%s/operstate", iface);

	FILE *f = fopen(path, "r");
	if (!f)
		perror_exit(path);

	char *operstate;
	if (fscanf(f, "%ms", &operstate) != 1)
		fprintf_exit("%s: Bad format\n", path);

	bool result = !strcmp(operstate, "up");

	free(operstate);
	fclose(f);

	return result;
}

static void wait_link(void)
{
	int rtnlsock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (rtnlsock < 0)
		perror_exit("socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)");

	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK,
	};
	if (bind(rtnlsock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		perror_exit("bind(rtnlsock)");

	// Redundant check to avoid races
	if (if_is_up())
		goto out;

	while (true) {
		struct iovec iov = { 0 };
		struct sockaddr_nl snl;

		// designated initializer is required here because musl uses
		// explicit padding fields wheras glibc does not.
		struct msghdr msg = {
			.msg_name = &snl,
			.msg_namelen = sizeof(snl),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = MSG_TRUNC,
		};

		int status;

		status = recvmsg(rtnlsock, &msg, MSG_PEEK|MSG_TRUNC);
		if (status < 0)
			perror_exit("recvmsg");
		if (!status)
			fprintf_exit("rtnlsock EOF\n");

		char buf[status];
		iov = (struct iovec){ &buf, status };
		msg = (struct msghdr){
			.msg_name = &snl,
			.msg_namelen = sizeof(snl),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = NULL,
			.msg_controllen = 0,
			.msg_flags = 0,
		};

		status = recvmsg(rtnlsock, &msg, 0);
		if (status < 0)
			perror_exit("recvmsg");
		if (!status)
			fprintf_exit("rtnlsock EOF\n");

		for (struct nlmsghdr *h = (void *)buf; NLMSG_OK(h, status); h = NLMSG_NEXT(h, status)) {
			if (h->nlmsg_type != RTM_NEWLINK)
				continue;

			struct ifinfomsg *ifi = NLMSG_DATA(h);
			if (ifi->ifi_index != ifindex)
				continue;

			if (ifi->ifi_flags & IFF_UP)
				goto out;
		}
	}

out:
	close(rtnlsock);
}

static void get_macaddr(void)
{
	struct ifreq ifr;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr))
		perror_exit("ioctl(SIOCGIFHWADDR)");
	memcpy(macaddr, ifr.ifr_hwaddr.sa_data, sizeof(macaddr_t));
}

static void set_ipaddr(ipaddr_t addr)
{
	struct ifreq ifr;

	mk_sockaddr_in(&ifr.ifr_addr, addr);
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(sock, SIOCSIFADDR, &ifr))
		perror_exit("ioctl(SIOCGIFADDR)");
}

static void set_netmask(ipaddr_t addr)
{
	struct ifreq ifr;

	mk_sockaddr_in(&ifr.ifr_addr, addr);
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	if (ioctl(sock, SIOCSIFNETMASK, &ifr))
		perror_exit("ioctl(SIOCGIFNETMASK)");
}

static void clear_routes(void)
{
	while (true) {
		struct rtentry rt = {
			.rt_flags = RTF_GATEWAY,
			.rt_dev = iface,
		};
		mk_sockaddr_in(&rt.rt_dst, 0);
		mk_sockaddr_in(&rt.rt_genmask, 0);

		if (!ioctl(sock, SIOCDELRT, &rt))
			continue;

		if (errno != ESRCH)
			perror_exit("ioctl(SIOCDELRT)");
		break;
	}
}

static void set_gateway(ipaddr_t addr)
{
	clear_routes();

	struct rtentry rt = {
		.rt_flags = RTF_GATEWAY,
		.rt_dev = iface,
	};

	mk_sockaddr_in(&rt.rt_dst, 0);
	mk_sockaddr_in(&rt.rt_genmask, 0);
	mk_sockaddr_in(&rt.rt_gateway, addr);

	if (ioctl(sock, SIOCADDRT, &rt))
		perror_exit("ioctl(SIOCADDRT)");
}

static bool netmask_valid(ipaddr_t addr)
{
	if (!addr)
		return false;

	addr = ntohl(addr);

	// https://stackoverflow.com/q/17401067
	return !(addr & (~addr >> 1));
}

static bool addr_in_use(ipaddr_t addr)
{
	bool result = false;

	int arpsock = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ARP));
	if (arpsock < 0)
		perror_exit("socket(AF_PACKET, SOCK_RAW)");

	struct sockaddr_ll addr_bind = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ARP),
		.sll_ifindex = ifindex,
		.sll_hatype = htons(ARPHRD_ETHER),
		.sll_pkttype = PACKET_HOST,
		.sll_halen = sizeof(macaddr_t),
	};
	memcpy(addr_bind.sll_addr, macaddr, sizeof(macaddr_t));

	if (bind(arpsock, (struct sockaddr *)&addr_bind, sizeof(addr_bind)))
		perror_exit("bind");

	/* Min L2 frame size: 64 bytes w/ 4 bytes CRC added by driver */
	char arp_request_buf[max(sizeof(struct arppkt), 60)] = {0};
	struct arppkt *arp_request = (void *)arp_request_buf;

	memcpy(arp_request->eth.h_dest, BROADCAST_MAC, sizeof(macaddr_t));
	memcpy(arp_request->eth.h_source, macaddr, sizeof(macaddr_t));
	arp_request->eth.h_proto = htons(ETH_P_ARP);

	arp_request->arph.ar_hrd = htons(ARPHRD_ETHER);
	arp_request->arph.ar_pro = htons(ETH_P_IP);
	arp_request->arph.ar_hln = 6;
	arp_request->arph.ar_pln = 4;
	arp_request->arph.ar_op = htons(ARPOP_REQUEST);

	memcpy(arp_request->arppl.ar_sha, macaddr, sizeof(macaddr_t));
	arp_request->arppl.ar_sip = 0;
	memset(arp_request->arppl.ar_tha, 0, sizeof(macaddr_t));
	arp_request->arppl.ar_tip = addr;

	if (send(arpsock, arp_request, sizeof(arp_request_buf), 0) < 0)
		perror_exit("send");

	while (true) {
		struct pollfd pfds = { .fd = arpsock, .events = POLLIN };
		int pollres = poll(&pfds, 1, 1000);

		if (pollres < 0)
			perror_exit("poll");
		else if (!pollres)
			goto out;

		struct arppkt arp_response;
		ssize_t recvsize = recv(arpsock, &arp_response, sizeof(arp_response), 0);
		if (recvsize < 0)
			perror_exit("recv");
		if (recvsize != sizeof(arp_response))
			continue;

		if (arp_response.eth.h_proto != htons(ETH_P_ARP))
			continue;

		if (arp_response.arph.ar_pro != htons(ETH_P_IP) ||
		    arp_response.arph.ar_hln != 6 ||
		    arp_response.arph.ar_pln != 4 ||
		    arp_response.arph.ar_op != htons(ARPOP_REPLY))
			continue;

		if (arp_response.arppl.ar_sip != addr)
			continue;

		result = true;
		goto out;
	}

out:
	close(arpsock);
	return result;
}

static void arp_announce(void)
{
	int arpsock = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ARP));
	if (arpsock < 0)
		perror_exit("socket(AF_PACKET, SOCK_RAW)");

	struct sockaddr_ll addr_bind = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ARP),
		.sll_ifindex = ifindex,
		.sll_hatype = htons(ARPHRD_ETHER),
		.sll_pkttype = PACKET_HOST,
		.sll_halen = sizeof(macaddr_t),
	};
	memcpy(addr_bind.sll_addr, macaddr, sizeof(macaddr_t));

	if (bind(arpsock, (struct sockaddr *)&addr_bind, sizeof(addr_bind)))
		perror_exit("bind");

	/* Min L2 frame size: 64 bytes w/ 4 bytes CRC added by driver */
	char arp_request_buf[max(sizeof(struct arppkt), 60)] = {0};
	struct arppkt *arp_request = (void *)arp_request_buf;

	memcpy(arp_request->eth.h_dest, BROADCAST_MAC, sizeof(macaddr_t));
	memcpy(arp_request->eth.h_source, macaddr, sizeof(macaddr_t));
	arp_request->eth.h_proto = htons(ETH_P_ARP);

	arp_request->arph.ar_hrd = htons(ARPHRD_ETHER);
	arp_request->arph.ar_pro = htons(ETH_P_IP);
	arp_request->arph.ar_hln = 6;
	arp_request->arph.ar_pln = 4;
	arp_request->arph.ar_op = htons(ARPOP_REQUEST);

	memcpy(arp_request->arppl.ar_sha, macaddr, sizeof(macaddr_t));
	arp_request->arppl.ar_sip = conf.ipaddr;
	memset(arp_request->arppl.ar_tha, 0, sizeof(macaddr_t));
	arp_request->arppl.ar_tip = conf.ipaddr;

	if (send(arpsock, arp_request, sizeof(arp_request_buf), 0) < 0)
		perror_exit("send");

	close(arpsock);
}

static bool dhcp_attempt(void)
{
	pid_t child = fork();
	if (child) {
		while (true) {
			int wstatus;
			pid_t w = waitpid(child, &wstatus, WUNTRACED | WCONTINUED);

			if (w < 0) {
				if (errno == ERESTART || errno == EINTR)
					continue;
				perror_exit("waitpid");
			}

			if (WIFEXITED(wstatus)) {
				return !WEXITSTATUS(wstatus);
			} else if (WIFSIGNALED(wstatus)) {
				return false;
			}
		}
	} else {
		int devnull = open("/dev/null", O_RDONLY);
		if (devnull < 0)
			perror_exit("/dev/null");
		if (dup2(devnull, STDIN_FILENO) < 0)
			perror_exit("dup2");
		close(devnull);

		int logfile = open("/var/log/udhcpc.log",
				   O_WRONLY | O_CREAT | O_APPEND,
				   0644);
		if (logfile < 0)
			perror_exit("/var/log/udhcpc.log");
		if (dup2(logfile, STDOUT_FILENO) < 0)
			perror_exit("dup2");
		if (dup2(logfile, STDERR_FILENO) < 0)
			perror_exit("dup2");
		close(logfile);

		execl("/bin/busybox", "udhcpc", "-i", iface, "-q", "-n", "-f", NULL);
		_exit(127);
	}
}

static void load_conf(void)
{
	if (access(CONF_PATH, R_OK)) {
		conf = (struct ishoal_ipconf_conf) {
			.dynamic = true,
			.netmask = inet_addr("255.255.255.0"),
		};

		return;
	}

	FILE *f = fopen(CONF_PATH, "r");
	if (!f)
		perror_exit(CONF_PATH);

	(void)!fread(&conf, sizeof(conf), 1, f);
	fclose(f);
}

static void save_conf(void)
{
	FILE *f = fopen(CONF_PATH, "w");
	if (!f)
		perror_exit(CONF_PATH);

	fwrite(&conf, sizeof(conf), 1, f);
	fclose(f);
}

static char *ip_str(ipaddr_t addr)
{
	char *str = calloc(IP_STR_BULEN, 1);
	if (!str)
		perror_exit("calloc");

	if (addr) {
		addr = ntohl(addr);
		snprintf(str, IP_STR_BULEN, "%hhu.%hhu.%hhu.%hhu",
			 (uint8_t)((addr & 0xFF000000) >> 24),
			 (uint8_t)((addr & 0x00FF0000) >> 16),
			 (uint8_t)((addr & 0x0000FF00) >> 8),
			 (uint8_t)(addr & 0x000000FF));
	}

	return str;
}

static void tui_clear(void)
{
	dlg_clear();

	dialog_vars.backtitle = "IShoal " ISHOAL_VERSION_STR " - VM Networking Setup";
	dlg_put_backtitle();
}

static void tui_reset(void)
{
	end_dialog();

	mouse_close();
	(void)endwin();

	fflush(stdout);

	// https://stackoverflow.com/a/7660837/13673228
	const char *CLEAR_SCREEN_ANSI = "\e[1;1H\e[2J";
	(void)!write(1, CLEAR_SCREEN_ANSI, 10);
}

static void reset_termios(void)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &start_termios);
}

int main(int argc, char *argv[])
{
	if (argc != 3)
		goto usage;

	iface = argv[1];
	ifindex = if_nametoindex(iface);
	if (!ifindex)
		perror_exit(iface);

	if (!strcmp(argv[2], "init"))
		mode = MODE_INIT;
	else if (!strcmp(argv[2], "reconf"))
		mode = MODE_RECONF;
	else
		goto usage;

	load_conf();

	sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		perror_exit("socket(AF_INET, SOCK_DGRAM, 0)");

	get_macaddr();

	if (tcgetattr(STDIN_FILENO, &start_termios))
		perror_exit("tcgetattr");

	atexit(reset_termios);

	init_dialog(stdin, stdout);
	dialog_vars.default_button = -1;
	dialog_vars.begin_set = false;

	if (tcgetattr(STDIN_FILENO, &run_termios))
		perror_exit("tcgetattr");

	run_termios.c_lflag &= ~(ISIG | IXON | IXOFF);
	run_termios.c_cc[VINTR] = _POSIX_VDISABLE;
	run_termios.c_cc[VQUIT] = _POSIX_VDISABLE;
	run_termios.c_cc[VSTOP] = _POSIX_VDISABLE;
	run_termios.c_cc[VSUSP] = _POSIX_VDISABLE;

	if (tcsetattr(STDIN_FILENO, TCSANOW, &run_termios))
		perror_exit("tcsetattr");

	if (!if_is_up()) {
		tui_clear();
		dialog_msgbox("Setup", "\nWaiting for link to be up ...", 5, 35, 0);

		wait_link();
	}

	/* Enable promiscuous mode in order to workaround VirtualBox WiFi issues */
	int promisc_sock = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (promisc_sock < 0)
		perror_exit("socket(AF_PACKET, SOCK_RAW)");

	struct packet_mreq mreq = {
		.mr_ifindex = ifindex,
		.mr_type = PACKET_MR_PROMISC,
	};
	if (setsockopt(promisc_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       &mreq, sizeof(mreq)))
		perror_exit("setsockopt");

	int res, choice = 0, current_item = 0;

	switch (mode) {
	case MODE_INIT:
		if (conf.dynamic)
			goto state_dhcp_attempt;
		else
			goto state_static_attempt;
	case MODE_RECONF:
		goto state_menu;
	}

state_dhcp_attempt:
	tui_clear();
	dialog_msgbox("Setup", "\nConfiguring with DHCP ...", 5, 30, 0);

	if (!dhcp_attempt()) {
		dialog_vars.extra_button = true;
		dialog_vars.ok_label = "Retry";
		dialog_vars.extra_label = "Static IP";
		dialog_vars.cancel_label = "Menu";
		res = dialog_yesno("Setup", "\nAutomatic network configuration failed.", 7, 45);
		dialog_vars.extra_button = false;
		dialog_vars.ok_label = dialog_vars.cancel_label = NULL;

		switch (res) {
		case DLG_EXIT_OK:
			goto state_dhcp_attempt;
		case DLG_EXIT_EXTRA:
			goto state_static_menu;
		default: // DLG_EXIT_CANCEL
			goto state_menu;
		}
	}

	goto done;

state_static_attempt:
	tui_clear();
	dialog_msgbox("Setup", "\nConfiguring VM network ...", 5, 30, 0);
	if (addr_in_use(conf.ipaddr)) {
		dialog_vars.extra_button = true;
		dialog_vars.ok_label = "Edit";
		dialog_vars.extra_label = "Retry";
		dialog_vars.cancel_label = "Menu";
		res = dialog_yesno("Setup", "\nIP collision detected.", 7, 40);
		dialog_vars.extra_button = false;
		dialog_vars.ok_label = dialog_vars.cancel_label = NULL;

		switch (res) {
		case DLG_EXIT_OK:
			current_item = 0;
			goto state_static_menu_loop;
		case DLG_EXIT_EXTRA:
			goto state_static_attempt;
		default: // DLG_EXIT_CANCEL
			goto state_menu;
		}
	}

	if (!netmask_valid(conf.netmask)) {
		dialog_vars.yes_label = "Edit";
		dialog_vars.no_label = "Menu";
		res = dialog_yesno("Setup", "\nInvalid subnet mask.", 7, 30);
		dialog_vars.ok_label = dialog_vars.cancel_label = NULL;

		switch (res) {
		case DLG_EXIT_OK:
			current_item = 1;
			goto state_static_menu_loop;
		default: // DLG_EXIT_CANCEL
			goto state_menu;
		}
	}

	if ((conf.ipaddr & conf.netmask) != (conf.gateway & conf.netmask) ||
	    conf.ipaddr == conf.gateway) {
		dialog_vars.yes_label = "Edit";
		dialog_vars.no_label = "Menu";
		res = dialog_yesno("Setup", "\nInvalid gateway.", 7, 30);
		dialog_vars.ok_label = dialog_vars.cancel_label = NULL;

		switch (res) {
		case DLG_EXIT_OK:
			current_item = 2;
			goto state_static_menu_loop;
		default: // DLG_EXIT_CANCEL
			goto state_menu;
		}
	}

	if (!addr_in_use(conf.gateway)) {
		dialog_vars.extra_button = true;
		dialog_vars.ok_label = "Edit";
		dialog_vars.extra_label = "Retry";
		dialog_vars.cancel_label = "Menu";
		res = dialog_yesno("Setup", "\nGateway not found.", 7, 40);
		dialog_vars.extra_button = false;
		dialog_vars.ok_label = dialog_vars.cancel_label = NULL;

		switch (res) {
		case DLG_EXIT_OK:
			current_item = 2;
			goto state_static_menu_loop;
		case DLG_EXIT_EXTRA:
			goto state_static_attempt;
		default: // DLG_EXIT_CANCEL
			goto state_menu;
		}
	}

	set_ipaddr(conf.ipaddr);
	set_netmask(conf.netmask);
	set_gateway(conf.gateway);

	arp_announce();

	conf.dynamic = false;
	goto done;

state_static_menu:
	current_item = 0;
state_static_menu_loop:
	; // workaround for "a label can only be part of a statement"

	char *ipaddr_str = ip_str(conf.ipaddr);
	char *netmask_str = ip_str(conf.netmask);
	char *gateway_str = ip_str(conf.gateway);

	DIALOG_FORMITEM items[] = {
		{
			.type = 0,
			.name = "VM IP Address:",
			.name_len = strlen("VM IP Address:"),
			.name_y = 0,
			.name_x = 0,
			.name_free = false,
			.text = ipaddr_str,
			.text_len = strlen(ipaddr_str),
			.text_y = 0,
			.text_x = 17,
			.text_flen = 16,
			.text_ilen = 0,
			.text_free = true,
			.help = dlg_strempty(),
			.help_free = false
		},
		{
			.type = 0,
			.name = "Subnet Mask:",
			.name_len = strlen("Subnet Mask:"),
			.name_y = 1,
			.name_x = 0,
			.name_free = false,
			.text = netmask_str,
			.text_len = strlen(netmask_str),
			.text_y = 1,
			.text_x = 17,
			.text_flen = 16,
			.text_ilen = 0,
			.text_free = true,
			.help = dlg_strempty(),
			.help_free = false
		},
		{
			.type = 0,
			.name = "Default Gateway:",
			.name_len = strlen("Default Gateway:"),
			.name_y = 2,
			.name_x = 0,
			.name_free = false,
			.text = gateway_str,
			.text_len = strlen(gateway_str),
			.text_y = 2,
			.text_x = 17,
			.text_flen = 16,
			.text_ilen = 0,
			.text_free = true,
			.help = dlg_strempty(),
			.help_free = false
		},
	};

state_static_menu_loop_invalid:
	dialog_vars.default_item = items[current_item].name;

	tui_clear();
	res = dlg_form("Setup", "Enter network configuration:", 10, 40, 0, 3, items, &current_item);
	if (res)
		goto state_menu;

	ipaddr_t ipaddr;
	ipaddr_t netmask;
	ipaddr_t gateway;
	char *invalid_msg;

	if (inet_pton(AF_INET, items[0].text, &ipaddr) != 1 ||
	    !ipaddr || ipaddr == 0xFFFFFFFF) {
		current_item = 0;
		invalid_msg = "\nInvalid IP address for VM.";
		goto state_static_menu_invalid;
	}

	if (inet_pton(AF_INET, items[1].text, &netmask) != 1 ||
	    !netmask || netmask == 0xFFFFFFFF) {
		current_item = 1;
		invalid_msg = "\nInvalid IP address for subnet mask.";
		goto state_static_menu_invalid;
	}

	if (inet_pton(AF_INET, items[2].text, &gateway) != 1 ||
	    !gateway || gateway == 0xFFFFFFFF) {
		current_item = 2;
		invalid_msg = "\nInvalid IP address for default gateway.";
		goto state_static_menu_invalid;
	}

	conf.ipaddr = ipaddr;
	conf.netmask = netmask;
	conf.gateway = gateway;

	free(items[0].text);
	free(items[1].text);
	free(items[2].text);

	goto state_static_attempt;

state_static_menu_invalid:
	dialog_msgbox("Setup", invalid_msg, 7, 45, 1);
	goto state_static_menu_loop_invalid;

state_menu:
	choice = 0;
state_menu_loop:
	tui_clear();
	dialog_vars.nocancel = true;

	DIALOG_LISTITEM choices[] = {
		{"1", conf.dynamic ?
			"Change to static IP (currently dynamic)" :
			"Change to dynamic IP (currently static)",
		      dlg_strempty()},
		{"2", conf.dynamic ?
			"Reconfigure dynamic IP" :
			"Reconfigure static IP",
		      dlg_strempty()},
		{"3", "Shutdown the VM", dlg_strempty()},
		{"4", "Start a Shell", dlg_strempty()},
		{"5", "Reboot the VM", dlg_strempty()},
	};

	dialog_vars.default_item = choices[choice].name;
	res = dlg_menu("Setup", "Please select an option:", 8, 50, 0, 5,
		 choices, &choice, dlg_dummy_menutext);
	if (res)
		goto state_menu_loop;

	dialog_state.plain_buttons = false;
	dialog_vars.nocancel = false;

	switch (choice) {
	case 0:
		if (conf.dynamic) {
			goto state_static_menu;
		} else {
			conf.dynamic = true;
			goto state_dhcp_attempt;
		}
	case 1:
		if (conf.dynamic)
			goto state_dhcp_attempt;
		else
			goto state_static_menu;
	case 2:
		dialog_vars.begin_set = false;
		res = dialog_yesno("Setup",
				   "\nDo you really want to shutdown the VM?",
				   8, 40);
		if (res)
			goto state_menu;

		tui_reset();
		sync();
		(void)!system("poweroff");

		while (true)
			pause();
	case 3:
		tui_reset();

		if (tcsetattr(STDIN_FILENO, TCSANOW, &start_termios))
			perror_exit("tcsetattr");

		printf("Please type 'exit' to exit the shell.\n");
		fflush(stdout);

		pid_t child = fork();
		if (child) {
			int wstatus;
			while (waitpid(child, &wstatus, 0) == child) {
				if (errno == ERESTART || errno == EINTR)
					continue;
				break;
			}
		} else {
			execl("/bin/sh", "-sh", NULL);
			_exit(127);
		}

		init_dialog(stdin, stdout);

		tui_clear();
		refresh();

		if (tcsetattr(STDIN_FILENO, TCSANOW, &run_termios))
			perror_exit("tcsetattr");

		goto state_menu;
	case 4:
		dialog_vars.begin_set = false;
		res = dialog_yesno("Setup",
				   "\nDo you really want to reboot the VM?",
				   8, 40);

		tui_reset();
		sync();
		(void)!system("reboot");

		while (true)
			pause();
	}

done:
	tui_reset();
	save_conf();

	return 0;

usage:
	fprintf_exit("Usage: %s [interface] <init|reconf>\n", argv[0]);
}
