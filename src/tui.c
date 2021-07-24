#include "features.h"

#define NCURSES_OPAQUE 0
#include <ncursesw/ncurses.h>

#include <arpa/inet.h>
#include <dialog.h>
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <linux/limits.h>
#include <pthread.h>
#include <setjmp.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>

#include "extern/plthook/plthook.h"

#include "ishoal.h"

static char remotes_path[PATH_MAX];
static int remotes_inotifyeventfd;

static char title_str[100];
static bool is_online;

static struct eventloop *tui_el;

static jmp_buf exit_jmp;

static int (*real_wget_wch)(WINDOW *win, wint_t *wch);
static int (*real_wgetch)(WINDOW *win);

static struct termios start_termios, run_termios;

static void reset_termios(void)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &start_termios);
}

static void recompute_title(void);

static void tui_el_exit_cb(int fd, void *_ctx, bool expired)
{
	longjmp(exit_jmp, 1);
}

static void tui_on_switch_change(int fd, void *_ctx, bool expired)
{
	recompute_title();
	refresh();
}

static void tui_on_xsk_pkt(int fd, void *_ctx, bool expired)
{
	if (!is_online) {
		is_online = true;

		recompute_title();
		refresh();
	}
}

static struct event tui_global_events[] = {
	{
		.eventfd_ack = true,
		.handler_type = EVT_CALL_FN,
		.handler_fn = tui_el_exit_cb,
	},
	{
		.eventfd_ack = true,
		.handler_type = EVT_CALL_FN,
		.handler_fn = tui_on_switch_change,
	},
	{
		.eventfd_ack = true,
		.handler_type = EVT_CALL_FN,
		.handler_fn = tui_on_xsk_pkt,
	}
};

// https://stackoverflow.com/a/12502754
static int same_file(int fd1, int fd2)
{
	struct stat stat1, stat2;

	if (fstat(fd1, &stat1) < 0)
		perror_exit("fstat");
	if (fstat(fd2, &stat2) < 0)
		perror_exit("fstat");

	return stat1.st_dev == stat2.st_dev && stat1.st_ino == stat2.st_ino;
}

static void wgetch_el()
{
	eventloop_clear_events(tui_el);
	eventloop_install_break(tui_el, STDIN_FILENO);

	DIALOG_CALLBACK *p;
	for (p = dialog_state.getc_callbacks; p != 0; p = p->next)
		if (p->input) {
			int fd = fileno(p->input);

			if (same_file(fd, remotes_log_fd))
				eventloop_install_event_sync(tui_el, &(struct event){
					.fd = remotes_inotifyeventfd,
					.eventfd_ack = true,
					.handler_type = EVT_BREAK,
				});
			else
				eventloop_install_break(tui_el, fd);
		}

	for (int i = 0; i < ARRAY_SIZE(tui_global_events); i++)
		eventloop_install_event_sync(tui_el, &tui_global_events[i]);

	eventloop_enter(tui_el, -1);
}

static int wrapper_wget_wch(WINDOW *win, wint_t *wch)
{
	if (win) {
		int old_delay = win->_delay;
		nodelay(win, true);

		int res = real_wget_wch(win, wch);

		wtimeout(win, old_delay);

		if (res != ERR)
			return res;

		wgetch_el();
	}

	return real_wget_wch(win, wch);
}

static int wrapper_wgetch(WINDOW *win)
{
	if (win) {
		int old_delay = win->_delay;
		nodelay(win, true);

		int res = real_wgetch(win);

		wtimeout(win, old_delay);

		if (res != ERR)
			return res;

		wgetch_el();
	}

	return real_wgetch(win);
}

struct dl_iterate_phdr_ctx {
	char libdialog_path[PATH_MAX];
};

static int
dl_iterate_phdr_cb(struct dl_phdr_info *info, size_t size, void *_ctx)
{
	struct dl_iterate_phdr_ctx *ctx = _ctx;

	if (strstr(info->dlpi_name, "libdialog"))
		strncpy(ctx->libdialog_path, info->dlpi_name, PATH_MAX - 1);

	return 0;
}

static void monkey_patch()
{
	struct dl_iterate_phdr_ctx ctx = {0};
	dl_iterate_phdr(dl_iterate_phdr_cb, &ctx);

	if (!strlen(ctx.libdialog_path))
		fprintf_exit("failed to locate libdialog library path\n");

	real_wget_wch = dlsym(RTLD_DEFAULT, "wget_wch");
	real_wgetch = dlsym(RTLD_DEFAULT, "wgetch");

	plthook_t *plthook;

	if (plthook_open(&plthook, ctx.libdialog_path) != 0)
		fprintf_exit("plthook_open error: %s\n", plthook_error());

	bool has_replace = false;
	if (real_wget_wch && !plthook_replace(plthook, "wget_wch",
					      wrapper_wget_wch, NULL))
		has_replace = true;
	if (real_wgetch && !plthook_replace(plthook, "wgetch",
					    wrapper_wgetch, NULL))
		has_replace = true;
	if (!has_replace)
		fprintf_exit("failed to hook ncurses\n");

	plthook_close(plthook);
}

// sleep, but exit-aware
static void tui_sleep(int ms)
{
	eventloop_clear_events(tui_el);
	eventloop_install_break(tui_el, tui_global_events[1].fd);
	eventloop_install_break(tui_el, tui_global_events[2].fd);

	eventloop_install_event_sync(tui_el, &(struct event){
		.fd = thread_stop_eventfd(current),
		.eventfd_ack = true,
		.handler_type = EVT_CALL_FN,
		.handler_fn = tui_el_exit_cb,
	});

	eventloop_enter(tui_el, ms);
}

static void tui_reset(void)
{
	int res;
	dlg_killall_bg(&res);
	end_dialog();

	mouse_close();
	(void)endwin();

	fflush(stdout);

	// https://stackoverflow.com/a/7660837/13673228
	const char *CLEAR_SCREEN_ANSI = "\e[1;1H\e[2J";
	(void)!write(STDOUT_FILENO, CLEAR_SCREEN_ANSI, 10);
}

static void recompute_title(void)
{
	if (!switch_ip)
		strncpy(title_str,
			"IShoal " ISHOAL_VERSION_STR " - "
			"Switch has not been detected, yet.", 100);
	else {
		char ip[IP_STR_BULEN];
		char mac[MAC_STR_BULEN];

		ip_str(switch_ip, ip);
		mac_str(switch_mac, mac);

		snprintf(title_str, 100,
			"IShoal " ISHOAL_VERSION_STR " - "
			"Switch is %s at: %s (%s)",
			 is_online ? "online" : "offline",
			 mac,
			 ip
		);
	}

	dialog_vars.backtitle = title_str;
	dlg_put_backtitle();
}

static void tui_clear(void)
{
	int res;
	dlg_killall_bg(&res);

	dlg_clear();

	recompute_title();
}

static void detect_switch_online(void)
{
	is_online = false;

	dialog_vars.begin_set = false;
	dialog_msgbox("Setup", "\nDetecting status of local Switch ...", 5, 40, 0);

	tui_sleep(2500);
}

static void detect_local_switch(void)
{
	bpf_set_switch_ip(0);
	bpf_set_switch_mac((macaddr_t){0});

	dialog_vars.begin_set = false;
	dialog_msgbox("Setup",
		      "\nPlease enter the shoal now, then enter LAN mode "
		      "(Hold L+R, then press down the left thumbstick) "
		      "and try to find a room ...", 10, 40, 1);
	tui_clear();

	int res;

	while (true) {
		dialog_state.pipe_input = NULL;
		void *gauge;
		gauge = dlg_allocate_gauge("Setup",
					   "\nSearching for local Switch ...",
					   9, 40, 0);

		for (int i = 1; i <= 100; i++) {
			tui_sleep(50);

			if (switch_ip)
				break;
			dlg_update_gauge(gauge, i);
		}

		dlg_free_gauge(gauge);
		tui_clear();

		if (!switch_ip) {
			res = dialog_yesno("Setup",
					   "\nCould not find local Switch. "
					   "Do you want to try again?", 8, 40);
			if (res)
				break;
		} else
			break;
	}

	if (switch_ip) {
		char ip[IP_STR_BULEN];
		char mac[MAC_STR_BULEN];
		char buf[100];

		ip_str(switch_ip, ip);
		mac_str(switch_mac, mac);

		snprintf(buf, 100, "\nFound local Switch:\n\n%s (%s)",
			 ip, mac);
		dialog_msgbox("Setup", buf, 9, 40, 1);
	}

	save_conf();
}

static bool check_updates(void) {
	dialog_vars.begin_set = false;
	dialog_msgbox("Update", "\nChecking for updates ...", 5, 30, 0);

	char **newver;
	struct ishoalc_check_update {
		unsigned int cmd;
		char ***destvar;
	} check_msg = { ISHOALC_RPC_CHECK_FOR_UPDATES, &newver };

	int res;
	res = python_rpc(&check_msg, sizeof(check_msg));

	tui_clear();

	if (res < 0) {
		dialog_msgbox("Update", "\nFailed checking update.", 7, 30, 1);
		return false;
	}
	if (res == 0) {
		dialog_msgbox("Update", "\nNo update available.", 7, 30, 1);
		return false;
	}

	char *msg;
	if (asprintf(&msg, "\nNew version %s available. Do you want to update?",
		     *newver) < 0)
		perror_exit("asprintf");
	res = dialog_yesno("Update", msg, 8, 40);

	free(msg);
	free(*newver);

	if (res)
		return false;

	tui_clear();
	dialog_msgbox("Update", "\nDownloading update ...", 5, 30, 0);

	int init_msg = ISHOALC_RPC_INIT_UPDATE;
	res = python_rpc(&init_msg, sizeof(init_msg));

	tui_clear();

	if (res < 0) {
		dialog_msgbox("Update", "\nFailed downloading update.", 7, 30, 1);
		return false;
	}

	return true;
}

static void __set_fake_gateway_ip(ipaddr_t new_gateway_ip)
{
	bpf_set_fake_gateway_ip(new_gateway_ip);
	save_conf();
}

struct tui_rau_ctx {
	int done_eventfd;
	bool solved;
	struct resolve_arp_user rau;
};

static void rau_cb(bool solved, void *_ctx)
{
	struct tui_rau_ctx *ctx = _ctx;

	ctx->solved = solved;

	if (eventfd_write(ctx->done_eventfd, 1))
		perror_exit("eventfd_write");
}

static void switch_gw_dialog(void)
{
	ipaddr_t new_gateway_ip = 0;
	char tmpbuf[IP_STR_BULEN];
	int res;

	dialog_vars.begin_set = false;
	res = dialog_yesno("Setup",
			   "\nDo you want to setup the VM as a Gateway?\n\n"
			   "This is needed for example when your local network "
			   "does not use the 192.168.1.0 subnet.", 12, 40);
	if (res)
		goto out;

	new_gateway_ip = fake_gateway_ip ? : htonl(0xc0a80101);

reenter:
	tui_clear();

	dialog_vars.nocancel = false;

	ip_str(new_gateway_ip, tmpbuf);
	while (true) {
		tui_clear();

		res = dialog_inputbox("Setup",
				      "Please enter the IP this VM should use "
				      "for the GW functionality (normally 192.168.1.1):\n",
				      10, 40, tmpbuf, 0);
		if (res)
			return;

		if (inet_pton(AF_INET, dialog_vars.input_result, &new_gateway_ip) != 1)
			goto invalid_ip;

		if (!new_gateway_ip || new_gateway_ip == 0xFFFFFFFF)
			goto invalid_ip;

		break;
invalid_ip:
		dialog_msgbox("Setup", "Invalid IP address", 7, 40, 1);
		snprintf(tmpbuf, IP_STR_BULEN, "%s", dialog_vars.input_result);
		continue;
	}

out:
	if (new_gateway_ip) {
		dialog_vars.begin_set = false;
		dialog_msgbox("Setup", "\nDetecting IP collision ...", 5, 40, 0);

		eventloop_clear_events(tui_el);
		eventloop_install_event_sync(tui_el, &(struct event){
			.fd = thread_stop_eventfd(current),
			.eventfd_ack = true,
			.handler_type = EVT_CALL_FN,
			.handler_fn = tui_el_exit_cb,
		});

		struct tui_rau_ctx *ctx = calloc(1, sizeof(*ctx));
		if (!ctx)
			perror_exit("calloc");

		ctx->done_eventfd = eventfd(0, EFD_CLOEXEC);
		if (ctx->done_eventfd < 0)
			perror_exit("eventfd");

		eventloop_install_break(tui_el, ctx->done_eventfd);

		ctx->rau.ipaddr = new_gateway_ip;
		ctx->rau.el = tui_el;
		ctx->rau.cb = rau_cb;
		ctx->rau.ctx = ctx;
		resolve_arp_user(&ctx->rau);

		eventloop_enter(tui_el, -1);

		close(ctx->done_eventfd);
		bool solved = ctx->solved;
		free(ctx);

		if (!solved) {
			__set_fake_gateway_ip(new_gateway_ip);
			return;
		}

		res = dialog_yesno("Setup",
				   "\nIP collision detected. Do you want to "
				   "enter another IP?\n\n", 8, 40);
		if (!res)
			goto reenter;
	} else {
		__set_fake_gateway_ip(new_gateway_ip);
	}
}

static void switch_information_dialog(void)
{
	char ip[IP_STR_BULEN];
	char mac[MAC_STR_BULEN];
	int res;

	ipaddr_t new_switch_ip = switch_ip;
	macaddr_t new_switch_mac;
	memcpy(new_switch_mac, switch_mac, sizeof(macaddr_t));

	dialog_vars.nocancel = false;
	dialog_vars.begin_set = false;

	mac_str(new_switch_mac, mac);
	if ((new_switch_mac[0] | new_switch_mac[1] |
	     new_switch_mac[2] | new_switch_mac[3] |
	     new_switch_mac[4] | new_switch_mac[5]) == 0)
		mac[0] = 0;

	while (true) {
		tui_clear();

		res = dialog_inputbox("Setup",
				      "Please enter the MAC address of the Switch:\n",
				      10, 40, mac, 0);
		if (res)
			return;

		if (strlen(dialog_vars.input_result) != 17)
			goto invalid_mac;

		res = sscanf(dialog_vars.input_result, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			     &new_switch_mac[0],
			     &new_switch_mac[1],
			     &new_switch_mac[2],
			     &new_switch_mac[3],
			     &new_switch_mac[4],
			     &new_switch_mac[5]);

		if (res != 6)
			goto invalid_mac;

		if ((new_switch_mac[0] | new_switch_mac[1] |
		     new_switch_mac[2] | new_switch_mac[3] |
		     new_switch_mac[4] | new_switch_mac[5]) == 0)
			goto invalid_mac;

		if ((new_switch_mac[0] & new_switch_mac[1] &
		     new_switch_mac[2] & new_switch_mac[3] &
		     new_switch_mac[4] & new_switch_mac[5]) == 0xff)
			goto invalid_mac;

		if (new_switch_mac[0] & 1)
			goto invalid_mac;

		break;

invalid_mac:
		dialog_msgbox("Setup", "Invalid MAC address", 7, 40, 1);
		snprintf(mac, MAC_STR_BULEN, "%s", dialog_vars.input_result);
		continue;
	}

	if (new_switch_ip)
		ip_str(new_switch_ip, ip);
	else
		ip[0] = 0;
	while (true) {
		tui_clear();

		res = dialog_inputbox("Setup",
				      "Please enter the IP address of the Switch:\n",
				      10, 40, ip, 0);
		if (res)
			return;

		if (inet_pton(AF_INET, dialog_vars.input_result, &new_switch_ip) != 1)
			goto invalid_ip;

		if (!new_switch_ip || new_switch_ip == 0xFFFFFFFF)
			goto invalid_ip;

		break;
invalid_ip:
		dialog_msgbox("Setup", "Invalid IP address", 7, 40, 1);
		snprintf(ip, IP_STR_BULEN, "%s", dialog_vars.input_result);
		continue;
	}

	char msg[110];

	ip_str(new_switch_ip, ip);
	mac_str(new_switch_mac, mac);

	snprintf(msg, 110, "You entered that your Switch can be found at:\n"
		 "\n%s (%s).\n\nIs that correct?",
		 mac, ip);
	res = dialog_yesno("Setup", msg, 10, 40);
	if (res)
		return;

	bpf_set_switch_ip(new_switch_ip);
	bpf_set_switch_mac(new_switch_mac);

	save_conf();
}

static void crash_entry_dialog(void)
{
	int res;

	dialog_vars.nocancel = false;
	dialog_vars.begin_set = false;

	res = dialog_inputbox("Crash", "Please cancel (or \npress Esc twice).\n", 8, 22, NULL, 0);
	if (res)
		return;

	if (!trigger_crash_init(dialog_vars.input_result))
		return;

	dialog_vars.begin_set = false;
	dialog_msgbox("Setup", "\nTriggering crash ... did anything happen?", 5, 50, 0);

	trigger_crash_exec();

	tui_sleep(2500);

	return;
}

void tui_thread_fn(void *arg)
{
	int res;

	if (tcgetattr(STDIN_FILENO, &start_termios))
		perror_exit("tcgetattr");

	atexit(reset_termios);

	monkey_patch();

	tui_el = eventloop_new();

	snprintf(remotes_path, PATH_MAX, "/proc/self/fd/%d", remotes_log_fd);
	remotes_inotifyeventfd = inotifyeventfd_add(remotes_path, IN_MODIFY);

	tui_global_events[0].fd = thread_stop_eventfd(current);
	tui_global_events[1].fd = broadcast_replica(switch_change_broadcast);
	tui_global_events[2].fd = broadcast_replica(xsk_broadcast_evt_broadcast);

	init_dialog(stdin, stdout);
	dialog_vars.default_button = -1;

	if (tcgetattr(STDIN_FILENO, &run_termios))
		perror_exit("tcgetattr");

	run_termios.c_lflag &= ~(ISIG | IXON | IXOFF);
	run_termios.c_cc[VINTR] = _POSIX_VDISABLE;
	run_termios.c_cc[VQUIT] = _POSIX_VDISABLE;
	run_termios.c_cc[VSTOP] = _POSIX_VDISABLE;
	run_termios.c_cc[VSUSP] = _POSIX_VDISABLE;

	if (tcsetattr(STDIN_FILENO, TCSANOW, &run_termios))
		perror_exit("tcsetattr");

	if (setjmp(exit_jmp))
		goto out;

	tui_clear();

	if (!switch_ip)
		detect_local_switch();
	else
		detect_switch_online();

	int choice = 0;

	while (true) {
		tui_clear();

		dialog_vars.begin_set = true;

		dialog_vars.begin_y = 18;
		dialog_vars.begin_x = 2;
		dialog_tailbox("Log", remotes_path, 10, 76, 1);

		dialog_vars.begin_y = 3;
		dialog_vars.begin_x = 10;

		dialog_vars.nocancel = true;

		DIALOG_LISTITEM choices[] = {
			{"1", "Refresh state", dlg_strempty()},
			{"2", "Re-detect Switch", dlg_strempty()},
			{"3", "Shutdown the VM", dlg_strempty()},
			{"4", "Check for updates", dlg_strempty()},
			{"5", fake_gateway_ip ?
				"Advanced: Setup VM as Gateway (currently enabled)" :
				"Advanced: Setup VM as Gateway (currently disabled)",
			      dlg_strempty()},
			{"6", "Advanced: Enter Switch information manually",
			      dlg_strempty()},
			{"7", "Advanced: Change VM network configuration",
			      dlg_strempty()},
			{"8", "Advanced: Reboot the VM", dlg_strempty()},
			{"9", "Debug: Start a Shell", dlg_strempty()},
			{"10", "Debug: Trigger crash", dlg_strempty()},
		};

		dialog_vars.default_item = choices[choice].name;
		res = dlg_menu("IShoal", "Please select an option:", 13, 60, 7, 10,
			 choices, &choice, dlg_dummy_menutext);
		if (res)
			continue;

		dialog_state.plain_buttons = false;
		tui_clear();

		switch (choice) {
		case 0:
			detect_switch_online();
			break;
		case 1:
			detect_local_switch();
			break;
		case 2:
			dialog_vars.begin_set = false;
			res = dialog_yesno("Setup",
					   "\nDo you really want to shutdown the VM?",
					   8, 40);
			if (res)
				break;

			exitcode = 2;
			goto out;
		case 3:
			if (!check_updates())
				break;

			exitcode = 5;
			goto out;
		case 4:
			switch_gw_dialog();
			break;
		case 5:
			switch_information_dialog();
			break;
		case 6:
			exitcode = 4;
			goto out;
		case 7:
			dialog_vars.begin_set = false;
			res = dialog_yesno("Setup",
					   "\nDo you really want to reboot the VM?",
					   8, 40);
			if (res)
				break;

			exitcode = 3;
			goto out;
		case 8:
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

			break;
		case 9:
			crash_entry_dialog();
			break;
		}

	}

out:
	tui_reset();

	thread_all_stop();
}
