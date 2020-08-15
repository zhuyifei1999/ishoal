#include <arpa/inet.h>
#include <dialog.h>
#include <errno.h>
#include <linux/limits.h>
#include <pthread.h>
#include <setjmp.h>
#include <sys/wait.h>

#include "ishoal.h"

static struct thread *tui_thread_ptr;

static pthread_mutex_t tui_reaper_lock = PTHREAD_MUTEX_INITIALIZER;

static void tui_reset(void)
{
	int res;
	dlg_killall_bg(&res);
	end_dialog();

	mouse_close();
	(void)endwin();

	// https://stackoverflow.com/a/7660837/13673228
	const char *CLEAR_SCREEN_ANSI = "\e[1;1H\e[2J";
	(void)!write(1, CLEAR_SCREEN_ANSI, 10);
}

static void tui_reaper_thread(void *arg)
{
	struct eventloop *wait_for_stun = eventloop_new();
	eventloop_install_break(wait_for_stun, thread_stop_eventfd(current));

	eventloop_enter(wait_for_stun, -1);
	eventloop_destroy(wait_for_stun);

	pthread_mutex_lock(&tui_reaper_lock);
	thread_kill(tui_thread_ptr);
	pthread_mutex_unlock(&tui_reaper_lock);
	tui_reset();
}

#ifdef SAFE_EXIT_DOES_NOT_WORK
jmp_buf exit_jmp;

static bool handle_exit_event(DIALOG_CALLBACK *cb)
{
	uint64_t event_data;
	if (read(fileno(cb->input), &event_data, sizeof(event_data)) == sizeof(event_data))
		longjmp(exit_jmp, 1);

	return true;
}

static void install_exit_cb(void)
{
	// All of this are freed when we call dlg_killall_bg *facepalm*
	FILE *exit_event = fdopen(dup(thread_stop_eventfd(current)), "r");
	if (!exit_event)
		perror_exit("fdopen");

	DIALOG_CALLBACK *exit_cb = malloc(sizeof(*exit_cb));
	*exit_cb = (typeof(*exit_cb)){
		.input = exit_event,
		.win = NULL,
		.handle_getc = NULL,
		.handle_input = handle_exit_event,
		.keep_bg = 0,
		.bg_task = 1,
	};
	dlg_add_callback(exit_cb);
}
#else
static inline void install_exit_cb(void) {}
#endif

static char remotes_path[PATH_MAX];
static char title_str[100];

static bool is_online;

static void recompute_title()
{
	if (!switch_ip)
		strncpy(title_str,
			"IShoal " ISHOAL_VERSION_STR " - "
			"Switch has not been detected, yet.", 100);
	else {
		snprintf(title_str, 100,
			"IShoal " ISHOAL_VERSION_STR " - "
			"Switch is %s at: %s (%s)",
			 is_online ? "online" : "offline",
			 mac_str(switch_mac),
			 ip_str(switch_ip)
		);
	}

	dialog_vars.backtitle = title_str;
	dlg_put_backtitle();
}

static void tui_clear(void)
{
	int res;
	dlg_killall_bg(&res);
	install_exit_cb();

	dlg_clear();

	recompute_title();
}

void tui_on_xsk_pkt(void)
{
	is_online = true;
}

static void tui_on_switch_chg(void)
{
	// FIXME: This would be racy, we need to somehow let the tui thread
	// do this...
	// recompute_title();
}

static void detect_switch_online(void)
{
	is_online = false;

	dialog_vars.begin_set = false;
	dialog_msgbox("Setup", "\nDetecting status of local Switch ...", 5, 40, 0);
	usleep(2500000);
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
			usleep(1 * 50000);

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
		char buf[100];
		snprintf(buf, 100, "\nFound local Switch:\n\n%s (%s)",
			 ip_str(switch_ip), mac_str(switch_mac));
		dialog_msgbox("Setup", buf, 9, 40, 1);
	}

	save_conf();
}

static void switch_gw_dialog(void)
{
	ipaddr_t new_gateway_ip = 0;
	char tmpbuf[20];
	int res;

	dialog_vars.begin_set = false;
	res = dialog_yesno("Setup",
			   "\nDo you want to setup the VM as a Gateway?\n\n"
			   "This is needed for example when your local network "
			   "does not use the 192.168.1.0 subnet.", 12, 40);
	if (res)
		goto out;

	tui_clear();

	new_gateway_ip = fake_gateway_ip ? : htonl(0xc0a80101);
	dialog_vars.nocancel = false;

	snprintf(tmpbuf, 20, "%s", ip_str(new_gateway_ip));
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
		snprintf(tmpbuf, 20, "%s", dialog_vars.input_result);
		continue;
	}

out:
	bpf_set_fake_gateway_ip(new_gateway_ip);

	save_conf();
}

static void switch_information_dialog(void)
{
	char tmpbuf[20];
	int res;

	ipaddr_t new_switch_ip = switch_ip;
	macaddr_t new_switch_mac;
	memcpy(new_switch_mac, switch_mac, sizeof(macaddr_t));

	dialog_vars.nocancel = false;
	dialog_vars.begin_set = false;

	snprintf(tmpbuf, 20, "%s", mac_str(new_switch_mac));
	if ((new_switch_mac[0] | new_switch_mac[1] |
	     new_switch_mac[2] | new_switch_mac[3] |
	     new_switch_mac[4] | new_switch_mac[5]) == 0)
		tmpbuf[0] = 0;

	while (true) {
		tui_clear();

		res = dialog_inputbox("Setup",
				      "Please enter the MAC address of the Switch:\n",
				      10, 40, tmpbuf, 0);
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

		break;

invalid_mac:
		dialog_msgbox("Setup", "Invalid MAC address", 7, 40, 1);
		snprintf(tmpbuf, 20, "%s", dialog_vars.input_result);
		continue;
	}

	snprintf(tmpbuf, 20, "%s", new_switch_ip ? ip_str(new_switch_ip) : "");
	while (true) {
		tui_clear();

		res = dialog_inputbox("Setup",
				      "Please enter the IP address of the Switch:\n",
				      10, 40, tmpbuf, 0);
		if (res)
			return;

		if (inet_pton(AF_INET, dialog_vars.input_result, &new_switch_ip) != 1)
			goto invalid_ip;

		if (!new_switch_ip || new_switch_ip == 0xFFFFFFFF)
			goto invalid_ip;

		break;
invalid_ip:
		dialog_msgbox("Setup", "Invalid IP address", 7, 40, 1);
		snprintf(tmpbuf, 20, "%s", dialog_vars.input_result);
		continue;
	}

	char msg[110];
	snprintf(msg, 110, "You entered that your Switch can be found at:\n"
		 "\n%s (%s).\n\nIs that correct?",
		 mac_str(new_switch_mac), ip_str(new_switch_ip));
	res = dialog_yesno("Setup", msg, 10, 40);
	if (res)
		return;

	bpf_set_switch_ip(new_switch_ip);
	bpf_set_switch_mac(new_switch_mac);

	save_conf();
}

void tui_thread(void *arg)
{
	int res;

	tui_thread_ptr = current;
	init_dialog(stdin, stdout);
	dialog_vars.default_button = -1;

	snprintf(remotes_path, PATH_MAX, "/proc/self/fd/%d", remotes_fd);

#ifdef SAFE_EXIT_DOES_NOT_WORK
	if (setjmp(exit_jmp))
		goto out;

	int flags = fcntl(thread_stop_eventfd(current), F_GETFL, 0);
	if (flags == -1)
		perror_exit("fcntl(F_GETFL)");
	if (fcntl(thread_stop_eventfd(current), F_SETFL, flags | O_NONBLOCK) == -1)
		perror_exit("fcntl(F_SETFL)");

	install_exit_cb();
#endif

	thread_start(tui_reaper_thread, NULL, "tui_reaper");
	on_switch_change(tui_on_switch_chg);

	tui_clear();

	if (!switch_ip) {
		detect_local_switch();
	} else {
		detect_switch_online();
	}

	while (true) {
		tui_clear();

		dialog_vars.begin_set = true;

		dialog_vars.begin_y = 16;
		dialog_vars.begin_x = 2;
		dialog_tailbox("Log", remotes_path, 8, 76, 1);

		dialog_vars.begin_y = 3;
		dialog_vars.begin_x = 10;

		dialog_vars.nocancel = true;

		DIALOG_LISTITEM choices[] = {
			{"1", "Refresh state", dlg_strempty()},
			{"2", "Re-detect Switch", dlg_strempty()},
			{"3", "Shutdown the VM", dlg_strempty()},
			{"4", fake_gateway_ip ?
				"Advanced: Setup VM as Gateway (currently enabled)" :
				"Advanced: Setup VM as Gateway (currently disabled)",
			      dlg_strempty()},
			{"5", "Advanced: Enter Switch information manually",
			      dlg_strempty()},
			{"6", "Advanced: Start a Shell", dlg_strempty()},
			{"7", "Advanced: Reboot the VM", dlg_strempty()},
		};

		int choice;
		dlg_menu("IShoal", "Please select an option:", 11, 60, 7, 7,
			 choices, &choice, dlg_dummy_menutext);

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
			switch_gw_dialog();
			break;
		case 4:
			switch_information_dialog();
			break;
		case 5:
			tui_reset();
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
			break;
		case 6:
			dialog_vars.begin_set = false;
			res = dialog_yesno("Setup",
					   "\nDo you really want to reboot the VM?",
					   8, 40);
			if (res)
				break;

			exitcode = 3;

			goto out;
		}

	}

out:
	tui_reset();

	pthread_mutex_lock(&tui_reaper_lock);
	thread_all_stop();
	pthread_mutex_unlock(&tui_reaper_lock);

	while (true)
		pause();
}
