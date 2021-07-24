#include "features.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include "ishoal.h"

struct linux_dirent64 {
	uint64_t	d_ino;
	int64_t		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[];
};

// ULLONG_MAX is only 20 chars in DEC
#define MAXNUMLEN 30
#define MAX_THREAD_NAME 16
#define ALTSTACKLEN 65536

#define CASE_EMIT(name) case name: emit(#name); break;

static struct termios start_termios;
static __thread void *altstack;
static int proc_fd;
static int maps_fd;

static __thread volatile sig_atomic_t reentrant;
static atomic_flag crashed = ATOMIC_FLAG_INIT;

static sigjmp_buf can_deref_ret;
static sigjmp_buf py_faulthandler_ret;
static bool py_faulthandler_set;
static struct sigaction py_faulthandler;

// surprisingly, atoi family functions are not async signal safe
static unsigned long safe_atoul(const char *str)
{
	unsigned long r = 0;

	while (*str) {
		r = r * 10 + *str - '0';
		str++;
	}

	return r;
}

static char *dec(unsigned long val, char *buf)
{
	char *ptr = &buf[MAXNUMLEN-1];
	*ptr = '\0';

	if (!val)
		*(--ptr) = '0';

	while (val) {
		*(--ptr) = '0' + val % 10;
		val /= 10;
	}

	return ptr;
}

static void emit(const char *str)
{
	size_t len = strlen(str);

	(void)!write(STDERR_FILENO, str, len);
}

static void emit_dec(unsigned long val)
{
	char buf[MAXNUMLEN];
	emit(dec(val, buf));
}

static void emit_charhex(unsigned char c)
{
	char s[2] = {0};

	s[0] = c >> 4;

	if (s[0] < 10)
		s[0] = '0' + s[0];
	else
		s[0] = 'a' + s[0] - 10;
	emit(s);

	s[0] = c & 0xf;
	if (s[0] < 10)
		s[0] = '0' + s[0];
	else
		s[0] = 'a' + s[0] - 10;
	emit(s);
}

static void __emit_hex(uintptr_t val, bool show_all)
{
	for (size_t i = 0; i < sizeof(val); i++) {
		size_t shift = sizeof(val) - i - 1;
		unsigned char c = val >> (shift * 8);
		char s[2] = {0};

		s[0] = c >> 4;

		if (!show_all && !s[0])
			goto next;
		else if (s[0] < 10)
			s[0] = '0' + s[0];
		else
			s[0] = 'a' + s[0] - 10;
		emit(s);
		show_all = true;

next:
		s[0] = c & 0xf;

		if (!show_all && !s[0])
			continue;
		else if (s[0] < 10)
			s[0] = '0' + s[0];
		else
			s[0] = 'a' + s[0] - 10;
		emit(s);
		show_all = true;
	}

	if (!show_all)
		emit("0");
}

static void emit_hex(uintptr_t val)
{
	__emit_hex(val, false);
}

static void emit_reghex(uintptr_t val)
{
	__emit_hex(val, true);
}

static void emit_pid(pid_t pid)
{
	emit_dec(pid);

	// best attempt to determine the thread name
	int pid_fd, comm_fd;
	pid_fd = comm_fd = -1;

	char pid_buf[MAXNUMLEN];
	char *pid_str = dec(pid, pid_buf);

	pid_fd = openat(proc_fd, pid_str, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (pid_fd < 0)
		goto out;

	comm_fd = openat(pid_fd, "comm", O_RDONLY | O_CLOEXEC);
	if (comm_fd < 0)
		goto out;

	char comm_buf[MAX_THREAD_NAME+1] = {0};
	if (read(comm_fd, comm_buf, MAX_THREAD_NAME) < 0)
		goto out;

	for (size_t i = 0; i < MAX_THREAD_NAME; i++)
		if (comm_buf[i] == '\n')
			comm_buf[i] = '\0';

	emit(" (");
	emit(comm_buf);
	emit(")");

out:
	close(pid_fd);
	close(comm_fd);
}

static void emit_mapinfo(uintptr_t ptr)
{
	static char name[PATH_MAX] = {0};
	static size_t name_len = 0;
	static uintptr_t low, high;
	ssize_t r;
	char c;

	if (low <= ptr && ptr < high)
		goto found;

	if (lseek(maps_fd, 0, SEEK_SET))
		goto err;

line:
	low = high = 0;

	while (true) {
		r = read(maps_fd, &c, 1);
		if (!r)
			goto not_found;
		if (r != 1)
			goto err;

		if (c == '-')
			break;

		if ('0' <= c && c <= '9')
			low = low * 16 + c - '0';
		else if ('a' <= c && c <= 'f')
			low = low * 16 + c - 'a' + 10;
		else
			goto err;
	}

	while (true) {
		r = read(maps_fd, &c, 1);
		if (!r)
			goto not_found;
		if (r != 1)
			goto err;

		if (c == ' ')
			break;

		if ('0' <= c && c <= '9')
			high = high * 16 + c - '0';
		else if ('a' <= c && c <= 'f')
			high = high * 16 + c - 'a' + 10;
		else
			goto err;
	}

	if (low <= ptr && ptr < high) {
		size_t column = 0;
		bool in_column = false;
		bool seen_dot_so = false;

		while (true) {
			r = read(maps_fd, &c, 1);
			if (!r)
				break;
			if (r != 1)
				goto err;
			if (c == '\n')
				break;

			bool new_in_col = c != ' ';
			if (new_in_col && !in_column)
				column++;
			in_column = new_in_col;

			if (in_column && column == 5) {
				if (c == '/') {
					name_len = 0;
					seen_dot_so = false;
				} else if (!seen_dot_so) {
					if (c == '.' && name_len > 3 &&
					    name[name_len-3] == '.' &&
					    name[name_len-2] == 's' &&
					    name[name_len-1] == 'o') {
						seen_dot_so = true;
					} else {
						name[name_len++] = c;
					}
				}

				if (name_len + 1 >= PATH_MAX)
					goto err;
			}
		}

		name[name_len] = '\0';
		goto found;
	} else {
		while (true) {
			r = read(maps_fd, &c, 1);
			if (!r)
				goto not_found;
			if (r != 1)
				goto err;
			if (c == '\n')
				goto line;
		}
	}

found:
	if (name_len) {
		emit(name);
	}
	emit("[");
	emit_hex(low);
	emit("+");
	emit_hex(ptr-low);
	emit("]");
	return;

err:
	emit("(err read maps)");
	return;

not_found:
	emit("(unmapped)");
	return;
}

static void fault_can_deref_ret(int sig_num)
{
	siglongjmp(can_deref_ret, 1);
}

static bool can_deref(uintptr_t addr)
{
	struct sigaction act = {
		.sa_handler = fault_can_deref_ret,
		.sa_flags = SA_NODEFER | SA_RESETHAND,
	};
	sigemptyset(&act.sa_mask);

	if (sigaction(SIGSEGV, &act, NULL))
		raise(SIGABRT);

	if (!sigsetjmp(can_deref_ret, 1)) {
		volatile char c = *(volatile char *)addr;
		(void)!c;

		struct sigaction act = {
			.sa_handler = SIG_DFL,
		};
		sigemptyset(&act.sa_mask);

		return true;
	}

	return false;
}

static void emit_code(uintptr_t ip)
{
#define BACK 10
#define FWD 10

	bool seen = false;

	for (ssize_t ptr = ip - BACK; ptr <= ip + FWD; ptr++) {
		if (can_deref(ptr)) {
			if (!seen && ptr > ip)
				emit("(fault) ");

			seen = true;

			if (ptr == ip)
				emit("<");
			emit_charhex(*(unsigned char *)ptr);
			if (ptr == ip)
				emit(">");

			emit(" ");
		} else {
			if (seen) {
				if (ptr <= ip)
					emit("(fault)");
				break;
			}
		}
	}

	if (!seen)
		emit("(fault)");
}

static bool freeze_threads(pid_t pid, pid_t tid)
{
	bool success = false;
	bool all_ptraced = true;

	int pid_fd, task_fd;
	pid_fd = task_fd = -1;

	char pid_buf[MAXNUMLEN];
	char *pid_str = dec(pid, pid_buf);

	pid_fd = openat(proc_fd, pid_str, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (pid_fd < 0)
		goto out;

	task_fd = openat(pid_fd, "task", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (task_fd < 0)
		goto out;

	#define BUF_SIZE 1024
	char buf[BUF_SIZE];

	for (;;) {
		// musl / glibc difference:
		// musl has getdents() is SYS_getdents64 with struct dirent *
		// glibc has getdents64() is SYS_getdents64 with void *
		ssize_t nread = syscall(SYS_getdents64, task_fd, buf, BUF_SIZE);
		if (nread < 0)
			goto out;
		if (nread == 0)
			break;

		for (size_t bpos = 0; bpos < nread;) {
			struct linux_dirent64 *d = (void *)(buf + bpos);
			if (d->d_type != DT_DIR)
			 	goto next;
			if (d->d_name[0] == '.')
				goto next;

			pid_t target = safe_atoul(d->d_name);
			if (ptrace(PTRACE_ATTACH, target, NULL, NULL))
				all_ptraced = false;
next:
			bpos += d->d_reclen;
		}
	}

	success = true;

out:
	close(pid_fd);
	close(task_fd);

	return success && all_ptraced;
}

static void fault_sig_handler(int sig_num, siginfo_t *siginfo, void *_ucontext)
{
	// This function must be async signal safe (see signal-safety(7) man)
	ucontext_t *ucontext = _ucontext;

	// The same thread already crashed with a different signal.
	// SA_RESETHAND protects us from same signal.
	if (reentrant)
		raise(sig_num);
	reentrant = true;

	// if other threads crashed wait for them to kill us
	if (atomic_flag_test_and_set(&crashed))
		while (true)
			pause();

	pid_t pid, tid;
	pid = getpid();
	tid = gettid();

	pid_t child = -1;
	child = fork();
	if (child >= 0) {
		if (child)  {
			// parent
			while (true)
				pause();
		} else {
			// child
			if (freeze_threads(pid, tid))
				goto all_frozen;
		}
	}

	/* We can't get a child to freeze us, so the next best thing we
	 * can do to minimize running of every other thread, without
	 * alerting our parent, is to become FIFO real time.
	 */
	struct sched_param param = {
		.sched_priority = 1,
	};

	sched_setscheduler(0, SCHED_FIFO, &param);

all_frozen:
	tcsetattr(STDIN_FILENO, TCSANOW, &start_termios);

	// // https://stackoverflow.com/a/7660837/13673228
	// const char *CLEAR_SCREEN_ANSI = "\e[1;1H\e[2J";
	// (void)!write(STDOUT_FILENO, CLEAR_SCREEN_ANSI, 10);

	// This is to get scroll back if we are running on a GUI terminal
	// see console_codes(4)
	emit("\e[?1000l");
	emit("\r");

	fork_tee();

	emit("iShoal Fatal Signal: ");
	switch (sig_num) {
		CASE_EMIT(SIGSEGV);
		CASE_EMIT(SIGFPE);
		CASE_EMIT(SIGABRT);
		CASE_EMIT(SIGBUS);
		CASE_EMIT(SIGILL);
	default:
		emit("(UNKNOWN)");
	}
	emit(", ");

	emit("si_code: ");
	switch (siginfo->si_code) {
		CASE_EMIT(SI_USER);
		CASE_EMIT(SI_KERNEL);
		CASE_EMIT(SI_TKILL);
	default:
		switch (sig_num) {
		case SIGILL:
			switch (siginfo->si_code) {
				CASE_EMIT(ILL_ILLOPC);
				CASE_EMIT(ILL_ILLOPN);
				CASE_EMIT(ILL_ILLADR);
				CASE_EMIT(ILL_ILLTRP);
				CASE_EMIT(ILL_PRVOPC);
				CASE_EMIT(ILL_PRVREG);
				CASE_EMIT(ILL_COPROC);
				CASE_EMIT(ILL_BADSTK);
			default:
				emit("(UNKNOWN)");
			}
			break;
		case SIGFPE:
			switch (siginfo->si_code) {
				CASE_EMIT(FPE_INTDIV);
				CASE_EMIT(FPE_INTOVF);
				CASE_EMIT(FPE_FLTDIV);
				CASE_EMIT(FPE_FLTOVF);
				CASE_EMIT(FPE_FLTUND);
				CASE_EMIT(FPE_FLTRES);
				CASE_EMIT(FPE_FLTINV);
				CASE_EMIT(FPE_FLTSUB);
			default:
				emit("(UNKNOWN)");
			}
			break;
		case SIGSEGV:
			switch (siginfo->si_code) {
				CASE_EMIT(SEGV_MAPERR);
				CASE_EMIT(SEGV_ACCERR);
				CASE_EMIT(SEGV_BNDERR);
				CASE_EMIT(SEGV_PKUERR);
			default:
				emit("(UNKNOWN)");
			}
			break;
		case SIGBUS:
			switch (siginfo->si_code) {
				CASE_EMIT(BUS_ADRALN);
				CASE_EMIT(BUS_ADRERR);
				CASE_EMIT(BUS_OBJERR);
				CASE_EMIT(BUS_MCEERR_AR);
				CASE_EMIT(BUS_MCEERR_AO);
			default:
				emit("(UNKNOWN)");
			}
			break;
		default:
			emit("(UNKNOWN)");
		}
	}
	emit("\n");

	emit("Thread: ");
	emit_pid(tid);
	if (pid == tid)
		emit(" [Main Thread]");
	emit("\n");

	if (siginfo->si_code == SI_USER || siginfo->si_code == SI_TKILL) {
		emit("si_uid: ");
		emit_dec(siginfo->si_uid);
		emit(" si_pid: ");
		emit_pid(siginfo->si_pid);

		if (siginfo->si_pid == pid || siginfo->si_pid == tid)
			emit(" [self]");
		emit("\n");
	} else if (sig_num != SIGABRT && siginfo->si_code > 0) {
		emit("si_addr: ");
		if (siginfo->si_addr)
			emit_reghex((uintptr_t)siginfo->si_addr);
		else
			emit("(null)");
		emit("\n");
	}

	uintptr_t ip, sp;

	// for future reference,
	// https://sourceforge.net/p/predef/wiki/Architectures/
#ifdef __x86_64__
	ip = ucontext->uc_mcontext.gregs[REG_RIP];
	emit("RIP: ");
	emit_reghex(ip);
	emit(" in ");
	emit_mapinfo(ip);
	emit("\n");

	emit("Code: ");
	emit_code(ip);
	emit("\n");

	sp = ucontext->uc_mcontext.gregs[REG_RSP];
	emit("RSP: ");
	emit_reghex(sp);
	emit(" in ");
	emit_mapinfo(sp);
	emit("\n");
	// emit(" ");
	// emit("EFLAGS: ");
	// emit_reghex(ucontext->uc_mcontext.gregs[REG_EFL]);
	// emit("\n");

#define SHOW_REG_ONE(REGNAME) do {                                 \
	emit(#REGNAME ": ");                                       \
	emit_reghex(ucontext->uc_mcontext.gregs[REG_ ## REGNAME]); \
} while (0)

#define SHOW_REG_THREE(A, B, C) do { \
	SHOW_REG_ONE(A);             \
	emit(" ");                   \
	SHOW_REG_ONE(B);             \
	emit(" ");                   \
	SHOW_REG_ONE(C);             \
	emit("\n");                  \
} while (0)

#ifndef REG_R08
#define REG_R08 REG_R8
#endif
#ifndef REG_R09
#define REG_R09 REG_R9
#endif

	SHOW_REG_THREE(RAX, RBX, RCX);
	SHOW_REG_THREE(RDX, RSI, RDI);
	SHOW_REG_THREE(RBP, R08, R09);
	SHOW_REG_THREE(R10, R11, R12);
	SHOW_REG_THREE(R13, R14, R15);
#else
#error "Unknown architecture"
#endif

	unw_cursor_t cursor;
	if (unw_init_local2(&cursor, ucontext, UNW_INIT_SIGNAL_FRAME))
		goto no_c_bt;

	emit("Call Trace:\n");

	unw_word_t last_ip = 0;
	bool omitting = false;
	ssize_t omissions = 0;
	ssize_t lines = 0;

	while (true) {
		char name[128];
		unw_word_t ip, off;
		int ret;

		unw_get_reg(&cursor, UNW_REG_IP, &ip);

		if (ip != last_ip && omitting) {
			if (omissions) {
				emit("  (");
				emit_dec(omissions);
				emit(" duplicate frames omitted...)\n");

				lines++;
			}
			omitting = false;
		}

		if (!omitting) {
			unw_proc_info_t pi;

			emit("  ");
			ret = unw_get_proc_name(&cursor, name, sizeof(name), &off);
			if (!ret)
				ret = unw_get_proc_info(&cursor, &pi);

			if (!ret && ip - pi.start_ip == off) {
				emit(name);
				emit("+");
				emit_hex(off);
				emit("/");
				emit_hex(pi.end_ip - pi.start_ip);
			} else {
				emit("0x");
				emit_hex(ip);
			}

			emit("\tin ");
			emit_mapinfo(ip);
			emit("\n");
			lines++;
		} else {
			omissions += 1;
		}

		if (ip == last_ip)
			omitting = true;
		last_ip = ip;

		if (!can_deref(sp)) {
			emit("  (SP is bad)\n");
			// unw_step will fault here otherwise
			goto no_c_bt;
		}

		ret = unw_step(&cursor);
		if (ret <= 0)
			break;

		if (lines > 64) {
			emit("  (... more)\n");
			goto no_c_bt;
		}
	}

no_c_bt:
	if (!py_faulthandler_set || !thread_is_python)
		goto no_py_bt;

	if (!sigsetjmp(py_faulthandler_ret, 1)) {
		if (py_faulthandler.sa_flags & SA_SIGINFO)
			py_faulthandler.sa_sigaction(sig_num, siginfo, ucontext);
		else
			py_faulthandler.sa_handler(sig_num);
	}

no_py_bt:
	emit("End of trace\n");

	if (child) {
		// This is the faulting thread and failed to start a child
		raise(sig_num);
	} else {
		// We are the child, now kill parent

		// musl / glibc difference:
		// musl has tkill()
		// glibc has tgkill()
		syscall(SYS_tgkill, pid, tid, sig_num);
		ptrace(PTRACE_CONT, tid, NULL, (void *)(uintptr_t)sig_num);
		_exit(0);
	}
}

static void fault_py_faulthandler_ret(int sig_num, siginfo_t *siginfo, void *ucontext)
{
	if (!py_faulthandler_set) {
		fault_sig_handler(sig_num, siginfo, ucontext);
		return;
	}

	/* There are these possible states during init:
	 * py_faulthandler_set = false, sighandler = SIG_DFL
	 * py_faulthandler_set = false, sighandler = fault_sig_handler
	 * py_faulthandler_set = false, sighandler = fault_py_faulthandler_ret
	 * py_faulthandler_set = false, sighandler = faulthandler_dump_traceback [python]
	 * py_faulthandler_set = false, sighandler = fault_sig_handler
	 * py_faulthandler_set = true,  sighandler = fault_sig_handler
	 *
	 * coming here without sigjmp_buf set requires sighandler be
	 * fault_py_faulthandler_ret or faulthandler_dump_traceback [python].
	 * In both cases py_faulthandler_set is false.
	 * Therefore sigjmp_buf must be set is we reach here with
	 * py_faulthandler_set = true
	 */

	siglongjmp(py_faulthandler_ret, 1);
}

static void faulthandler_reinit(void)
{
	struct sigaction act = {
		.sa_sigaction = fault_sig_handler,
		.sa_flags = SA_NODEFER | SA_ONSTACK | SA_RESETHAND | SA_SIGINFO,
	};
	sigemptyset(&act.sa_mask);

	if (sigaction(SIGSEGV, &act, NULL))
		perror_exit("sigaction");
	if (sigaction(SIGFPE, &act, NULL))
		perror_exit("sigaction");
	if (sigaction(SIGABRT, &act, NULL))
		perror_exit("sigaction");
	if (sigaction(SIGBUS, &act, NULL))
		perror_exit("sigaction");
	if (sigaction(SIGILL, &act, NULL))
		perror_exit("sigaction");
}

void faulthandler_altstack_init(void)
{
	altstack = mmap(NULL, ALTSTACKLEN, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK, 0, 0);
	if (altstack == MAP_FAILED)
		perror_exit("mmap");

	stack_t altstack_ss = {
		.ss_sp = altstack,
		.ss_size = ALTSTACKLEN,
	};
	if (sigaltstack(&altstack_ss, NULL))
		perror_exit("sigaltstack");
}

void faulthandler_altstack_deinit(void)
{
	if (altstack != MAP_FAILED) {
		stack_t altstack_ss = {
			.ss_flags = SS_DISABLE,
		};
		if (sigaltstack(&altstack_ss, NULL))
			perror_exit("sigaltstack");

		munmap(altstack, ALTSTACKLEN);
	}
}

void faulthandler_init(void)
{
	if (tcgetattr(STDIN_FILENO, &start_termios))
		perror_exit("tcgetattr");

	proc_fd = open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (proc_fd < 0)
		perror_exit("open(/proc)");

	maps_fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
	if (maps_fd < 0)
		perror_exit("open(/proc/self/maps)");

	faulthandler_altstack_init();
	faulthandler_reinit();
}

void faulthandler_hijack_py_pre(void)
{
	struct sigaction act = {
		.sa_sigaction = fault_py_faulthandler_ret,
		.sa_flags = SA_NODEFER | SA_ONSTACK | SA_RESETHAND | SA_SIGINFO,
	};
	sigemptyset(&act.sa_mask);

	if (sigaction(SIGSEGV, &act, NULL))
		perror_exit("sigaction");
	if (sigaction(SIGFPE, &act, NULL))
		perror_exit("sigaction");
	if (sigaction(SIGABRT, &act, NULL))
		perror_exit("sigaction");
	if (sigaction(SIGBUS, &act, NULL))
		perror_exit("sigaction");
	if (sigaction(SIGILL, &act, NULL))
		perror_exit("sigaction");
}

void faulthandler_hijack_py_post(void)
{
	bool deferrd_set = !sigaction(SIGSEGV, NULL, &py_faulthandler);

	faulthandler_reinit();

	if (deferrd_set)
		py_faulthandler_set = true;
}
