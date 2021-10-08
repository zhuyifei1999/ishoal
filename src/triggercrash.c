#include "features.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <urcu.h>

#include "ishoal.h"

enum crash_agent {
	CRASH_AGENT_TUI,	// T
	CRASH_AGENT_RPC_C,	// C
	CRASH_AGENT_RPC_PY,	// P
	CRASH_AGENT_RCU,	// R
};

enum crash_kind {
	CRASH_KIND_RAISE_SIG,	// S
	CRASH_KIND_KERN_SYSRQ,	// K
	CRASH_KIND_FATAL_EXC,	// E
	CRASH_KIND_ILL_INSN,	// I
};

static enum crash_agent agent;
static enum crash_kind kind;
static char subkind;
static char subkind_num;

static void trigger_crash_raise_sig(void)
{
	raise(subkind_num);
}

static void trigger_crash_kern_sysrq(void)
{
	int sysrq_trigger = open("/proc/sysrq-trigger", O_WRONLY);
	if (sysrq_trigger >= 0) {
		(void)!write(sysrq_trigger, &subkind, 1);
		close(sysrq_trigger);
	}
}

static void trigger_crash_fatal_exc(void)
{
	errno = 0;
	perror_exit("User triggered crash");
}

static inline void make_sigill(void)
{
	__builtin_trap();
}

static inline void make_sigfpe(void)
{
	volatile int zero = 0;
	zero = zero / zero;
	(void)!zero;
}

static inline void make_sigsegv(void)
{
	volatile int *nullptr = NULL;
	volatile int unused = *nullptr;
	(void)!unused;
}

static inline void make_sigbus(void)
{
	int tmpfile = open(".", O_TMPFILE | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (tmpfile < 0)
		return;

	int *map = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, tmpfile, 0);
	if (map == MAP_FAILED)
		goto err_close;

	CMM_ACCESS_ONCE(*map) = 0;

	munmap(map, pagesize);

err_close:
	close(tmpfile);
}

static void trigger_crash_ill_insn(void)
{
	switch (subkind_num) {
	case SIGILL:
		make_sigill();
		break;
	case SIGFPE:
		make_sigfpe();
		break;
	case SIGSEGV:
		make_sigsegv();
		break;
	case SIGBUS:
		make_sigbus();
		break;
	}
}

// the difference between this and actual base64 is that 0-9 comes first
static char *b64_table = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

bool trigger_crash_init(char *cmd)
{
	if (strlen(cmd) != 4)
		return false;

	int csum = 0;
	csum += cmd[0];
	csum += cmd[1];
	csum += cmd[2];

	if (cmd[3] != b64_table[csum % 64])
		return false;

	switch (cmd[0]) {
	case 'T':
		agent = CRASH_AGENT_TUI;
		break;
	case 'C':
		agent = CRASH_AGENT_RPC_C;
		break;
	case 'P':
		agent = CRASH_AGENT_RPC_PY;
		break;
	case 'R':
		agent = CRASH_AGENT_RCU;
		break;
	default:
		return false;
	}

	switch (cmd[1]) {
	case 'S':
		kind = CRASH_KIND_RAISE_SIG;
		break;
	case 'K':
		kind = CRASH_KIND_KERN_SYSRQ;
		break;
	case 'E':
		kind = CRASH_KIND_FATAL_EXC;
		break;
	case 'I':
		kind = CRASH_KIND_ILL_INSN;
		break;
	default:
		return false;
	}

	subkind = cmd[2];

	char *subkind_ptr = strchr(b64_table, subkind);
	if (!subkind_ptr)
		return false;

	subkind_num = subkind_ptr - b64_table;

	switch (kind) {
	case CRASH_KIND_RAISE_SIG:
	case CRASH_KIND_KERN_SYSRQ:
		// takes anything
		break;
	case CRASH_KIND_ILL_INSN:
		switch (subkind_num) {
		case SIGILL:
		case SIGFPE:
		case SIGSEGV:
		case SIGBUS:
			break;
		default:
			return false;
		}
		break;
	case CRASH_KIND_FATAL_EXC:
		switch (agent) {
		case CRASH_AGENT_TUI:
		case CRASH_AGENT_RPC_C:
		case CRASH_AGENT_RCU:
			if (subkind != 'C')
				return false;
			break;
		case CRASH_AGENT_RPC_PY:
			if (subkind != 'C' && subkind != 'P')
				return false;
			break;
		}
		break;
	}

	return true;
}

static void (*trigger_crash_cb)(void);

int trigger_crash_cb_invoke(void *ctx)
{
	trigger_crash_cb();
	return 0;
}

struct rcu_head trigger_crash_rcu;

static void trigger_crash_rcu_cb(struct rcu_head *head)
{
	trigger_crash_cb_invoke(NULL);
}

void trigger_crash_exec(void)
{
	switch (kind) {
	case CRASH_KIND_RAISE_SIG:
		trigger_crash_cb = trigger_crash_raise_sig;
		break;
	case CRASH_KIND_KERN_SYSRQ:
		trigger_crash_cb = trigger_crash_kern_sysrq;
		break;
	case CRASH_KIND_ILL_INSN:
		trigger_crash_cb = trigger_crash_ill_insn;
		break;
	case CRASH_KIND_FATAL_EXC:
		trigger_crash_cb = trigger_crash_fatal_exc;
		break;
	}

	switch (agent) {
	case CRASH_AGENT_TUI:
		trigger_crash_cb_invoke(NULL);
		break;
	case CRASH_AGENT_RPC_C:
		worker_async(trigger_crash_cb_invoke, NULL);
		break;
	case CRASH_AGENT_RPC_PY: {
		int crash_msg = ISHOALC_RPC_INVOKE_CRASH;
		if (kind == CRASH_KIND_FATAL_EXC && subkind == 'P')
			crash_msg = ISHOALC_RPC_RAISE_ERR;
		python_rpc(&crash_msg, sizeof(crash_msg));
		break;
	}
	case CRASH_AGENT_RCU:
		rcu_read_lock();
		call_rcu(&trigger_crash_rcu, trigger_crash_rcu_cb);
		rcu_read_unlock();
		break;
	}
}
