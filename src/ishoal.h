#ifndef __ISHOAL_H
#define __ISHOAL_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "version.h"
#include "bpf_kern.h"

#define container_of(ptr, type, member) ({ \
	void *__mptr = (void *)(ptr);      \
	((type *)(__mptr - offsetof(type, member))); })

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define MAX_ERRNO	4095
#define PTR_ERR(val) ((unsigned long)(val))
#define IS_ERR(val) (PTR_ERR(val) >= -MAX_ERRNO)
#define IS_ERR_OR_NULL(val) (IS_ERR(val) || !(val))

#define free_rcu(ptr, rhf)						\
do {									\
	typeof (ptr) ___p = (ptr);					\
									\
	if (___p)							\
		call_rcu(&((___p)->rhf), free_rcu_get_cb(	\
				offsetof(typeof(*(ptr)), rhf)));		\
} while (0)

extern int exitcode;

extern char *progname;
extern char *iface;
extern int ifindex;

extern macaddr_t switch_mac;
extern macaddr_t host_mac;
extern macaddr_t gateway_mac;

extern ipaddr_t switch_ip;
extern ipaddr_t public_host_ip;
extern ipaddr_t real_subnet_mask;
extern ipaddr_t fake_gateway_ip;

extern uint16_t vpn_port;
extern uint16_t public_vpn_port;

extern int remotes_fd;

enum event_handler {
	EVT_CALL_FN,
	EVT_BREAK,
};
struct event {
	int fd;
	struct timespec expiry;
	bool eventfd_ack;
	enum event_handler handler_type;
	void (*handler_fn)(int fd, void *ctx, bool expired);
	void *handler_ctx;
};

struct eventloop;

struct broadcast_event;

extern int stop_broadcast_primary;

extern int xsk_broadcast_evt_broadcast_primary;
extern struct broadcast_event *xsk_broadcast_evt_broadcast;

extern int switch_change_broadcast_primary;
extern struct broadcast_event *switch_change_broadcast;

void free_rcu_init(void);
void *free_rcu_get_cb(size_t offset);

int timespec_cmp(const struct timespec *x, const struct timespec *y);
void timespec_add(struct timespec *x, const struct timespec *y);
void timespec_sub(struct timespec *x, const struct timespec *y);

void tui_thread(void *arg);
void bpf_load_thread(void *arg);
void python_thread(void *arg);

__attribute__ ((format(printf, 1, 2), noreturn))
void fprintf_exit(char *fmt, ...);
__attribute__ ((noreturn))
void perror_exit(char *msg);

char *read_whole_file(char *path, size_t *nbytes);

void hex_dump(void *ptr, size_t length);

char *ip_str(ipaddr_t addr);
char *mac_str(macaddr_t addr);

void ifinfo_init(void);
void start_endpoint(void);

void load_conf(void);
void save_conf(void);

void bpf_set_switch_ip(ipaddr_t addr);
void bpf_set_switch_mac(macaddr_t addr);
void bpf_set_fake_gateway_ip(ipaddr_t addr);

struct xsk_socket *xsk_configure_socket(char *iface, int queue,
	void (*handler)(void *pkt, size_t length));

struct thread;
extern __thread struct thread *current;

struct thread *thread_start(void (*fn)(void *arg), void *arg, char *name);
void thread_stop(struct thread *thread);
bool thread_should_stop(struct thread *thread);
int thread_stop_eventfd(struct thread *thread);
bool thread_is_main(struct thread *thread);
void thread_join(struct thread *thread);
void thread_kill(struct thread *thread);
void thread_release(struct thread *thread);
void thread_all_stop(void);
void thread_join_rest(void);

void make_fd_pair(int *send_fd, int *recv_fd);
void handle_rpc(int call_recv_fd);
int invoke_rpc_sync(int call_send_fd, int (*fn)(void *ctx), void *ctx);
void invoke_rpc_async(int call_send_fd, int (*fn)(void *ctx), void *ctx);

struct eventloop *eventloop_new(void);
void eventloop_destroy(struct eventloop *el);
void eventloop_clear_events(struct eventloop *el);
void eventloop_install_event_sync(struct eventloop *el, struct event *evt);
void eventloop_install_rpc(struct eventloop *el, int rpc_recv_fd);
void eventloop_install_break(struct eventloop *el, int break_evt_fd);
void eventloop_install_event_async(struct eventloop *el, struct event *evt,
				   int rpc_send_fd);
void eventloop_remove_event_current(struct eventloop *el);
int eventloop_enter(struct eventloop *el, int timeout_ms);
void eventloop_thread_fn(void *arg);

struct broadcast_event *broadcast_new(int primary_event_fd);
int broadcast_replica(struct broadcast_event *bce);
void broadcast_replica_del(struct broadcast_event *bce, int fd);

void __broadcast_finalize_init(void);

int inotifyeventfd_add(char *pathname, uint32_t mask);
void inotifyeventfd_rm(int fd);

void do_stun(int sockfd, ipaddr_t *address, uint16_t *port);

struct resolve_arp_user {
	ipaddr_t ipaddr;
	macaddr_t *macaddr;
	struct eventloop *el;
	void (*cb)(bool solved, void *ctx);
	void *ctx;
};

void resolve_arp_user(struct resolve_arp_user *ctx);

void set_remote_addr(ipaddr_t local_ip, ipaddr_t remote_ip, uint16_t remote_port);
void delete_remote_addr(ipaddr_t local_ip);
void broadcast_all_remotes(void *buf, size_t len);

void bpf_set_remote_addr(ipaddr_t local_ip, struct remote_addr *remote_addr);
void bpf_delete_remote_addr(ipaddr_t local_ip);
#endif
