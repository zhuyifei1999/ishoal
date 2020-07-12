#ifndef __ISHOAL_H
#define __ISHOAL_H

#include <stdbool.h>
#include <stddef.h>

#include "bpf_kern.h"

#define container_of(ptr, type, member) ({ \
	void *__mptr = (void *)(ptr);      \
	((type *)(__mptr - offsetof(type, member))); })

#define MAX_ERRNO	4095
#define PTR_ERR(val) ((unsigned long)(val))
#define IS_ERR(val) (PTR_ERR(val) >= -MAX_ERRNO)
#define IS_ERR_OR_NULL(val) (IS_ERR(val) || !(val))

extern char *iface;
extern int ifindex;

void bpf_load_thread(void *arg);

__attribute__ ((format(printf, 1, 2), noreturn))
void fprintf_exit(char *fmt, ...);
__attribute__ ((noreturn))
void perror_exit(char *msg);

char *read_whole_file(char *path);

void hex_dump(void *ptr, size_t length);

char *ip_str(ipaddr_t addr);
char *mac_str(macaddr_t addr);

void get_if_ipaddr(char *iface, ipaddr_t *addr);
void get_if_netmask(char *iface, ipaddr_t *addr);
void get_if_macaddr(char *iface, macaddr_t *addr);
void get_if_gateway(char *iface, ipaddr_t *addr);
void resolve_arp(char *iface, ipaddr_t ipaddr, macaddr_t *macaddr);

struct xsk_socket *xsk_configure_socket(char *iface, int queue,
	void (*handler)(void *pkt, size_t length));

struct thread;
extern __thread struct thread *current;

struct thread *thread_start(void (*fn)(void *arg), void *arg, char *name);
void thread_stop(struct thread *thread);
bool thread_should_stop(void);
int thread_stop_eventfd(struct thread *thread);
bool thread_is_main(void);
void thread_join(struct thread *thread);
void thread_release(struct thread *thread);
void thread_all_stop(void);
void thread_join_rest(void);

#endif
