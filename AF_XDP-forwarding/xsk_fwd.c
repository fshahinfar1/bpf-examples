// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2022 Intel Corporation. */

#define _GNU_SOURCE
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <assert.h>

#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

/* This program illustrates the packet forwarding between multiple AF_XDP
 * sockets in multi-threaded environment. All threads are sharing a common
 * buffer pool, with each socket having its own private buffer cache.
 *
 * Example 1: Single thread handling two sockets. The packets received by socket
 * A (interface IFA, queue QA) are forwarded to socket B (interface IFB, queue
 * QB), while the packets received by socket B are forwarded to socket A. The
 * thread is running on CPU core X:
 *
 *         ./xsk_fwd -i IFA -q QA -i IFB -q QB -c X
 *
 * Example 2: Two threads, each handling two sockets. The thread running on CPU
 * core X forwards all the packets received by socket A to socket B, and all the
 * packets received by socket B to socket A. The thread running on CPU core Y is
 * performing the same packet forwarding between sockets C and D:
 *
 *         ./xsk_fwd -i IFA -q QA -i IFB -q QB -i IFC -q QC -i IFD -q QD
 *         -c CX -c CY
 */

/*
 * Buffer pool and buffer cache
 *
 * For packet forwarding, the packet buffers are typically allocated from the
 * pool for packet reception and freed back to the pool for further reuse once
 * the packet transmission is completed.
 *
 * The buffer pool is shared between multiple threads. In order to minimize the
 * access latency to the shared buffer pool, each thread creates one (or
 * several) buffer caches, which, unlike the buffer pool, are private to the
 * thread that creates them and therefore cannot be shared with other threads.
 * The access to the shared pool is only needed either (A) when the cache gets
 * empty due to repeated buffer allocations and it needs to be replenished from
 * the pool, or (B) when the cache gets full due to repeated buffer free and it
 * needs to be flushed back to the pull.
 *
 * In a packet forwarding system, a packet received on any input port can
 * potentially be transmitted on any output port, depending on the forwarding
 * configuration. For AF_XDP sockets, for this to work with zero-copy of the
 * packet buffers when, it is required that the buffer pool memory fits into the
 * UMEM area shared by all the sockets.
 */

struct bpool_params {
	u32 n_buffers;
	u32 buffer_size;
	int mmap_flags;

	u32 n_users_max;
	u32 n_buffers_per_slab;
};

/* This buffer pool implementation organizes the buffers into equally sized
 * slabs of *n_buffers_per_slab*. Initially, there are *n_slabs* slabs in the
 * pool that are completely filled with buffer pointers (full slabs).
 *
 * Each buffer cache has a slab for buffer allocation and a slab for buffer
 * free, with both of these slabs initially empty. When the cache's allocation
 * slab goes empty, it is swapped with one of the available full slabs from the
 * pool, if any is available. When the cache's free slab goes full, it is
 * swapped for one of the empty slabs from the pool, which is guaranteed to
 * succeed.
 *
 * Partially filled slabs never get traded between the cache and the pool
 * (except when the cache itself is destroyed), which enables fast operation
 * through pointer swapping.
 */
struct bpool {
	struct bpool_params params;
	pthread_mutex_t lock;
	void *addr;

	u64 **slabs;
	u64 **slabs_reserved;
	u64 *buffers;
	u64 *buffers_reserved;

	u64 n_slabs;
	u64 n_slabs_reserved;
	u64 n_buffers;

	u64 n_slabs_available;
	u64 n_slabs_reserved_available;

	struct xsk_umem_config umem_cfg;
	struct xsk_ring_prod umem_fq;
	struct xsk_ring_cons umem_cq;
	struct xsk_umem *umem;
};

static struct bpool *
bpool_init(struct bpool_params *params,
	   struct xsk_umem_config *umem_cfg)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	u64 n_slabs, n_slabs_reserved, n_buffers, n_buffers_reserved;
	u64 slabs_size, slabs_reserved_size;
	u64 buffers_size, buffers_reserved_size;
	u64 total_size, i;
	struct bpool *bp;
	u8 *p;
	int status;

	/* mmap prep. */
	if (setrlimit(RLIMIT_MEMLOCK, &r))
		return NULL;

	/* bpool internals dimensioning. */
	n_slabs = (params->n_buffers + params->n_buffers_per_slab - 1) /
		params->n_buffers_per_slab;
	n_slabs_reserved = params->n_users_max * 2;
	n_buffers = n_slabs * params->n_buffers_per_slab;
	n_buffers_reserved = n_slabs_reserved * params->n_buffers_per_slab;

	slabs_size = n_slabs * sizeof(u64 *);
	slabs_reserved_size = n_slabs_reserved * sizeof(u64 *);
	buffers_size = n_buffers * sizeof(u64);
	buffers_reserved_size = n_buffers_reserved * sizeof(u64);

	total_size = sizeof(struct bpool) +
		slabs_size + slabs_reserved_size +
		buffers_size + buffers_reserved_size;

	/* bpool memory allocation. */
	p = calloc(total_size, sizeof(u8));
	if (!p)
		return NULL;

	/* bpool memory initialization. */
	bp = (struct bpool *)p;
	memcpy(&bp->params, params, sizeof(*params));
	bp->params.n_buffers = n_buffers;

	bp->slabs = (u64 **)&p[sizeof(struct bpool)];
	bp->slabs_reserved = (u64 **)&p[sizeof(struct bpool) +
		slabs_size];
	bp->buffers = (u64 *)&p[sizeof(struct bpool) +
		slabs_size + slabs_reserved_size];
	bp->buffers_reserved = (u64 *)&p[sizeof(struct bpool) +
		slabs_size + slabs_reserved_size + buffers_size];

	bp->n_slabs = n_slabs;
	bp->n_slabs_reserved = n_slabs_reserved;
	bp->n_buffers = n_buffers;

	for (i = 0; i < n_slabs; i++)
		bp->slabs[i] = &bp->buffers[i * params->n_buffers_per_slab];
	bp->n_slabs_available = n_slabs;

	for (i = 0; i < n_slabs_reserved; i++)
		bp->slabs_reserved[i] = &bp->buffers_reserved[i *
			params->n_buffers_per_slab];
	bp->n_slabs_reserved_available = n_slabs_reserved;

	for (i = 0; i < n_buffers; i++)
		bp->buffers[i] = i * params->buffer_size;

	/* lock. */
	status = pthread_mutex_init(&bp->lock, NULL);
	if (status) {
		free(p);
		return NULL;
	}

	/* mmap. */
	bp->addr = mmap(NULL,
			n_buffers * params->buffer_size,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | params->mmap_flags,
			-1,
			0);
	if (bp->addr == MAP_FAILED) {
		pthread_mutex_destroy(&bp->lock);
		free(p);
		return NULL;
	}

	/* umem. */
	status = xsk_umem__create(&bp->umem,
				  bp->addr,
				  bp->params.n_buffers * bp->params.buffer_size,
				  &bp->umem_fq,
				  &bp->umem_cq,
				  umem_cfg);
	if (status) {
		munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
		pthread_mutex_destroy(&bp->lock);
		free(p);
		return NULL;
	}
	memcpy(&bp->umem_cfg, umem_cfg, sizeof(*umem_cfg));

	return bp;
}

static void
bpool_free(struct bpool *bp)
{
	if (!bp)
		return;

	xsk_umem__delete(bp->umem);
	munmap(bp->addr, bp->params.n_buffers * bp->params.buffer_size);
	pthread_mutex_destroy(&bp->lock);
	free(bp);
}

struct bcache {
	struct bpool *bp;

	u64 *slab_cons;
	u64 *slab_prod;

	u64 n_buffers_cons;
	u64 n_buffers_prod;
};

static u32
bcache_slab_size(struct bcache *bc)
{
	struct bpool *bp = bc->bp;

	return bp->params.n_buffers_per_slab;
}

static struct bcache *
bcache_init(struct bpool *bp)
{
	struct bcache *bc;

	bc = calloc(1, sizeof(struct bcache));
	if (!bc)
		return NULL;

	bc->bp = bp;
	bc->n_buffers_cons = 0;
	bc->n_buffers_prod = 0;

	pthread_mutex_lock(&bp->lock);
	if (bp->n_slabs_reserved_available == 0) {
		pthread_mutex_unlock(&bp->lock);
		free(bc);
		return NULL;
	}

	bc->slab_cons = bp->slabs_reserved[bp->n_slabs_reserved_available - 1];
	bc->slab_prod = bp->slabs_reserved[bp->n_slabs_reserved_available - 2];
	bp->n_slabs_reserved_available -= 2;
	pthread_mutex_unlock(&bp->lock);

	return bc;
}

static void
bcache_free(struct bcache *bc)
{
	struct bpool *bp;

	if (!bc)
		return;

	/* In order to keep this example simple, the case of freeing any
	 * existing buffers from the cache back to the pool is ignored.
	 */

	bp = bc->bp;
	pthread_mutex_lock(&bp->lock);
	bp->slabs_reserved[bp->n_slabs_reserved_available] = bc->slab_prod;
	bp->slabs_reserved[bp->n_slabs_reserved_available + 1] = bc->slab_cons;
	bp->n_slabs_reserved_available += 2;
	pthread_mutex_unlock(&bp->lock);

	free(bc);
}

/* To work correctly, the implementation requires that the *n_buffers* input
 * argument is never greater than the buffer pool's *n_buffers_per_slab*. This
 * is typically the case, with one exception taking place when large number of
 * buffers are allocated at init time (e.g. for the UMEM fill queue setup).
 */
static inline u32
bcache_cons_check(struct bcache *bc, u32 n_buffers)
{
	struct bpool *bp = bc->bp;
	u64 n_buffers_per_slab = bp->params.n_buffers_per_slab;
	u64 n_buffers_cons = bc->n_buffers_cons;
	u64 n_slabs_available;
	u64 *slab_full;

	/*
	 * Consumer slab is not empty: Use what's available locally. Do not
	 * look for more buffers from the pool when the ask can only be
	 * partially satisfied.
	 */
	if (n_buffers_cons)
		return (n_buffers_cons < n_buffers) ?
			n_buffers_cons :
			n_buffers;

	/*
	 * Consumer slab is empty: look to trade the current consumer slab
	 * (full) for a full slab from the pool, if any is available.
	 */
	pthread_mutex_lock(&bp->lock);
	n_slabs_available = bp->n_slabs_available;
	if (!n_slabs_available) {
		pthread_mutex_unlock(&bp->lock);
		return 0;
	}

	n_slabs_available--;
	slab_full = bp->slabs[n_slabs_available];
	bp->slabs[n_slabs_available] = bc->slab_cons;
	bp->n_slabs_available = n_slabs_available;
	pthread_mutex_unlock(&bp->lock);

	bc->slab_cons = slab_full;
	bc->n_buffers_cons = n_buffers_per_slab;
	return n_buffers;
}

static inline u64
bcache_cons(struct bcache *bc)
{
	u64 n_buffers_cons = bc->n_buffers_cons - 1;
	u64 buffer;

	buffer = bc->slab_cons[n_buffers_cons];
	bc->n_buffers_cons = n_buffers_cons;
	return buffer;
}

static inline void
bcache_prod(struct bcache *bc, u64 buffer)
{
	struct bpool *bp = bc->bp;
	u64 n_buffers_per_slab = bp->params.n_buffers_per_slab;
	u64 n_buffers_prod = bc->n_buffers_prod;
	u64 n_slabs_available;
	u64 *slab_empty;

	/*
	 * Producer slab is not yet full: store the current buffer to it.
	 */
	if (n_buffers_prod < n_buffers_per_slab) {
		bc->slab_prod[n_buffers_prod] = buffer;
		bc->n_buffers_prod = n_buffers_prod + 1;
		return;
	}

	/*
	 * Producer slab is full: trade the cache's current producer slab
	 * (full) for an empty slab from the pool, then store the current
	 * buffer to the new producer slab. As one full slab exists in the
	 * cache, it is guaranteed that there is at least one empty slab
	 * available in the pool.
	 */
	pthread_mutex_lock(&bp->lock);
	n_slabs_available = bp->n_slabs_available;
	slab_empty = bp->slabs[n_slabs_available];
	bp->slabs[n_slabs_available] = bc->slab_prod;
	bp->n_slabs_available = n_slabs_available + 1;
	pthread_mutex_unlock(&bp->lock);

	slab_empty[0] = buffer;
	bc->slab_prod = slab_empty;
	bc->n_buffers_prod = 1;
}

/*
 * Port
 *
 * Each of the forwarding ports sits on top of an AF_XDP socket. In order for
 * packet forwarding to happen with no packet buffer copy, all the sockets need
 * to share the same UMEM area, which is used as the buffer pool memory.
 */
#ifndef MAX_BURST_RX
#define MAX_BURST_RX 64
#endif

#ifndef MAX_BURST_TX
#define MAX_BURST_TX 64
#endif

struct burst_rx {
	u64 addr[MAX_BURST_RX];
	u32 len[MAX_BURST_RX];
};

struct burst_tx {
	u64 addr[MAX_BURST_TX];
	u32 len[MAX_BURST_TX];
	u32 n_pkts;
};

struct port_params {
	struct xsk_socket_config xsk_cfg;
	struct bpool *bp;
	const char *iface;
	u32 iface_queue;
};

struct shareable_rings {
	pthread_spinlock_t fq_lock;
	pthread_spinlock_t cq_lock;
	struct xsk_ring_prod _umem_fq;
	struct xsk_ring_cons _umem_cq;
	int _umem_fq_initialized;
	u32 refs;
};

struct port {
	struct port_params params;

	struct bcache *bc;

	struct xsk_ring_cons rxq;
	struct xsk_ring_prod txq;
	struct shareable_rings *r;
	struct xsk_socket *xsk;

#define umem_fq r->_umem_fq
#define umem_cq r->_umem_cq
#define umem_fq_initialized r->_umem_fq_initialized

	u64 n_pkts_rx;
	u64 n_pkts_tx;
};

#ifndef MAX_PORTS
#define MAX_PORTS 64
#endif

static struct port_params port_params[MAX_PORTS];
static struct port *ports[MAX_PORTS];
static u64 n_pkts_rx[MAX_PORTS];
static u64 n_pkts_tx[MAX_PORTS];
static int n_ports;

static bool
is_same_iface_qid_pair(struct port *port_a, struct port *port_b)
{
	if (port_a->params.iface_queue != port_b->params.iface_queue)
		return false;
	return strcmp(port_a->params.iface, port_b->params.iface) == 0;
}

static void
port_free(struct port *p)
{
	if (!p)
		return;

	/* To keep this example simple, the code to free the buffers from the
	 * socket's receive and transmit queues, as well as from the UMEM fill
	 * and completion queues, is not included.
	 */

	if (p->xsk)
		xsk_socket__delete(p->xsk);

	bcache_free(p->bc);

	/* if (p->r) { */
	/* 	p->r->refs--; */
	/* 	if (p->r->refs == 0) */
	/* 		free(p->r); */
	/* } */

	free(p);
}

static struct port *
port_init(struct port_params *params)
{
	struct port *p;
	u32 umem_fq_size, pos = 0;
	int status, i;

	/* Memory allocation and initialization. */
	p = calloc(sizeof(struct port), 1);
	if (!p)
		return NULL;

	memcpy(&p->params, params, sizeof(p->params));
	umem_fq_size = params->bp->umem_cfg.fill_size;

	/* bcache. */
	p->bc = bcache_init(params->bp);
	if (!p->bc ||
	    (bcache_slab_size(p->bc) < umem_fq_size) ||
	    (bcache_cons_check(p->bc, umem_fq_size) < umem_fq_size)) {
		port_free(p);
		return NULL;
	}

	p->r = calloc(sizeof(struct shareable_rings), 1);
	pthread_spin_init(&p->r->fq_lock, 0);
	pthread_spin_init(&p->r->cq_lock, 0);
	if (!p->r) {
		port_free(p);
		return NULL;
	}

	/* xsk socket. */
	status = xsk_socket__create_shared(&p->xsk,
					   params->iface,
					   params->iface_queue,
					   params->bp->umem,
					   &p->rxq,
					   &p->txq,
					   &p->umem_fq,
					   &p->umem_cq,
					   &params->xsk_cfg);
	if (status) {
		port_free(p);
		return NULL;
	}

	// check if we have another socket on the same interface-queue (port)
	for (u32 i = 0; i < n_ports; i++) {
		struct port *other = ports[i];
		if (!other)
			continue;
		if (other->umem_fq_initialized == 0)
			continue; // is not initialized yet
		if (!is_same_iface_qid_pair(other, p))
			continue; // is not same iface-queue pair
		// oh, we have bound on this queue before:
		free(p->r);
		p->r = other->r;
		p->r->refs++;
		return p; // we are done
	}

	/* umem fq. */
	xsk_ring_prod__reserve(&p->umem_fq, umem_fq_size, &pos);

	for (i = 0; i < umem_fq_size; i++)
		*xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) =
			bcache_cons(p->bc);

	xsk_ring_prod__submit(&p->umem_fq, umem_fq_size);
	p->umem_fq_initialized = 1;

	return p;
}

static inline u32
port_rx_burst(struct port *p, struct burst_rx *b)
{
	u32 n_pkts, pos, i;

	/* Free buffers for FQ replenish. */
	n_pkts = ARRAY_SIZE(b->addr);

	n_pkts = bcache_cons_check(p->bc, n_pkts);
	if (!n_pkts)
		return 0;

	/* RXQ. */
	n_pkts = xsk_ring_cons__peek(&p->rxq, n_pkts, &pos);
	if (!n_pkts) {
		if (xsk_ring_prod__needs_wakeup(&p->umem_fq)) {
			struct pollfd pollfd = {
				.fd = xsk_socket__fd(p->xsk),
				.events = POLLIN,
			};

			poll(&pollfd, 1, 0);
		}
		return 0;
	}

	for (i = 0; i < n_pkts; i++) {
		b->addr[i] = xsk_ring_cons__rx_desc(&p->rxq, pos + i)->addr;
		b->len[i] = xsk_ring_cons__rx_desc(&p->rxq, pos + i)->len;
	}

	xsk_ring_cons__release(&p->rxq, n_pkts);
	p->n_pkts_rx += n_pkts;

	/* UMEM FQ. */
	pthread_spin_lock(&p->r->fq_lock);
	for ( ; ; ) {
		int status;

		status = xsk_ring_prod__reserve(&p->umem_fq, n_pkts, &pos);
		if (status == n_pkts)
			break;

		if (xsk_ring_prod__needs_wakeup(&p->umem_fq)) {
			struct pollfd pollfd = {
				.fd = xsk_socket__fd(p->xsk),
				.events = POLLIN,
			};

			poll(&pollfd, 1, 0);
		}
	}

	for (i = 0; i < n_pkts; i++)
		*xsk_ring_prod__fill_addr(&p->umem_fq, pos + i) =
			bcache_cons(p->bc);

	xsk_ring_prod__submit(&p->umem_fq, n_pkts);
	pthread_spin_unlock(&p->r->fq_lock);

	return n_pkts;
}

static inline void
port_tx_burst(struct port *p, struct burst_tx *b)
{
	u32 n_pkts, pos, i;
	int status;

	/* UMEM CQ. */
	pthread_spin_lock(&p->r->cq_lock);
	n_pkts = p->params.bp->umem_cfg.comp_size;

	n_pkts = xsk_ring_cons__peek(&p->umem_cq, n_pkts, &pos);

	for (i = 0; i < n_pkts; i++) {
		u64 addr = *xsk_ring_cons__comp_addr(&p->umem_cq, pos + i);

		bcache_prod(p->bc, addr);
	}

	xsk_ring_cons__release(&p->umem_cq, n_pkts);
	pthread_spin_unlock(&p->r->cq_lock);

	/* TXQ. */
	n_pkts = b->n_pkts;

	for ( ; ; ) {
		status = xsk_ring_prod__reserve(&p->txq, n_pkts, &pos);
		if (status == n_pkts)
			break;

		if (xsk_ring_prod__needs_wakeup(&p->txq))
			sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT,
			       NULL, 0);
	}

	for (i = 0; i < n_pkts; i++) {
		xsk_ring_prod__tx_desc(&p->txq, pos + i)->addr = b->addr[i];
		xsk_ring_prod__tx_desc(&p->txq, pos + i)->len = b->len[i];
	}

	xsk_ring_prod__submit(&p->txq, n_pkts);
	if (xsk_ring_prod__needs_wakeup(&p->txq))
		sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	p->n_pkts_tx += n_pkts;
}

/*
 * Thread
 *
 * Packet forwarding threads.
 */
#ifndef MAX_PORTS_PER_THREAD
#define MAX_PORTS_PER_THREAD 16
#endif

static u64 delay = 0;

struct thread_data {
	struct port *ports_rx[MAX_PORTS_PER_THREAD];
	struct port *ports_tx[MAX_PORTS_PER_THREAD];
	u32 n_ports_rx;
	struct burst_rx burst_rx;
	struct burst_tx burst_tx[MAX_PORTS_PER_THREAD];
	u32 cpu_core_id;
	int quit;
};

u64 fib(u32 limit)
{
	u64 a = 1, b = 1 , c = 0;
	for (__u32 i = 2; i < limit; i++) {
		c = a + b;
		a = b;
		b = c;
	}
	return b;
}

static inline void do_some_pkt_processing(void *data, u32 len)
{
	if (delay == 0) return;
	u64 f = fib(delay);
	if (f == 4) {
		printf("this should be impossible\n");
	}
}

static void swap_mac_addresses(void *data)
{
	struct ether_header *eth = (struct ether_header *)data;
	struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
	struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
	struct ether_addr tmp;

	tmp = *src_addr;
	*src_addr = *dst_addr;
	*dst_addr = tmp;
}

static void *
thread_func(void *arg)
{
	struct thread_data *t = arg;
	cpu_set_t cpu_cores;
	u32 i;

	CPU_ZERO(&cpu_cores);
	CPU_SET(t->cpu_core_id, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);

	for (i = 0; !t->quit; i = (i + 1) & (t->n_ports_rx - 1)) {
		struct port *port_rx = t->ports_rx[i];
		struct port *port_tx = t->ports_tx[i];
		struct burst_rx *brx = &t->burst_rx;
		struct burst_tx *btx = &t->burst_tx[i];
		u32 n_pkts, j;

		/* RX. */
		n_pkts = port_rx_burst(port_rx, brx);
		if (!n_pkts)
			continue;

		/* Process & TX. */
		for (j = 0; j < n_pkts; j++) {
			u64 addr = xsk_umem__add_offset_to_addr(brx->addr[j]);
			u8 *pkt = xsk_umem__get_data(port_rx->params.bp->addr,
						     addr);

			do_some_pkt_processing(pkt, brx->len[j]);
			swap_mac_addresses(pkt);

			btx->addr[btx->n_pkts] = brx->addr[j];
			btx->len[btx->n_pkts] = brx->len[j];
			btx->n_pkts++;

			if (btx->n_pkts == MAX_BURST_TX) {
				port_tx_burst(port_tx, btx);
				btx->n_pkts = 0;
			}
		}
	}

	return NULL;
}

/*
 * Process
 */
static const struct bpool_params bpool_params_default = {
	.n_buffers = 64 * 1024,
	.buffer_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	.mmap_flags = 0,

	.n_users_max = 16,
	.n_buffers_per_slab = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
};

static const struct xsk_umem_config umem_cfg_default = {
	.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
	.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
	.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
	.flags = 0,
};

static const struct port_params port_params_default = {
	.xsk_cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libxdp_flags = 0,
		.xdp_flags = XDP_FLAGS_DRV_MODE,
		.bind_flags = XDP_USE_NEED_WAKEUP,
	},

	.bp = NULL,
	.iface = NULL,
	.iface_queue = 0,
};

#ifndef MAX_THREADS
#define MAX_THREADS 64
#endif

static struct bpool_params bpool_params;
static struct xsk_umem_config umem_cfg;
static struct bpool *bp;

static pthread_t threads[MAX_THREADS];
static struct thread_data thread_data[MAX_THREADS];
static int n_threads;

static bool load_xdp_prog = false;
static char *custom_prog_path = NULL;

static void
print_usage(char *prog_name)
{
	const char *usage =
		"Usage:\n"
		"\t%s [ -b SIZE ] -c CORE -i INTERFACE [ -q QUEUE ]\n"
		"\n"
		"-c CORE        CPU core to run a packet forwarding thread\n"
		"               on. May be invoked multiple times.\n"
		"\n"
		"-b SIZE        Number of buffers in the buffer pool shared\n"
		"               by all the forwarding threads. Default: %u.\n"
		"\n"
		"-i INTERFACE   Network interface. Each (INTERFACE, QUEUE)\n"
		"               pair specifies one forwarding port. May be\n"
		"               invoked multiple times.\n"
		"\n"
		"-q QUEUE       Network interface queue for RX and TX. Each\n"
		"               (INTERFACE, QUEUE) pair specified one\n"
		"               forwarding port. Default: %u. May be invoked\n"
		"               multiple times.\n"
		"-d DELAY       Calculate the given fibonacci number as proxy\n"
		"			for processing a packet.\n"
		"-x XDP-PROG    Load the XDP program\n"
		"\n";
	printf(usage,
	       prog_name,
	       bpool_params_default.n_buffers,
	       port_params_default.iface_queue);
}

static int
parse_args(int argc, char **argv)
{
	struct option lgopts[] = {
		{ NULL,  0, 0, 0 }
	};
	int opt, option_index;

	/* Parse the input arguments. */
	for ( ; ;) {
		opt = getopt_long(argc, argv, "b:c:d:i:q:x:", lgopts, &option_index);
		if (opt == EOF)
			break;

		switch (opt) {
		case 'b':
			bpool_params.n_buffers = atoi(optarg);
			break;

		case 'c':
			if (n_threads == MAX_THREADS) {
				printf("Max number of threads (%d) reached.\n",
				       MAX_THREADS);
				return -1;
			}

			thread_data[n_threads].cpu_core_id = atoi(optarg);
			n_threads++;
			break;
		case 'd':
			sscanf(optarg, "%llu", &delay);
			break;
		case 'i':
			if (n_ports == MAX_PORTS) {
				printf("Max number of ports (%d) reached.\n",
				       MAX_PORTS);
				return -1;
			}

			port_params[n_ports].iface = optarg;
			port_params[n_ports].iface_queue = 0;
			n_ports++;
			break;

		case 'q':
			if (n_ports == 0) {
				printf("No port specified for queue.\n");
				return -1;
			}
			port_params[n_ports - 1].iface_queue = atoi(optarg);
			break;

		case 'x':
			load_xdp_prog = true;
			custom_prog_path = strdup(optarg);
			break;

		default:
			printf("Illegal argument.\n");
			return -1;
		}
	}

	optind = 1; /* reset getopt lib */

	/* Check the input arguments. */
	if (!n_ports) {
		printf("No ports specified.\n");
		return -1;
	}

	if (!n_threads) {
		printf("No threads specified.\n");
		return -1;
	}

	if (n_ports % n_threads) {
		printf("Ports cannot be evenly distributed to threads.\n");
		return -1;
	}

	return 0;
}

static void
print_port(u32 port_id)
{
	struct port *port = ports[port_id];

	printf("Port %u: interface = %s, queue = %u\n",
	       port_id, port->params.iface, port->params.iface_queue);
}

static void
print_thread(u32 thread_id)
{
	struct thread_data *t = &thread_data[thread_id];
	u32 i;

	printf("Thread %u (CPU core %u): ",
	       thread_id, t->cpu_core_id);

	for (i = 0; i < t->n_ports_rx; i++) {
		struct port *port_rx = t->ports_rx[i];
		struct port *port_tx = t->ports_tx[i];

		printf("(%s, %u) -> (%s, %u), ",
		       port_rx->params.iface,
		       port_rx->params.iface_queue,
		       port_tx->params.iface,
		       port_tx->params.iface_queue);
	}

	printf("\n");
}

static void
print_port_stats_separator(void)
{
	printf("+-%4s-+-%12s-+-%13s-+-%12s-+-%13s-+\n",
	       "----",
	       "------------",
	       "-------------",
	       "------------",
	       "-------------");
}

static void
print_port_stats_header(void)
{
	print_port_stats_separator();
	printf("| %4s | %12s | %13s | %12s | %13s |\n",
	       "Port",
	       "RX packets",
	       "RX rate (pps)",
	       "TX packets",
	       "TX_rate (pps)");
	print_port_stats_separator();
}

static void
print_port_stats_trailer(void)
{
	print_port_stats_separator();
	printf("\n");
}

static void
print_port_stats(int port_id, u64 ns_diff)
{
	struct port *p = ports[port_id];
	double rx_pps, tx_pps;

	rx_pps = (p->n_pkts_rx - n_pkts_rx[port_id]) * 1000000000. / ns_diff;
	tx_pps = (p->n_pkts_tx - n_pkts_tx[port_id]) * 1000000000. / ns_diff;

	printf("| %4d | %12llu | %13.0f | %12llu | %13.0f |\n",
	       port_id,
	       p->n_pkts_rx,
	       rx_pps,
	       p->n_pkts_tx,
	       tx_pps);

	n_pkts_rx[port_id] = p->n_pkts_rx;
	n_pkts_tx[port_id] = p->n_pkts_tx;
}

static void
print_port_stats_all(u64 ns_diff)
{
	int i;

	print_port_stats_header();
	for (i = 0; i < n_ports; i++)
		print_port_stats(i, ns_diff);
	print_port_stats_trailer();
}

static int quit;

static void
signal_handler(int sig)
{
	quit = 1;
}

#define STRERR_BUFSIZE          1024
static enum xdp_attach_mode opt_attach_mode = XDP_MODE_NATIVE;
static struct xdp_program *xdp_prog = NULL;
static void remove_xdp_program(void)
{
	struct xdp_multiprog *mp;
	int i, err;


	for (i = 0 ; i < n_ports; i++) {
		int ifindex = if_nametoindex(port_params[i].iface);
		bpf_xdp_attach(ifindex, -1, opt_attach_mode, NULL);

	        mp = xdp_multiprog__get_from_ifindex(ifindex);
	        if (IS_ERR_OR_NULL(mp)) {
	        	printf("No XDP program loaded on %s\n", port_params[i].iface);
	        	continue;
	        }

                err = xdp_multiprog__detach(mp);
                if (err)
                        printf("Unable to detach XDP program: %s\n", strerror(-err));
	}
}

static void load_xdp_program(void)
{
	char errmsg[STRERR_BUFSIZE];
	int err;
	
	if (custom_prog_path == NULL) {
		fprintf(stderr, "internal error, the xdp program path is not set\n");
		exit(EXIT_FAILURE);
	}

	xdp_prog = xdp_program__open_file(custom_prog_path, NULL, NULL);
	err = libxdp_get_error(xdp_prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: program loading failed: %s\n", errmsg);
		exit(EXIT_FAILURE);
	}
}

static void attach_xdp_program(void)
{
	char errmsg[STRERR_BUFSIZE];
	assert (xdp_prog != NULL);
	for (u32 i = 0; i < n_ports; i++) {
		bool duplicate = false;
		for (u32 j = 0; j < i; j++) {
			if (strcmp(ports[i]->params.iface, ports[j]->params.iface) == 0) {
				duplicate = true;
				break;
			}
		}
		if (duplicate)
			continue;
		// attach xdp to this interface
		int ifindex = if_nametoindex(ports[i]->params.iface);
		if (ifindex  < 0) {
			fprintf(stderr, "failed to get interface fd for %s\n", ports[i]->params.iface);
			remove_xdp_program();
			exit(EXIT_FAILURE);
		}
		int err = xdp_program__attach(xdp_prog, ifindex, opt_attach_mode, 0);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "ERROR: attaching program failed: %s\n", errmsg);
			remove_xdp_program();
			exit(EXIT_FAILURE);
		}
		printf("Attaching XDP to %s\n", ports[i]->params.iface);
	}
}

static int lookup_bpf_map(int prog_fd)
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	int fd, err, xsks_map_fd = -ENOENT;
	struct bpf_map_info map_info;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -ENOMEM;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		free(map_ids);
		return err;
	}

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		memset(&map_info, 0, map_len);
		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strncmp(map_info.name, "xsks_map", sizeof(map_info.name)) &&
		    map_info.key_size == 4 && map_info.value_size == 4) {
			xsks_map_fd = fd;
			break;
		}

		close(fd);
	}

	free(map_ids);
	return xsks_map_fd;
}

static void insert_sockets(void)
{
	struct bpf_map *data_map;
	int i, xsks_map;
	int key = 0;

	data_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(xdp_prog), ".bss");
	if (!data_map || !bpf_map__is_internal(data_map)) {
		fprintf(stderr, "ERROR: bss map found!\n");
		remove_xdp_program();
		exit(EXIT_FAILURE);
	}
	if (bpf_map_update_elem(bpf_map__fd(data_map), &key, &n_ports, BPF_ANY)) {
		fprintf(stderr, "ERROR: bpf_map_update_elem num_socks %d!\n", n_ports);
		remove_xdp_program();
		exit(EXIT_FAILURE);
	}
	xsks_map = lookup_bpf_map(xdp_program__fd(xdp_prog));
	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
			remove_xdp_program();
			exit(EXIT_FAILURE);
	}

	for (i = 0; i < n_ports; i++) {
		struct port *p = ports[i];
		int fd = xsk_socket__fd(p->xsk);
		int ret;

		key = i;
		ret = bpf_map_update_elem(xsks_map, &key, &fd, 0);
		if (ret) {
			fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
			remove_xdp_program();
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char **argv)
{
	struct timespec time;
	u64 ns0;
	int i;

	remove_xdp_program();

	/* Parse args. */
	memcpy(&bpool_params, &bpool_params_default,
	       sizeof(struct bpool_params));
	memcpy(&umem_cfg, &umem_cfg_default,
	       sizeof(struct xsk_umem_config));

	for (i = 0; i < MAX_PORTS; i++)
		memcpy(&port_params[i], &port_params_default,
		       sizeof(struct port_params));

	if (parse_args(argc, argv)) {
		print_usage(argv[0]);
		return -1;
	}

	if (load_xdp_prog) {
		for (i = 0; i < MAX_PORTS; i++)
			port_params[i].xsk_cfg.libxdp_flags =
				XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
	}


	/* Buffer pool initialization. */
	bp = bpool_init(&bpool_params, &umem_cfg);
	if (!bp) {
		printf("Buffer pool initialization failed.\n");
		return -1;
	}
	printf("Buffer pool created successfully.\n");

	/* Ports initialization. */
	for (i = 0; i < MAX_PORTS; i++)
		port_params[i].bp = bp;

	for (i = 0; i < n_ports; i++) {
		ports[i] = port_init(&port_params[i]);
		if (!ports[i]) {
			printf("Port %d initialization failed.\n", i);
			return -1;
		}
		print_port(i);
	}
	printf("All ports created successfully.\n");

	if (load_xdp_prog) {
		printf("Loading custom XDP program\n");
		load_xdp_program();
		attach_xdp_program();
		insert_sockets();
	}

	/* Threads. */
	for (i = 0; i < n_threads; i++) {
		struct thread_data *t = &thread_data[i];
		u32 n_ports_per_thread = n_ports / n_threads, j;

		for (j = 0; j < n_ports_per_thread; j++) {
			t->ports_rx[j] = ports[i * n_ports_per_thread + j];
			t->ports_tx[j] = ports[i * n_ports_per_thread +
				(j + 1) % n_ports_per_thread];
		}

		t->n_ports_rx = n_ports_per_thread;

		print_thread(i);
	}

	for (i = 0; i < n_threads; i++) {
		int status;

		status = pthread_create(&threads[i],
					NULL,
					thread_func,
					&thread_data[i]);
		if (status) {
			printf("Thread %d creation failed.\n", i);
			return -1;
		}
	}
	printf("All threads created successfully.\n");

	/* Print statistics. */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);

	clock_gettime(CLOCK_MONOTONIC, &time);
	ns0 = time.tv_sec * 1000000000UL + time.tv_nsec;
	for ( ; !quit; ) {
		u64 ns1, ns_diff;

		sleep(1);
		clock_gettime(CLOCK_MONOTONIC, &time);
		ns1 = time.tv_sec * 1000000000UL + time.tv_nsec;
		ns_diff = ns1 - ns0;
		ns0 = ns1;

		print_port_stats_all(ns_diff);
	}

	/* Threads completion. */
	printf("Quit.\n");
	for (i = 0; i < n_threads; i++)
		thread_data[i].quit = 1;

	for (i = 0; i < n_threads; i++)
		pthread_join(threads[i], NULL);

	for (i = 0; i < n_ports; i++)
		port_free(ports[i]);

	bpool_free(bp);

	remove_xdp_program();

	return 0;
}
