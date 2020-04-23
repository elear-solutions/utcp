/*
    utcp.c -- Userspace TCP
    Copyright (C) 2014-2017 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "utcp_priv.h"

#ifndef EBADMSG
#define EBADMSG         104
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

#ifdef poll
#undef poll
#endif

#ifndef UTCP_CLOCK
#if defined(CLOCK_MONOTONIC_RAW) && defined(__x86_64__)
#define UTCP_CLOCK CLOCK_MONOTONIC_RAW
#else
#define UTCP_CLOCK CLOCK_MONOTONIC
#endif
#endif

static void timespec_sub(const struct timespec *a, const struct timespec *b, struct timespec *r) {
	printf("%s.%d. Started\n", __func__, __LINE__);
	r->tv_sec = a->tv_sec - b->tv_sec;
	r->tv_nsec = a->tv_nsec - b->tv_nsec;

	if(r->tv_nsec < 0) {
		r->tv_sec--, r->tv_nsec += NSEC_PER_SEC;
	}
	printf("%s.%d. Done\n", __func__, __LINE__);
}

static int32_t timespec_diff_usec(const struct timespec *a, const struct timespec *b) {
	printf("%s.%d. Inside timespec_diff_usec\n", __func__, __LINE__);
	return (a->tv_sec - b->tv_sec) * 1000000 + (a->tv_nsec - b->tv_nsec) / 1000;
}

static bool timespec_lt(const struct timespec *a, const struct timespec *b) {
	printf("%s.%d. Started\n", __func__, __LINE__);
	if(a->tv_sec == b->tv_sec) {
		return a->tv_nsec < b->tv_nsec;
	} else {
		return a->tv_sec < b->tv_sec;
	}
	printf("%s.%d. Done\n", __func__, __LINE__);
}

static void timespec_clear(struct timespec *a) {
	a->tv_sec = 0;
	a->tv_nsec = 0;
}

static bool timespec_isset(const struct timespec *a) {
	return a->tv_sec;
}

static long CLOCK_GRANULARITY; // usec

static inline size_t min(size_t a, size_t b) {
	return a < b ? a : b;
}

static inline size_t max(size_t a, size_t b) {
	return a > b ? a : b;
}

#ifdef UTCP_DEBUG
#include <stdarg.h>

#ifndef UTCP_DEBUG_DATALEN
#define UTCP_DEBUG_DATALEN 20
#endif

static void debug(struct utcp_connection *c, const char *format, ...) {
	struct timespec tv;
	char buf[1024];
	int len;

	clock_gettime(CLOCK_REALTIME, &tv);
	len = snprintf(buf, sizeof(buf), "%ld.%06lu %u:%u ", (long)tv.tv_sec, tv.tv_nsec / 1000, c ? c->src : 0, c ? c->dst : 0);
	va_list ap;
	va_start(ap, format);
	len += vsnprintf(buf + len, sizeof(buf) - len, format, ap);
	va_end(ap);

	if(len > 0 && (size_t)len < sizeof(buf)) {
		fwrite(buf, len, 1, stderr);
	}
}

static void print_packet(struct utcp_connection *c, const char *dir, const void *pkt, size_t len) {
	struct hdr hdr;

	if(len < sizeof(hdr)) {
		debug(c, "%s: short packet (%lu bytes)\n", dir, (unsigned long)len);
		return;
	}

	memcpy(&hdr, pkt, sizeof(hdr));

	uint32_t datalen;

	if(len > sizeof(hdr)) {
		datalen = min(len - sizeof(hdr), UTCP_DEBUG_DATALEN);
	} else {
		datalen = 0;
	}


	const uint8_t *data = (uint8_t *)pkt + sizeof(hdr);
	char str[datalen * 2 + 1];
	char *p = str;

	for(uint32_t i = 0; i < datalen; i++) {
		*p++ = "0123456789ABCDEF"[data[i] >> 4];
		*p++ = "0123456789ABCDEF"[data[i] & 15];
	}

	*p = 0;

	debug(c, "%s: len %lu src %u dst %u seq %u ack %u wnd %u aux %x ctl %s%s%s%s%s data %s\n",
	      dir, (unsigned long)len, hdr.src, hdr.dst, hdr.seq, hdr.ack, hdr.wnd, hdr.aux,
	      hdr.ctl & SYN ? "SYN" : "",
	      hdr.ctl & RST ? "RST" : "",
	      hdr.ctl & FIN ? "FIN" : "",
	      hdr.ctl & ACK ? "ACK" : "",
	      hdr.ctl & MF ? "MF" : "",
	      str
	     );
}

static void debug_cwnd(struct utcp_connection *c) {
	debug(c, "snd.cwnd %u snd.ssthresh %u\n", c->snd.cwnd, ~c->snd.ssthresh ? c->snd.ssthresh : 0);
}
#else
#define debug(...) do {} while(0)
#define print_packet(...) do {} while(0)
#define debug_cwnd(...) do {} while(0)
#endif

static void set_state(struct utcp_connection *c, enum state state) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	c->state = state;

	if(state == ESTABLISHED) {
		timespec_clear(&c->conn_timeout);
	}

	debug(c, "state %s\n", strstate[state]);
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

static bool fin_wanted(struct utcp_connection *c, uint32_t seq) {
	debug(NULL, "%s.%d. called\n", __func__, __LINE__);
	if(seq != c->snd.last) {
	debug(NULL, "%s.%d. seq != c->snd.last\n", __func__, __LINE__);
		return false;
	}

	switch(c->state) {
	case FIN_WAIT_1:
	case CLOSING:
	case LAST_ACK:
	debug(NULL, "%s.%d. LAST ACK\n", __func__, __LINE__);
		return true;

	default:
	debug(NULL, "%s.%d. Default\n", __func__, __LINE__);
		return false;
	}
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

static bool is_reliable(struct utcp_connection *c) {
	debug(NULL, "%s.%d. called\n", __func__, __LINE__);
	return c->flags & UTCP_RELIABLE;
}

static int32_t seqdiff(uint32_t a, uint32_t b) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	return a - b;
}

// Buffer functions
static bool buffer_wraps(struct buffer *buf) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	return buf->size - buf->offset < buf->used;
}

static bool buffer_resize(struct buffer *buf, uint32_t newsize) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	char *newdata = realloc(buf->data, newsize);

	if(!newdata) {
		return false;
	}

	buf->data = newdata;

	if(buffer_wraps(buf)) {
		// Shift the right part of the buffer until it hits the end of the new buffer.
		// Old situation:
		// [345......012]
		// New situation:
		// [345.........|........012]
		uint32_t tailsize = buf->size - buf->offset;
		uint32_t newoffset = newsize - tailsize;
		memmove(buf->data + newoffset, buf->data + buf->offset, tailsize);
		buf->offset = newoffset;
	}

	buf->size = newsize;
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return true;
}

// Store data into the buffer
static ssize_t buffer_put_at(struct buffer *buf, size_t offset, const void *data, size_t len) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	debug(NULL, "buffer_put_at %lu %lu %lu\n", (unsigned long)buf->used, (unsigned long)offset, (unsigned long)len);

	// Ensure we don't store more than maxsize bytes in total
	size_t required = offset + len;

	if(required > buf->maxsize) {
		if(offset >= buf->maxsize) {
			return 0;
		}

		len = buf->maxsize - offset;
		required = buf->maxsize;
	}

	// Check if we need to resize the buffer
	if(required > buf->size) {
		size_t newsize = buf->size;

		if(!newsize) {
			newsize = 4096;
		}

		do {
			newsize *= 2;
		} while(newsize < required);

		if(newsize > buf->maxsize) {
			newsize = buf->maxsize;
		}

		if(!buffer_resize(buf, newsize)) {
			return -1;
		}
	}

	uint32_t realoffset = buf->offset + offset;

	if(buf->size - buf->offset < offset) {
		// The offset wrapped
		realoffset -= buf->size;
	}

	if(buf->size - realoffset < len) {
		// The new chunk of data must be wrapped
		memcpy(buf->data + realoffset, data, buf->size - realoffset);
		memcpy(buf->data, (char *)data + buf->size - realoffset, len - (buf->size - realoffset));
	} else {
		memcpy(buf->data + realoffset, data, len);
	}

	if(required > buf->used) {
		buf->used = required;
	}

	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return len;
}

static ssize_t buffer_put(struct buffer *buf, const void *data, size_t len) {
	debug(NULL, "%s.%d. called\n", __func__, __LINE__);
	return buffer_put_at(buf, buf->used, data, len);
}

// Copy data from the buffer without removing it.
static ssize_t buffer_copy(struct buffer *buf, void *data, size_t offset, size_t len) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	// Ensure we don't copy more than is actually stored in the buffer
	if(offset >= buf->used) {
		return 0;
	}

	if(buf->used - offset < len) {
		len = buf->used - offset;
	}

	uint32_t realoffset = buf->offset + offset;

	if(buf->size - buf->offset < offset) {
		// The offset wrapped
		realoffset -= buf->size;
	}

	if(buf->size - realoffset < len) {
		// The data is wrapped
		memcpy(data, buf->data + realoffset, buf->size - realoffset);
		memcpy((char *)data + buf->size - realoffset, buf->data, len - (buf->size - realoffset));
	} else {
		memcpy(data, buf->data + realoffset, len);
	}

	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return len;
}

// Copy data from the buffer without removing it.
static ssize_t buffer_call(struct buffer *buf, utcp_recv_t cb, void *arg, size_t offset, size_t len) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	// Ensure we don't copy more than is actually stored in the buffer
	if(offset >= buf->used) {
		return 0;
	}

	if(buf->used - offset < len) {
		len = buf->used - offset;
	}

	uint32_t realoffset = buf->offset + offset;

	if(buf->size - buf->offset < offset) {
		// The offset wrapped
		realoffset -= buf->size;
	}

	if(buf->size - realoffset < len) {
		// The data is wrapped
		ssize_t rx1 = cb(arg, buf->data + realoffset, buf->size - realoffset);

		if(rx1 < buf->size - realoffset) {
			return rx1;
		}

		ssize_t rx2 = cb(arg, buf->data, len - (buf->size - realoffset));

		if(rx2 < 0) {
			return rx2;
		} else {
			return rx1 + rx2;
		}
	} else {
		return cb(arg, buf->data + realoffset, len);
	}
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

// Discard data from the buffer.
static ssize_t buffer_discard(struct buffer *buf, size_t len) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(buf->used < len) {
	debug(NULL, "%s.%d. len = used buffer size\n", __func__, __LINE__);
		len = buf->used;
	}

	debug(NULL, "%s.%d. If buffer size - offset is < len\n", __func__, __LINE__);
	if(buf->size - buf->offset < len) {
	debug(NULL, "%s.%d. Modify buffer offset\n", __func__, __LINE__);
		buf->offset -= buf->size;
	}

	debug(NULL, "%s.%d. If buffer used is = len\n", __func__, __LINE__);
	if(buf->used == len) {
	debug(NULL, "%s.%d. Reset buffer offset\n", __func__, __LINE__);
		buf->offset = 0;
	} else {
	debug(NULL, "%s.%d. Increase buffer offset\n", __func__, __LINE__);
		buf->offset += len;
	}

	debug(NULL, "%s.%d. Reduce buffer used by len\n", __func__, __LINE__);
	buf->used -= len;

	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return len;
}

static void buffer_clear(struct buffer *buf) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	buf->used = 0;
	buf->offset = 0;
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

static bool buffer_set_size(struct buffer *buf, uint32_t minsize, uint32_t maxsize) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(maxsize < minsize) {
		maxsize = minsize;
	}

	buf->maxsize = maxsize;

	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return buf->size >= minsize || buffer_resize(buf, minsize);
}

static void buffer_exit(struct buffer *buf) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	free(buf->data);
	memset(buf, 0, sizeof(*buf));
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

static uint32_t buffer_free(const struct buffer *buf) {
	debug(NULL, "%s.%d. Buffer free called\n", __func__, __LINE__);
	return buf->maxsize - buf->used;
}

// Connections are stored in a sorted list.
// This gives O(log(N)) lookup time, O(N log(N)) insertion time and O(N) deletion time.

static int compare(const void *va, const void *vb) {
	debug(NULL, "%s.%d. Compare connections\n", __func__, __LINE__);
	assert(va && vb);

	const struct utcp_connection *a = *(struct utcp_connection **)va;
	const struct utcp_connection *b = *(struct utcp_connection **)vb;

	assert(a && b);
	assert(a->src && b->src);

	int c = (int)a->src - (int)b->src;

	if(c) {
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
		return c;
	}

	c = (int)a->dst - (int)b->dst;
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return c;
}

static struct utcp_connection *find_connection(const struct utcp *utcp, uint16_t src, uint16_t dst) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(!utcp->nconnections) {
	debug(NULL, "%s.%d. NULL Done\n", __func__, __LINE__);
		return NULL;
	}

	struct utcp_connection key = {
		.src = src,
		.dst = dst,
	}, *keyp = &key;
	debug(NULL, "%s.%d. bsearch\n", __func__, __LINE__);
	struct utcp_connection **match = bsearch(&keyp, utcp->connections, utcp->nconnections, sizeof(*utcp->connections), compare);
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return match ? *match : NULL;
}

static void free_connection(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	struct utcp *utcp = c->utcp;
	struct utcp_connection **cp = bsearch(&c, utcp->connections, utcp->nconnections, sizeof(*utcp->connections), compare);

	assert(cp);

	int i = cp - utcp->connections;
	memmove(cp, cp + 1, (utcp->nconnections - i - 1) * sizeof(*cp));
	utcp->nconnections--;

	buffer_exit(&c->rcvbuf);
	buffer_exit(&c->sndbuf);
	free(c);
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

static struct utcp_connection *allocate_connection(struct utcp *utcp, uint16_t src, uint16_t dst) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	// Check whether this combination of src and dst is free

	if(src) {
		if(find_connection(utcp, src, dst)) {
			errno = EADDRINUSE;
			return NULL;
		}
	} else { // If src == 0, generate a random port number with the high bit set
		if(utcp->nconnections >= 32767) {
			errno = ENOMEM;
			return NULL;
		}

		src = rand() | 0x8000;

		while(find_connection(utcp, src, dst)) {
			src++;
		}
	}

	// Allocate memory for the new connection

	if(utcp->nconnections >= utcp->nallocated) {
		if(!utcp->nallocated) {
			utcp->nallocated = 4;
		} else {
			utcp->nallocated *= 2;
		}

		struct utcp_connection **new_array = realloc(utcp->connections, utcp->nallocated * sizeof(*utcp->connections));

		if(!new_array) {
			return NULL;
		}

		utcp->connections = new_array;
	}

	struct utcp_connection *c = calloc(1, sizeof(*c));

	if(!c) {
		return NULL;
	}

	if(!buffer_set_size(&c->sndbuf, DEFAULT_SNDBUFSIZE, DEFAULT_MAXSNDBUFSIZE)) {
		free(c);
		return NULL;
	}

	if(!buffer_set_size(&c->rcvbuf, DEFAULT_RCVBUFSIZE, DEFAULT_MAXRCVBUFSIZE)) {
		buffer_exit(&c->sndbuf);
		free(c);
		return NULL;
	}

	// Fill in the details

	c->src = src;
	c->dst = dst;
#ifdef UTCP_DEBUG
	c->snd.iss = 0;
#else
	c->snd.iss = rand();
#endif
	c->snd.una = c->snd.iss;
	c->snd.nxt = c->snd.iss + 1;
	c->snd.last = c->snd.nxt;
	c->snd.cwnd = (utcp->mss > 2190 ? 2 : utcp->mss > 1095 ? 3 : 4) * utcp->mss;
	c->snd.ssthresh = ~0;
	debug_cwnd(c);
	c->srtt = 0;
	c->rttvar = 0;
	c->rto = START_RTO;
	c->utcp = utcp;

	// Add it to the sorted list of connections

	utcp->connections[utcp->nconnections++] = c;
	qsort(utcp->connections, utcp->nconnections, sizeof(*utcp->connections), compare);

	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return c;
}

static inline uint32_t absdiff(uint32_t a, uint32_t b) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(a > b) {
	debug(NULL, "%s.%d. a - b\n", __func__, __LINE__);
		return a - b;
	} else {
	debug(NULL, "%s.%d. b - a\n", __func__, __LINE__);
		return b - a;
	}
}

// Update RTT variables. See RFC 6298.
static void update_rtt(struct utcp_connection *c, uint32_t rtt) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(!rtt) {
		debug(c, "invalid rtt\n");
		return;
	}

	debug(NULL, "%s.%d. If c->srtt\n", __func__, __LINE__);
	if(!c->srtt) {
	debug(NULL, "%s.%d. Set c->srtt\n", __func__, __LINE__);
		c->srtt = rtt;
		c->rttvar = rtt / 2;
	} else {
	debug(NULL, "%s.%d. Calculate rttvar\n", __func__, __LINE__);
		c->rttvar = (c->rttvar * 3 + absdiff(c->srtt, rtt)) / 4;
		c->srtt = (c->srtt * 7 + rtt) / 8;
	}

	debug(NULL, "%s.%d. Calculate rto\n", __func__, __LINE__);
	c->rto = c->srtt + max(4 * c->rttvar, CLOCK_GRANULARITY);

	debug(NULL, "%s.%d. if rtor > MAX RTO\n", __func__, __LINE__);
	if(c->rto > MAX_RTO) {
	debug(NULL, "%s.%d. set rto to MAX RTO\n", __func__, __LINE__);
		c->rto = MAX_RTO;
	}

	debug(c, "rtt %u srtt %u rttvar %u rto %u\n", rtt, c->srtt, c->rttvar, c->rto);
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

static void start_retransmit_timer(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	clock_gettime(UTCP_CLOCK, &c->rtrx_timeout);

	uint32_t rto = c->rto;

	debug(NULL, "%s.%d. loop id rto > USEC_PER_SEC\n", __func__, __LINE__);
	while(rto > USEC_PER_SEC) {
	debug(NULL, "%s.%d. Increment rtrx timeout\n", __func__, __LINE__);
		c->rtrx_timeout.tv_sec++;
		rto -= USEC_PER_SEC;
	}

	debug(NULL, "%s.%d. Set rtrx_timeout in micro sec\n", __func__, __LINE__);
	c->rtrx_timeout.tv_nsec += rto * 1000;

	debug(NULL, "%s.%d. Set rtrx_timeout in micro sec > NSEC_PER_SEC\n", __func__, __LINE__);
	if(c->rtrx_timeout.tv_nsec >= NSEC_PER_SEC) {
		c->rtrx_timeout.tv_nsec -= NSEC_PER_SEC;
		c->rtrx_timeout.tv_sec++;
	}

	debug(c, "rtrx_timeout %ld.%06lu\n", c->rtrx_timeout.tv_sec, c->rtrx_timeout.tv_nsec);
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

static void stop_retransmit_timer(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	timespec_clear(&c->rtrx_timeout);
	debug(c, "rtrx_timeout cleared\n");
}

struct utcp_connection *utcp_connect_ex(struct utcp *utcp, uint16_t dst, utcp_recv_t recv, void *priv, uint32_t flags) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	struct utcp_connection *c = allocate_connection(utcp, 0, dst);

	if(!c) {
		return NULL;
	}

	assert((flags & ~0x1f) == 0);

	c->flags = flags;
	c->recv = recv;
	c->priv = priv;

	struct {
		struct hdr hdr;
		uint8_t init[4];
	} pkt;

	pkt.hdr.src = c->src;
	pkt.hdr.dst = c->dst;
	pkt.hdr.seq = c->snd.iss;
	pkt.hdr.ack = 0;
	pkt.hdr.wnd = c->rcvbuf.maxsize;
	pkt.hdr.ctl = SYN;
	pkt.hdr.aux = 0x0101;
	pkt.init[0] = 1;
	pkt.init[1] = 0;
	pkt.init[2] = 0;
	pkt.init[3] = flags & 0x7;

	set_state(c, SYN_SENT);

	print_packet(c, "send", &pkt, sizeof(pkt));
	utcp->send(utcp, &pkt, sizeof(pkt));

	clock_gettime(UTCP_CLOCK, &c->conn_timeout);
	c->conn_timeout.tv_sec += utcp->timeout;

	start_retransmit_timer(c);

	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return c;
}

struct utcp_connection *utcp_connect(struct utcp *utcp, uint16_t dst, utcp_recv_t recv, void *priv) {
	return utcp_connect_ex(utcp, dst, recv, priv, UTCP_TCP);
}

void utcp_accept(struct utcp_connection *c, utcp_recv_t recv, void *priv) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(c->reapable || c->state != SYN_RECEIVED) {
		debug(c, "accept() called on invalid connection in state %s\n", c, strstate[c->state]);
		return;
	}

	debug(c, "accepted %p %p\n", c, recv, priv);
	c->recv = recv;
	c->priv = priv;
	set_state(c, ESTABLISHED);
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

static void ack(struct utcp_connection *c, bool sendatleastone) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	int32_t left = seqdiff(c->snd.last, c->snd.nxt);
	debug(c, "%s.%d. Calculate cwd left size\n", __func__, __LINE__);
	int32_t cwndleft = is_reliable(c) ? min(c->snd.cwnd, c->snd.wnd) - seqdiff(c->snd.nxt, c->snd.una) : MAX_UNRELIABLE_SIZE;

	assert(left >= 0);

	debug(c, "%s.%d. If cwd left size <= 0\n", __func__, __LINE__);
	if(cwndleft <= 0) {
		left = 0;
	} else if(cwndleft < left) {
		left = cwndleft;

		if(!sendatleastone || cwndleft > c->utcp->mss) {
			left -= left % c->utcp->mss;
		}
	}

	debug(c, "cwndleft %d left %d\n", cwndleft, left);

	if(!left && !sendatleastone) {
	debug(NULL, "%s.%d. !left && !sendatleastone\n", __func__, __LINE__);
		return;
	}

	struct {
		struct hdr hdr;
		uint8_t data[];
	} *pkt = c->utcp->pkt;

	pkt->hdr.src = c->src;
	pkt->hdr.dst = c->dst;
	pkt->hdr.ack = c->rcv.nxt;
	pkt->hdr.wnd = is_reliable(c) ? c->rcvbuf.maxsize : 0;
	pkt->hdr.ctl = ACK;
	pkt->hdr.aux = 0;

	debug(c, "%s.%d. Send ACK in a loop\n", __func__, __LINE__);
	do {
		uint32_t seglen = left > c->utcp->mss ? c->utcp->mss : left;
		pkt->hdr.seq = c->snd.nxt;

	debug(c, "%s.%d. Buffer copy\n", __func__, __LINE__);
		buffer_copy(&c->sndbuf, pkt->data, seqdiff(c->snd.nxt, c->snd.una), seglen);

		c->snd.nxt += seglen;
		left -= seglen;

	debug(c, "%s.%d. Is reliable\n", __func__, __LINE__);
		if(!is_reliable(c)) {
			if(left) {
				pkt->hdr.ctl |= MF;
			} else {
				pkt->hdr.ctl &= ~MF;
			}
		}

	debug(c, "%s.%d. FIN wanted?\n", __func__, __LINE__);
		if(seglen && fin_wanted(c, c->snd.nxt)) {
			seglen--;
			pkt->hdr.ctl |= FIN;
		}

	debug(c, "%s.%d. Start RTT measurment\n", __func__, __LINE__);
		if(!c->rtt_start.tv_sec) {
			// Start RTT measurement
			clock_gettime(UTCP_CLOCK, &c->rtt_start);
			c->rtt_seq = pkt->hdr.seq + seglen;
			debug(c, "starting RTT measurement, expecting ack %u\n", c->rtt_seq);
		}

		print_packet(c, "send", pkt, sizeof(pkt->hdr) + seglen);
		c->utcp->send(c->utcp, pkt, sizeof(pkt->hdr) + seglen);

		if(left && !is_reliable(c)) {
			pkt->hdr.wnd += seglen;
		}
	debug(c, "%s.%d. Sent ACK\n", __func__, __LINE__);
	} while(left);
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
}

ssize_t utcp_send(struct utcp_connection *c, const void *data, size_t len) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(c->reapable) {
		debug(c, "send() called on closed connection\n");
		errno = EBADF;
		return -1;
	}

	debug(NULL, "%s.%d. c->state\n", __func__, __LINE__);
	switch(c->state) {
	case CLOSED:
	case LISTEN:
		debug(c, "send() called on unconnected connection\n");
		errno = ENOTCONN;
		return -1;

	case SYN_SENT:
	case SYN_RECEIVED:
	case ESTABLISHED:
	case CLOSE_WAIT:
		break;

	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		debug(c, "send() called on closed connection\n");
		errno = EPIPE;
		return -1;
	}

	// Exit early if we have nothing to send.

	debug(NULL, "%s.%d. If len = 0\n", __func__, __LINE__);
	if(!len) {
	debug(NULL, "%s.%d. Exit early if we have nothing to send.\n", __func__, __LINE__);
		return 0;
	}

	debug(NULL, "%s.%d. Data is NULL?\n", __func__, __LINE__);
	if(!data) {
		errno = EFAULT;
	debug(NULL, "%s.%d. Faulty packet\n", __func__, __LINE__);
		return -1;
	}

	// Check if we need to be able to buffer all data

	debug(NULL, "%s.%d. Check if we need to be able to buffer all data\n", __func__, __LINE__);
	if(c->flags & UTCP_NO_PARTIAL) {
	debug(NULL, "%s.%d. Free send buffer\n", __func__, __LINE__);
		if(len > buffer_free(&c->sndbuf)) {
			if(len > c->sndbuf.maxsize) {
				errno = EMSGSIZE;
				return -1;
			} else {
				errno = EWOULDBLOCK;
	debug(NULL, "%s.%d. Would block\n", __func__, __LINE__);
				return 0;
			}
		}
	}

	// Add data to send buffer.

	debug(NULL, "%s.%d. Add data to send buffer\n", __func__, __LINE__);
	if(is_reliable(c)) {
		len = buffer_put(&c->sndbuf, data, len);
	} else if(c->state != SYN_SENT && c->state != SYN_RECEIVED) {
		if(len > MAX_UNRELIABLE_SIZE || buffer_put(&c->sndbuf, data, len) != (ssize_t)len) {
			errno = EMSGSIZE;
	debug(NULL, "%s.%d. Packet too BIG!!\n", __func__, __LINE__);
			return -1;
		}
	} else {
	debug(NULL, "%s.%d. Is not reliable\n", __func__, __LINE__);
		return 0;
	}

	debug(NULL, "%s.%d. if len is -ve\n", __func__, __LINE__);
	if(len <= 0) {
		if(is_reliable(c)) {
	debug(NULL, "%s.%d. if reliable then error as would block\n", __func__, __LINE__);
			errno = EWOULDBLOCK;
			return 0;
		} else {
	debug(NULL, "%s.%d. Return len\n", __func__, __LINE__);
			return len;
		}
	}

	c->snd.last += len;

	// Don't send anything yet if the connection has not fully established yet

	debug(NULL, "%s.%d. Don't send anything yet if the connection has not fully established yet\n", __func__, __LINE__);
	if(c->state == SYN_SENT || c->state == SYN_RECEIVED) {
	debug(NULL, "%s.%d. SYN send and received\n", __func__, __LINE__);
		return len;
	}

	debug(NULL, "%s.%d. Send ACK\n", __func__, __LINE__);
	ack(c, false);

	debug(NULL, "%s.%d. Is not reliable hen discard and poll\n", __func__, __LINE__);
	if(!is_reliable(c)) {
		c->snd.una = c->snd.nxt = c->snd.last;
		buffer_discard(&c->sndbuf, c->sndbuf.used);
		c->do_poll = true;
	}

	debug(NULL, "%s.%d. Is reliable and rtxx set\n", __func__, __LINE__);
	if(is_reliable(c) && !timespec_isset(&c->rtrx_timeout)) {
		start_retransmit_timer(c);
	}

	debug(NULL, "%s.%d. Is reliable and connection set\n", __func__, __LINE__);
	if(is_reliable(c) && !timespec_isset(&c->conn_timeout)) {
		clock_gettime(UTCP_CLOCK, &c->conn_timeout);
		c->conn_timeout.tv_sec += c->utcp->timeout;
	}

	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return len;
}

static void swap_ports(struct hdr *hdr) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	uint16_t tmp = hdr->src;
	hdr->src = hdr->dst;
	hdr->dst = tmp;
}

static void fast_retransmit(struct utcp_connection *c) {
	if(c->state == CLOSED || c->snd.last == c->snd.una) {
		debug(c, "fast_retransmit() called but nothing to retransmit!\n");
		return;
	}

	struct utcp *utcp = c->utcp;

	struct {
		struct hdr hdr;
		uint8_t data[];
	} *pkt;

	pkt = malloc(c->utcp->mtu);

	if(!pkt) {
		return;
	}

	pkt->hdr.src = c->src;
	pkt->hdr.dst = c->dst;
	pkt->hdr.wnd = c->rcvbuf.maxsize;
	pkt->hdr.aux = 0;

	switch(c->state) {
	case ESTABLISHED:
	case FIN_WAIT_1:
	case CLOSE_WAIT:
	case CLOSING:
	case LAST_ACK:
		// Send unacked data again.
		pkt->hdr.seq = c->snd.una;
		pkt->hdr.ack = c->rcv.nxt;
		pkt->hdr.ctl = ACK;
		uint32_t len = min(seqdiff(c->snd.last, c->snd.una), utcp->mss);

		if(fin_wanted(c, c->snd.una + len)) {
			len--;
			pkt->hdr.ctl |= FIN;
		}

		buffer_copy(&c->sndbuf, pkt->data, 0, len);
		print_packet(c, "rtrx", pkt, sizeof(pkt->hdr) + len);
		utcp->send(utcp, pkt, sizeof(pkt->hdr) + len);
		break;

	default:
		break;
	}

	free(pkt);
}

static void retransmit(struct utcp_connection *c) {
	if(c->state == CLOSED || c->snd.last == c->snd.una) {
		debug(c, "retransmit() called but nothing to retransmit!\n");
		stop_retransmit_timer(c);
		return;
	}

	struct utcp *utcp = c->utcp;

	struct {
		struct hdr hdr;
		uint8_t data[];
	} *pkt = c->utcp->pkt;

	pkt->hdr.src = c->src;
	pkt->hdr.dst = c->dst;
	pkt->hdr.wnd = c->rcvbuf.maxsize;
	pkt->hdr.aux = 0;

	switch(c->state) {
	case SYN_SENT:
		// Send our SYN again
		pkt->hdr.seq = c->snd.iss;
		pkt->hdr.ack = 0;
		pkt->hdr.ctl = SYN;
		pkt->hdr.aux = 0x0101;
		pkt->data[0] = 1;
		pkt->data[1] = 0;
		pkt->data[2] = 0;
		pkt->data[3] = c->flags & 0x7;
		print_packet(c, "rtrx", pkt, sizeof(pkt->hdr) + 4);
		utcp->send(utcp, pkt, sizeof(pkt->hdr) + 4);
		break;

	case SYN_RECEIVED:
		// Send SYNACK again
		pkt->hdr.seq = c->snd.nxt;
		pkt->hdr.ack = c->rcv.nxt;
		pkt->hdr.ctl = SYN | ACK;
		print_packet(c, "rtrx", pkt, sizeof(pkt->hdr));
		utcp->send(utcp, pkt, sizeof(pkt->hdr));
		break;

	case ESTABLISHED:
	case FIN_WAIT_1:
	case CLOSE_WAIT:
	case CLOSING:
	case LAST_ACK:
		// Send unacked data again.
		pkt->hdr.seq = c->snd.una;
		pkt->hdr.ack = c->rcv.nxt;
		pkt->hdr.ctl = ACK;
		uint32_t len = min(seqdiff(c->snd.last, c->snd.una), utcp->mss);

		if(fin_wanted(c, c->snd.una + len)) {
			len--;
			pkt->hdr.ctl |= FIN;
		}

		// RFC 5681 slow start after timeout
		uint32_t flightsize = seqdiff(c->snd.nxt, c->snd.una);
		c->snd.ssthresh = max(flightsize / 2, utcp->mss * 2); // eq. 4
		c->snd.cwnd = utcp->mss;
		debug_cwnd(c);

		buffer_copy(&c->sndbuf, pkt->data, 0, len);
		print_packet(c, "rtrx", pkt, sizeof(pkt->hdr) + len);
		utcp->send(utcp, pkt, sizeof(pkt->hdr) + len);

		c->snd.nxt = c->snd.una + len;
		break;

	case CLOSED:
	case LISTEN:
	case TIME_WAIT:
	case FIN_WAIT_2:
		// We shouldn't need to retransmit anything in this state.
#ifdef UTCP_DEBUG
		abort();
#endif
		stop_retransmit_timer(c);
		goto cleanup;
	}

	start_retransmit_timer(c);
	c->rto *= 2;

	if(c->rto > MAX_RTO) {
		c->rto = MAX_RTO;
	}

	c->rtt_start.tv_sec = 0; // invalidate RTT timer
	c->dupack = 0; // cancel any ongoing fast recovery

cleanup:
	return;
}

/* Update receive buffer and SACK entries after consuming data.
 *
 * Situation:
 *
 * |.....0000..1111111111.....22222......3333|
 * |---------------^
 *
 * 0..3 represent the SACK entries. The ^ indicates up to which point we want
 * to remove data from the receive buffer. The idea is to substract "len"
 * from the offset of all the SACK entries, and then remove/cut down entries
 * that are shifted to before the start of the receive buffer.
 *
 * There are three cases:
 * - the SACK entry is after ^, in that case just change the offset.
 * - the SACK entry starts before and ends after ^, so we have to
 *   change both its offset and size.
 * - the SACK entry is completely before ^, in that case delete it.
 */
static void sack_consume(struct utcp_connection *c, size_t len) {
	debug(c, "sack_consume %lu\n", (unsigned long)len);

	if(len > c->rcvbuf.used) {
		debug(c, "all SACK entries consumed\n");
		c->sacks[0].len = 0;
		return;
	}

	buffer_discard(&c->rcvbuf, len);

	for(int i = 0; i < NSACKS && c->sacks[i].len;) {
		if(len < c->sacks[i].offset) {
			c->sacks[i].offset -= len;
			i++;
		} else if(len < c->sacks[i].offset + c->sacks[i].len) {
			c->sacks[i].len -= len - c->sacks[i].offset;
			c->sacks[i].offset = 0;
			i++;
		} else {
			if(i < NSACKS - 1) {
				memmove(&c->sacks[i], &c->sacks[i + 1], (NSACKS - 1 - i) * sizeof(c->sacks)[i]);
				c->sacks[NSACKS - 1].len = 0;
			} else {
				c->sacks[i].len = 0;
				break;
			}
		}
	}

	for(int i = 0; i < NSACKS && c->sacks[i].len; i++) {
		debug(c, "SACK[%d] offset %u len %u\n", i, c->sacks[i].offset, c->sacks[i].len);
	}
}

static void handle_out_of_order(struct utcp_connection *c, uint32_t offset, const void *data, size_t len) {
	debug(c, "out of order packet, offset %u\n", offset);
	// Packet loss or reordering occured. Store the data in the buffer.
	ssize_t rxd = buffer_put_at(&c->rcvbuf, offset, data, len);

	if(rxd < 0 || (size_t)rxd < len) {
		abort();
	}

	// Make note of where we put it.
	for(int i = 0; i < NSACKS; i++) {
		if(!c->sacks[i].len) { // nothing to merge, add new entry
			debug(c, "new SACK entry %d\n", i);
			c->sacks[i].offset = offset;
			c->sacks[i].len = rxd;
			break;
		} else if(offset < c->sacks[i].offset) {
			if(offset + rxd < c->sacks[i].offset) { // insert before
				if(!c->sacks[NSACKS - 1].len) { // only if room left
					debug(c, "insert SACK entry at %d\n", i);
					memmove(&c->sacks[i + 1], &c->sacks[i], (NSACKS - i - 1) * sizeof(c->sacks)[i]);
					c->sacks[i].offset = offset;
					c->sacks[i].len = rxd;
				} else {
					debug(c, "SACK entries full, dropping packet\n");
				}

				break;
			} else { // merge
				debug(c, "merge with start of SACK entry at %d\n", i);
				c->sacks[i].offset = offset;
				break;
			}
		} else if(offset <= c->sacks[i].offset + c->sacks[i].len) {
			if(offset + rxd > c->sacks[i].offset + c->sacks[i].len) { // merge
				debug(c, "merge with end of SACK entry at %d\n", i);
				c->sacks[i].len = offset + rxd - c->sacks[i].offset;
				// TODO: handle potential merge with next entry
			}

			break;
		}
	}

	for(int i = 0; i < NSACKS && c->sacks[i].len; i++) {
		debug(c, "SACK[%d] offset %u len %u\n", i, c->sacks[i].offset, c->sacks[i].len);
	}
}

static void handle_in_order(struct utcp_connection *c, const void *data, size_t len) {
	if(c->recv) {
		ssize_t rxd = c->recv(c, data, len);

		if(rxd != (ssize_t)len) {
			// TODO: handle the application not accepting all data.
			abort();
		}
	}

	// Check if we can process out-of-order data now.
	if(c->sacks[0].len && len >= c->sacks[0].offset) {
		debug(c, "incoming packet len %lu connected with SACK at %u\n", (unsigned long)len, c->sacks[0].offset);

		if(len < c->sacks[0].offset + c->sacks[0].len) {
			size_t offset = len;
			len = c->sacks[0].offset + c->sacks[0].len;
			size_t remainder = len - offset;
			ssize_t rxd = buffer_call(&c->rcvbuf, c->recv, c, offset, remainder);

			if(rxd != (ssize_t)remainder) {
				// TODO: handle the application not accepting all data.
				abort();
			}
		}
	}

	if(c->rcvbuf.used) {
		sack_consume(c, len);
	}

	c->rcv.nxt += len;
}

static void handle_unreliable(struct utcp_connection *c, const struct hdr *hdr, const void *data, size_t len) {
	debug(c, "%s.%d. Fast path for unfragmented packets\n", __func__, __LINE__);
	// Fast path for unfragmented packets
	if(!hdr->wnd && !(hdr->ctl & MF)) {
	debug(c, "%s.%d. Invoke receive callback\n", __func__, __LINE__);
		c->recv(c, data, len);
		c->rcv.nxt = hdr->seq + len;
	debug(c, "%s.%d. Update receive next\n", __func__, __LINE__);
		return;
	}

	// Ensure reassembled packet are not larger than 64 kiB
	debug(c, "%s.%d. Ensure reassembled packet are not larger than 64 kiB\n", __func__, __LINE__);
	if(hdr->wnd >= MAX_UNRELIABLE_SIZE || hdr->wnd + len > MAX_UNRELIABLE_SIZE) {
	debug(c, "%s.%d. header wnd is > MAX SIZE\n", __func__, __LINE__);
		return;
	}

	// Don't accept out of order fragments
	debug(c, "%s.%d. Don't accept out of order fragments\n", __func__, __LINE__);
	if(hdr->wnd && hdr->seq != c->rcv.nxt) {
	debug(c, "%s.%d. header seq != recv next\n", __func__, __LINE__);
		return;
	}

	// Reset the receive buffer for the first fragment
	debug(c, "%s.%d. Reset the receive buffer for the first fragment\n", __func__, __LINE__);
	if(!hdr->wnd) {
		buffer_clear(&c->rcvbuf);
	}

	debug(c, "%s.%d. Buffer put at\n", __func__, __LINE__);
	ssize_t rxd = buffer_put_at(&c->rcvbuf, hdr->wnd, data, len);

	if(rxd != (ssize_t)len) {
	debug(c, "%s.%d. Rxd != len\n", __func__, __LINE__);
		return;
	}

	// Send the packet if it's the final fragment
	debug(c, "%s.%d. Send the packet if it's the final fragment\n", __func__, __LINE__);
	if(!(hdr->ctl & MF)) {
		buffer_call(&c->rcvbuf, c->recv, c, 0, hdr->wnd + len);
	}

	debug(c, "%s.%d. Update recv next\n", __func__, __LINE__);
	c->rcv.nxt = hdr->seq + len;
	debug(c, "%s.%d. Done\n", __func__, __LINE__);
}

static void handle_incoming_data(struct utcp_connection *c, const struct hdr *hdr, const void *data, size_t len) {
	debug(c, "%s.%d. Started\n", __func__, __LINE__);
	if(!is_reliable(c)) {
	debug(c, "%s.%d. Handle unreliable data\n", __func__, __LINE__);
		handle_unreliable(c, hdr, data, len);
	debug(c, "%s.%d. Handled unreliable data\n", __func__, __LINE__);
		return;
	}

	uint32_t offset = seqdiff(hdr->seq, c->rcv.nxt);

	debug(c, "%s.%d. offset len > max rcv buf size?\n", __func__, __LINE__);
	if(offset + len > c->rcvbuf.maxsize) {
		abort();
	}

	debug(c, "%s.%d. Handle the offset, in or out of order\n", __func__, __LINE__);
	if(offset) {
		handle_out_of_order(c, offset, data, len);
	} else {
		handle_in_order(c, data, len);
	}
	debug(c, "%s.%d. Done\n", __func__, __LINE__);
}


ssize_t utcp_recv(struct utcp *utcp, const void *data, size_t len) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	const uint8_t *ptr = data;

	if(!utcp) {
		errno = EFAULT;
		return -1;
	}

	if(!len) {
		return 0;
	}

	if(!data) {
		errno = EFAULT;
		return -1;
	}

	// Drop packets smaller than the header

	struct hdr hdr;

	if(len < sizeof(hdr)) {
		print_packet(NULL, "recv", data, len);
		errno = EBADMSG;
		return -1;
	}

	// Make a copy from the potentially unaligned data to a struct hdr

	memcpy(&hdr, ptr, sizeof(hdr));

	// Try to match the packet to an existing connection

	struct utcp_connection *c = find_connection(utcp, hdr.dst, hdr.src);
	print_packet(c, "recv", data, len);

	// Process the header

	ptr += sizeof(hdr);
	len -= sizeof(hdr);

	// Drop packets with an unknown CTL flag

	debug(NULL, "%s.%d. Drop packets with an unknown CTL flag\n", __func__, __LINE__);
	if(hdr.ctl & ~(SYN | ACK | RST | FIN | MF)) {
		print_packet(NULL, "recv", data, len);
		errno = EBADMSG;
	debug(NULL, "%s.%d. Bad msg\n", __func__, __LINE__);
		return -1;
	}

	// Check for auxiliary headers
	debug(NULL, "%s.%d. Check for auxiliary headers\n", __func__, __LINE__);

	const uint8_t *init = NULL;

	uint16_t aux = hdr.aux;

	while(aux) {
		size_t auxlen = 4 * (aux >> 8) & 0xf;
		uint8_t auxtype = aux & 0xff;

		if(len < auxlen) {
			errno = EBADMSG;
	debug(NULL, "%s.%d. EBADMSG\n", __func__, __LINE__);
			return -1;
		}

	debug(NULL, "%s.%d. Switch aux type\n", __func__, __LINE__);
		switch(auxtype) {
		case AUX_INIT:
			if(!(hdr.ctl & SYN) || auxlen != 4) {
				errno = EBADMSG;
	debug(NULL, "%s.%d. BAD MSG\n", __func__, __LINE__);
				return -1;
			}

			init = ptr;
			break;

		default:
			errno = EBADMSG;
	debug(NULL, "%s.%d. BAD MSG\n", __func__, __LINE__);
			return -1;
		}

		len -= auxlen;
		ptr += auxlen;

		if(!(aux & 0x800)) {
			break;
		}

		if(len < 2) {
			errno = EBADMSG;
	debug(NULL, "%s.%d. BAD MSG\n", __func__, __LINE__);
			return -1;
		}

		memcpy(&aux, ptr, 2);
		len -= 2;
		ptr += 2;
	}

	bool has_data = len || (hdr.ctl & (SYN | FIN));

	// Is it for a new connection?

	debug(NULL, "%s.%d. Is it for a new connection?\n", __func__, __LINE__);
	if(!c) {
		// Ignore RST packets

	debug(NULL, "%s.%d. Ignore RST packets\n", __func__, __LINE__);
		if(hdr.ctl & RST) {
	debug(NULL, "%s.%d. Ignored RST packets\n", __func__, __LINE__);
			return 0;
		}

		// Is it a SYN packet and are we LISTENing?

	debug(NULL, "%s.%d. Is it a SYN packet and are we LISTENing?\n", __func__, __LINE__);
		if(hdr.ctl & SYN && !(hdr.ctl & ACK) && utcp->accept) {
			// If we don't want to accept it, send a RST back
	debug(NULL, "%s.%d. If we don't want to accept it, send a RST back\n", __func__, __LINE__);
			if((utcp->pre_accept && !utcp->pre_accept(utcp, hdr.dst))) {
				len = 1;
	debug(NULL, "%s.%d. reset\n", __func__, __LINE__);
				goto reset;
			}

			// Try to allocate memory, otherwise send a RST back
			c = allocate_connection(utcp, hdr.dst, hdr.src);
	debug(NULL, "%s.%d. allocated memory, otherwise sent a RST back\n", __func__, __LINE__);

			if(!c) {
				len = 1;
	debug(NULL, "%s.%d. reset\n", __func__, __LINE__);
				goto reset;
			}

			// Parse auxilliary information
	debug(NULL, "%s.%d. Parse auxilliary information\n", __func__, __LINE__);
			if(init) {
				if(init[0] < 1) {
					len = 1;
	debug(NULL, "%s.%d. reset\n", __func__, __LINE__);
					goto reset;
				}

				c->flags = init[3] & 0x7;
			} else {
				c->flags = UTCP_TCP;
			}

synack:
			// Return SYN+ACK, go to SYN_RECEIVED state
	debug(c, "%s.%d. Return SYN+ACK, go to SYN_RECEIVED state\n", __func__, __LINE__);
			c->snd.wnd = hdr.wnd;
			c->rcv.irs = hdr.seq;
			c->rcv.nxt = c->rcv.irs + 1;
			set_state(c, SYN_RECEIVED);

			struct {
				struct hdr hdr;
				uint8_t data[4];
			} pkt;

			pkt.hdr.src = c->src;
			pkt.hdr.dst = c->dst;
			pkt.hdr.ack = c->rcv.irs + 1;
			pkt.hdr.seq = c->snd.iss;
			pkt.hdr.wnd = c->rcvbuf.maxsize;
			pkt.hdr.ctl = SYN | ACK;

	debug(c, "%s.%d. Send SYN ACK\n", __func__, __LINE__);
			if(init) {
				pkt.hdr.aux = 0x0101;
				pkt.data[0] = 1;
				pkt.data[1] = 0;
				pkt.data[2] = 0;
				pkt.data[3] = c->flags & 0x7;
				print_packet(c, "send", &pkt, sizeof(hdr) + 4);
				utcp->send(utcp, &pkt, sizeof(hdr) + 4);
			} else {
				pkt.hdr.aux = 0;
				print_packet(c, "send", &pkt, sizeof(hdr));
				utcp->send(utcp, &pkt, sizeof(hdr));
			}
		} else {
			// No, we don't want your packets, send a RST back
	debug(c, "%s.%d. No, we don't want your packets, send a RST back\n", __func__, __LINE__);
			len = 1;
			goto reset;
		}

	debug(c, "%s.%d. Synack done\n", __func__, __LINE__);
		return 0;
	}

	debug(c, "state %s\n", strstate[c->state]);

	// In case this is for a CLOSED connection, ignore the packet.
	// TODO: make it so incoming packets can never match a CLOSED connection.

	if(c->state == CLOSED) {
		debug(c, "got packet for closed connection\n");
		return 0;
	}

	// It is for an existing connection.

	// 1. Drop invalid packets.

	// 1a. Drop packets that should not happen in our current state.
	debug(NULL, "%s.%d. Drop packets that should not happen in our current state.\n", __func__, __LINE__);

	switch(c->state) {
	case SYN_SENT:
	case SYN_RECEIVED:
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSE_WAIT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		break;

	default:
#ifdef UTCP_DEBUG
		abort();
#endif
		break;
	}

	// 1b. Discard data that is not in our receive window.

	debug(NULL, "%s.%d. Discard data that is not in our receive window.\n", __func__, __LINE__);
	if(is_reliable(c)) {
		bool acceptable;

		if(c->state == SYN_SENT) {
			acceptable = true;
		} else if(len == 0) {
			acceptable = seqdiff(hdr.seq, c->rcv.nxt) >= 0;
		} else {
			int32_t rcv_offset = seqdiff(hdr.seq, c->rcv.nxt);

			// cut already accepted front overlapping
			if(rcv_offset < 0) {
				acceptable = len > (size_t) - rcv_offset;

				if(acceptable) {
					ptr -= rcv_offset;
					len += rcv_offset;
					hdr.seq -= rcv_offset;
				}
			} else {
				acceptable = seqdiff(hdr.seq, c->rcv.nxt) >= 0 && seqdiff(hdr.seq, c->rcv.nxt) + len <= c->rcvbuf.maxsize;
			}
		}

		if(!acceptable) {
			debug(c, "packet not acceptable, %u <= %u + %lu < %u\n", c->rcv.nxt, hdr.seq, (unsigned long)len, c->rcv.nxt + c->rcvbuf.maxsize);

			// Ignore unacceptable RST packets.
			if(hdr.ctl & RST) {
				return 0;
			}

			// Otherwise, continue processing.
			len = 0;
		}
	} else {
#if UTCP_DEBUG
		int32_t rcv_offset = seqdiff(hdr.seq, c->rcv.nxt);

		if(rcv_offset) {
			debug(c, "packet out of order, offset %u bytes", rcv_offset);
		}

#endif
	}

	c->snd.wnd = hdr.wnd; // TODO: move below

	// 1c. Drop packets with an invalid ACK.
	// ackno should not roll back, and it should also not be bigger than what we ever could have sent
	// (= snd.una + c->sndbuf.used).
	debug(NULL, "%s.%d.  Drop packets with an invalid ACK\n", __func__, __LINE__);

	if(!is_reliable(c)) {
		if(hdr.ack != c->snd.last && c->state >= ESTABLISHED) {
			hdr.ack = c->snd.una;
		}
	}

	if(hdr.ctl & ACK && (seqdiff(hdr.ack, c->snd.last) > 0 || seqdiff(hdr.ack, c->snd.una) < 0)) {
		debug(c, "packet ack seqno out of range, %u <= %u < %u\n", c->snd.una, hdr.ack, c->snd.una + c->sndbuf.used);

		// Ignore unacceptable RST packets.
	debug(NULL, "%s.%d.  Ignore unacceptable RST packets.\n", __func__, __LINE__);
		if(hdr.ctl & RST) {
			return 0;
		}

	debug(NULL, "%s.%d.  goto reset\n", __func__, __LINE__);
		goto reset;
	}

	// 2. Handle RST packets

	debug(NULL, "%s.%d.  Handle RST packets\n", __func__, __LINE__);
	if(hdr.ctl & RST) {
		switch(c->state) {
		case SYN_SENT:
			if(!(hdr.ctl & ACK)) {
				return 0;
			}

			// The peer has refused our connection.
			set_state(c, CLOSED);
			errno = ECONNREFUSED;

			if(c->recv) {
				c->recv(c, NULL, 0);
			}

			if(c->poll && !c->reapable) {
				c->poll(c, 0);
			}

			return 0;

		case SYN_RECEIVED:
			if(hdr.ctl & ACK) {
				return 0;
			}

			// We haven't told the application about this connection yet. Silently delete.
			free_connection(c);
			return 0;

		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSE_WAIT:
			if(hdr.ctl & ACK) {
				return 0;
			}

			// The peer has aborted our connection.
			set_state(c, CLOSED);
			errno = ECONNRESET;

			if(c->recv) {
				c->recv(c, NULL, 0);
			}

			if(c->poll && !c->reapable) {
				c->poll(c, 0);
			}

			return 0;

		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			if(hdr.ctl & ACK) {
				return 0;
			}

			// As far as the application is concerned, the connection has already been closed.
			// If it has called utcp_close() already, we can immediately free this connection.
			if(c->reapable) {
				free_connection(c);
				return 0;
			}

			// Otherwise, immediately move to the CLOSED state.
			set_state(c, CLOSED);
			return 0;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			break;
		}
	}

	uint32_t advanced;

	debug(c, "%s.%d. if header is ACK\n", __func__, __LINE__);
	if(!(hdr.ctl & ACK)) {
		advanced = 0;
	debug(c, "%s.%d. goto skip_ack\n", __func__, __LINE__);
		goto skip_ack;
	}

	// 3. Advance snd.una

	debug(c, "%s.%d. After snd.una\n", __func__, __LINE__);
	advanced = seqdiff(hdr.ack, c->snd.una);
	debug(c, "%s.%d. If advanced\n", __func__, __LINE__);

	if(advanced) {
	debug(c, "%s.%d. Advanced, RTT measurement\n", __func__, __LINE__);
		// RTT measurement
		if(c->rtt_start.tv_sec) {
	debug(c, "%s.%d. If RTT start\n", __func__, __LINE__);
			if(c->rtt_seq == hdr.ack) {
				struct timespec now;
	debug(c, "%s.%d. Calling clock_gettime\n", __func__, __LINE__);
				clock_gettime(UTCP_CLOCK, &now);
	debug(c, "%s.%d. Calling timespec_diff_usec\n", __func__, __LINE__);
				int32_t diff = timespec_diff_usec(&now, &c->rtt_start);
	debug(c, "%s.%d. Returned from timespec_diff_usec\n", __func__, __LINE__);
				update_rtt(c, diff);
				c->rtt_start.tv_sec = 0;
			} else if(c->rtt_seq < hdr.ack) {
				debug(c, "cancelling RTT measurement: %u < %u\n", c->rtt_seq, hdr.ack);
				c->rtt_start.tv_sec = 0;
				debug(c, "%s.%d. c->rtt_start.tv_sec reset\n", __func__, __LINE__);
			}
	debug(c, "%s.%d. out of rtt measurement\n", __func__, __LINE__);
		}
	debug(c, "%s.%d. out advanced condition\n", __func__, __LINE__);

		int32_t data_acked = advanced;

		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
	debug(c, "%s.%d. SYN_RECEIVED\n", __func__, __LINE__);
			data_acked--;
	debug(c, "%s.%d. SYN_RECEIVED, data_acked--\n", __func__, __LINE__);
			break;

		// TODO: handle FIN as well.
		default:
			break;
		}

	debug(c, "%s.%d. data_acked is -ve?\n", __func__, __LINE__);
		assert(data_acked >= 0);

#ifndef NDEBUG
		int32_t bufused = seqdiff(c->snd.last, c->snd.una);
		assert(data_acked <= bufused);
#endif

	debug(c, "%s.%d. if data_acked\n", __func__, __LINE__);
		if(data_acked) {
	debug(c, "%s.%d. discard send buffer, data acked\n", __func__, __LINE__);
			buffer_discard(&c->sndbuf, data_acked);
	debug(c, "%s.%d. buffer discarded\n", __func__, __LINE__);
			c->do_poll = true;
	debug(c, "%s.%d. do poll the connection\n", __func__, __LINE__);
		}

		// Also advance snd.nxt if possible
	debug(c, "%s.%d. Also advance snd.nxt if possible\n", __func__, __LINE__);
		if(seqdiff(c->snd.nxt, hdr.ack) < 0) {
	debug(c, "%s.%d. send next with ack header\n", __func__, __LINE__);
			c->snd.nxt = hdr.ack;
	debug(c, "%s.%d. send next with ack header is set to the connection\n", __func__, __LINE__);
		}

	debug(c, "%s.%d. send next with ack header\n", __func__, __LINE__);
		c->snd.una = hdr.ack;

	debug(c, "%s.%d. if dup ack?\n", __func__, __LINE__);
		if(c->dupack) {
	debug(c, "%s.%d. if dup ack is >= 3?\n", __func__, __LINE__);
			if(c->dupack >= 3) {
				debug(c, "fast recovery ended\n");
				c->snd.cwnd = c->snd.ssthresh;
	debug(c, "%s.%d. set send cwnd to ssthreshold\n", __func__, __LINE__);
			}

	debug(c, "%s.%d. reset duplicate ack\n", __func__, __LINE__);
			c->dupack = 0;
		}

	debug(c, "%s.%d. Increase the congestion window according to RFC 5681\n", __func__, __LINE__);
		// Increase the congestion window according to RFC 5681
		if(c->snd.cwnd < c->snd.ssthresh) {
	debug(c, "%s.%d. Execute eq 2\n", __func__, __LINE__);
			c->snd.cwnd += min(advanced, utcp->mss); // eq. 2
	debug(c, "%s.%d. Executed eq 2\n", __func__, __LINE__);
		} else {
	debug(c, "%s.%d. Execute eq 3\n", __func__, __LINE__);
			c->snd.cwnd += max(1, (utcp->mss * utcp->mss) / c->snd.cwnd); // eq. 3
	debug(c, "%s.%d. Executed eq 3\n", __func__, __LINE__);
		}
	debug(c, "%s.%d. Increased the congestion window according to RFC 5681\n", __func__, __LINE__);

		if(c->snd.cwnd > c->sndbuf.maxsize) {
	debug(c, "%s.%d. Set send cwnd to max size\n", __func__, __LINE__);
			c->snd.cwnd = c->sndbuf.maxsize;
		}
	debug(c, "%s.%d. Print cwnd\n", __func__, __LINE__);

		debug_cwnd(c);

		// Check if we have sent a FIN that is now ACKed.
	debug(c, "%s.%d. Check if we have sent a FIN that is now ACKed\n", __func__, __LINE__);
		switch(c->state) {
		case FIN_WAIT_1:
	debug(c, "%s.%d. If connetion state is FIN_WAIT_1\n", __func__, __LINE__);
			if(c->snd.una == c->snd.last) {
	debug(c, "%s.%d. Set connection state to FIN_WAIT_2\n", __func__, __LINE__);
				set_state(c, FIN_WAIT_2);
			}
	debug(c, "%s.%d. Case FIN_WAIT_1 break\n", __func__, __LINE__);

			break;

		case CLOSING:
	debug(c, "%s.%d. If connetion state is CLOSING\n", __func__, __LINE__);
			if(c->snd.una == c->snd.last) {
	debug(c, "%s.%d. clock_gettime\n", __func__, __LINE__);
				clock_gettime(UTCP_CLOCK, &c->conn_timeout);
	debug(c, "%s.%d. Update connection timeout\n", __func__, __LINE__);
				c->conn_timeout.tv_sec += utcp->timeout;
	debug(c, "%s.%d. Set connection state to TIME_WAIT\n", __func__, __LINE__);
				set_state(c, TIME_WAIT);
			}
	debug(c, "%s.%d. Case CLOSING break\n", __func__, __LINE__);

			break;

		default:
			break;
		}
	debug(c, "%s.%d. Validated if we have sent a FIN that is now ACKed\n", __func__, __LINE__);
	} else {
	debug(c, "%s.%d. If not advanced\n", __func__, __LINE__);
		if(!len && is_reliable(c) && c->snd.una != c->snd.last) {
	debug(c, "%s.%d. dupack++\n", __func__, __LINE__);
			c->dupack++;
			debug(c, "duplicate ACK %d\n", c->dupack);

			if(c->dupack == 3) {
				// RFC 5681 fast recovery
				debug(c, "fast recovery started\n", c->dupack);
				uint32_t flightsize = seqdiff(c->snd.nxt, c->snd.una);
	debug(c, "%s.%d. Calculated flight size\n", __func__, __LINE__);
				c->snd.ssthresh = max(flightsize / 2, utcp->mss * 2); // eq. 4
	debug(c, "%s.%d. Calculated eq. 4\n", __func__, __LINE__);
				c->snd.cwnd = min(c->snd.ssthresh + 3 * utcp->mss, c->sndbuf.maxsize);

	debug(c, "%s.%d. If send cwnd is > send maxsize\n", __func__, __LINE__);
				if(c->snd.cwnd > c->sndbuf.maxsize) {
	debug(c, "%s.%d. Set send cwnd = send maxsize\n", __func__, __LINE__);
					c->snd.cwnd = c->sndbuf.maxsize;
				}

	debug(c, "%s.%d. Debug cwnd\n", __func__, __LINE__);
				debug_cwnd(c);

	debug(c, "%s.%d. Call fast transmit for the connection\n", __func__, __LINE__);
				fast_retransmit(c);
	debug(c, "%s.%d. Called fast transmit for the connection\n", __func__, __LINE__);
			} else if(c->dupack > 3) {
	debug(c, "%s.%d. Increase send cwnd by one MSS\n", __func__, __LINE__);
				c->snd.cwnd += utcp->mss;

	debug(c, "%s.%d. If send cwnd is > send maxsize\n", __func__, __LINE__);
				if(c->snd.cwnd > c->sndbuf.maxsize) {
	debug(c, "%s.%d. Set send cwnd = send maxsize\n", __func__, __LINE__);
					c->snd.cwnd = c->sndbuf.maxsize;
				}

	debug(c, "%s.%d. Debug cwnd\n", __func__, __LINE__);
				debug_cwnd(c);
			}

			// We got an ACK which indicates the other side did get one of our packets.
			// Reset the retransmission timer to avoid going to slow start,
			// but don't touch the connection timeout.
	debug(c, "%s.%d. Start retransmit timer\n", __func__, __LINE__);
			start_retransmit_timer(c);
	debug(c, "%s.%d. Start retransmit timer returned\n", __func__, __LINE__);
		}
	debug(c, "%s.%d. Else advanced end\n", __func__, __LINE__);
	}

	// 4. Update timers

	debug(c, "%s.%d. Update timers\n", __func__, __LINE__);
	if(advanced) {
	debug(c, "%s.%d. If advanced\n", __func__, __LINE__);
		if(c->snd.una == c->snd.last) {
	debug(c, "%s.%d. Stop retransmit timer\n", __func__, __LINE__);
			stop_retransmit_timer(c);
	debug(c, "%s.%d. Clear connection timeout\n", __func__, __LINE__);
			timespec_clear(&c->conn_timeout);
	debug(c, "%s.%d. Cleared connection timeout\n", __func__, __LINE__);
		} else if(is_reliable(c)) {
	debug(c, "%s.%d. Else if connection is reliable\n", __func__, __LINE__);
			start_retransmit_timer(c);
	debug(c, "%s.%d. Started retransmit timer\n", __func__, __LINE__);
			clock_gettime(UTCP_CLOCK, &c->conn_timeout);
	debug(c, "%s.%d. Increase connection timeout by utcp timeout\n", __func__, __LINE__);
			c->conn_timeout.tv_sec += utcp->timeout;
	debug(c, "%s.%d. Increased connection timeout by utcp timeout\n", __func__, __LINE__);
		}
	}
	debug(c, "%s.%d. Updated timers\n", __func__, __LINE__);

skip_ack:
	// 5. Process SYN stuff

	debug(c, "%s.%d. Process SYN stuff\n", __func__, __LINE__);
	if(hdr.ctl & SYN) {
		switch(c->state) {
		case SYN_SENT:

			// This is a SYNACK. It should always have ACKed the SYN.
	debug(c, "%s.%d. This is a SYNACK. It should always have ACKed the SYN.\n", __func__, __LINE__);
			if(!advanced) {
				goto reset;
			}

			c->rcv.irs = hdr.seq;
			c->rcv.nxt = hdr.seq;

			if(c->shut_wr) {
				c->snd.last++;
				set_state(c, FIN_WAIT_1);
			} else {
				set_state(c, ESTABLISHED);
			}
	debug(c, "%s.%d. Setting the state is done\n", __func__, __LINE__);

			// TODO: notify application of this somehow.
			break;

		case SYN_RECEIVED:
			// This is a retransmit of a SYN, send back the SYNACK.
	debug(c, "%s.%d. This is a retransmit of a SYN, send back the SYNACK.\n", __func__, __LINE__);
			goto synack;

		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// Ehm, no. We should never receive a second SYN.
	debug(c, "%s.%d. Ehm, no. We should never receive a second SYN.\n", __func__, __LINE__);
			return 0;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;
		}

		// SYN counts as one sequence number
	debug(c, "%s.%d. SYN counts as one sequence number\n", __func__, __LINE__);
		c->rcv.nxt++;
	}

	// 6. Process new data

	debug(c, "%s.%d. Process new data\n", __func__, __LINE__);
	if(c->state == SYN_RECEIVED) {
		// This is the ACK after the SYNACK. It should always have ACKed the SYNACK.
	debug(c, "%s.%d. This is the ACK after the SYNACK. It should always have ACKed the SYNACK.\n", __func__, __LINE__);
		if(!advanced) {
	debug(c, "%s.%d. If not advaced reset\n", __func__, __LINE__);
			goto reset;
		}

		// Are we still LISTENing?
	debug(c, "%s.%d. Are we still LISTENing?\n", __func__, __LINE__);
		if(utcp->accept) {
	debug(c, "%s.%d. Invoke accept cb\n", __func__, __LINE__);
			utcp->accept(c, c->src);
		}

	debug(c, "%s.%d. If not established then close\n", __func__, __LINE__);
		if(c->state != ESTABLISHED) {
			set_state(c, CLOSED);
			c->reapable = true;
	debug(c, "%s.%d. reap and reaset after close\n", __func__, __LINE__);
			goto reset;
		}
	}

	debug(c, "%s.%d. if len != 0\n", __func__, __LINE__);
	if(len) {
		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
			// This should never happen.
	debug(c, "%s.%d. This should never happe\n", __func__, __LINE__);
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;

		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
	debug(c, "%s.%d. estd, finwait1,2\n", __func__, __LINE__);
			break;

		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// Ehm no, We should never receive more data after a FIN.
	debug(c, "%s.%d. Ehm no, We should never receive more data after a FIN, reset\n", __func__, __LINE__);
			goto reset;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;
		}

	debug(c, "%s.%d. Handle inoming data\n", __func__, __LINE__);
		handle_incoming_data(c, &hdr, ptr, len);
	}

	// 7. Process FIN stuff

	debug(c, "%s.%d. Process FIN stuff\n", __func__, __LINE__);
	if((hdr.ctl & FIN) && (!is_reliable(c) || hdr.seq + len == c->rcv.nxt)) {
	debug(c, "%s.%d. Swith state\n", __func__, __LINE__);
		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
			// This should never happen.
	debug(c, "%s.%d. This should never happe\n", __func__, __LINE__);
#ifdef UTCP_DEBUG
			abort();
#endif
			break;

		case ESTABLISHED:
	debug(c, "%s.%d. Ested, set state to close wait\n", __func__, __LINE__);
			set_state(c, CLOSE_WAIT);
			break;

		case FIN_WAIT_1:
	debug(c, "%s.%d. set state to closing\n", __func__, __LINE__);
			set_state(c, CLOSING);
			break;

		case FIN_WAIT_2:
	debug(c, "%s.%d. Get clock time\n", __func__, __LINE__);
			clock_gettime(UTCP_CLOCK, &c->conn_timeout);
			c->conn_timeout.tv_sec += utcp->timeout;
			set_state(c, TIME_WAIT);
	debug(c, "%s.%d. Set state to TIME WAIT\n", __func__, __LINE__);
			break;

		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
	debug(c, "%s.%d. CLOSE_WAIT, CLOSE_WAIT, LAST_ACK and TIME_WAIT go reset\n", __func__, __LINE__);
			// Ehm, no. We should never receive a second FIN.
			goto reset;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			break;
		}

		// FIN counts as one sequence number
	debug(c, "%s.%d. FIN counts as one sequence number\n", __func__, __LINE__);
		c->rcv.nxt++;
		len++;

		// Inform the application that the peer closed its end of the connection.
	debug(c, "%s.%d. Inform the application that the peer closed its end of the connection\n", __func__, __LINE__);
		if(c->recv) {
			errno = 0;
			c->recv(c, NULL, 0);
		}
	}

	// Now we send something back if:
	// - we received data, so we have to send back an ACK
	//   -> sendatleastone = true
	// - or we got an ack, so we should maybe send a bit more data
	//   -> sendatleastone = false

	debug(c, "%s.%d. send seomething back if possible\n", __func__, __LINE__);
	if(is_reliable(c) || hdr.ctl & SYN || hdr.ctl & FIN) {
		ack(c, has_data);
	}

	debug(c, "%s.%d. Done\n", __func__, __LINE__);
	return 0;

reset:
	debug(c, "%s.%d. Start reset\n", __func__, __LINE__);
	swap_ports(&hdr);
	hdr.wnd = 0;
	hdr.aux = 0;

	if(hdr.ctl & ACK) {
		hdr.seq = hdr.ack;
		hdr.ctl = RST;
	} else {
		hdr.ack = hdr.seq + len;
		hdr.seq = 0;
		hdr.ctl = RST | ACK;
	}

	print_packet(c, "send", &hdr, sizeof(hdr));
	utcp->send(utcp, &hdr, sizeof(hdr));
	debug(c, "%s.%d. reset done\n", __func__, __LINE__);
	return 0;

}

int utcp_shutdown(struct utcp_connection *c, int dir) {
	debug(c, "shutdown %d at %u\n", dir, c ? c->snd.last : 0);

	if(!c) {
		errno = EFAULT;
		return -1;
	}

	if(c->reapable) {
		debug(c, "shutdown() called on closed connection\n");
		errno = EBADF;
		return -1;
	}

	if(!(dir == UTCP_SHUT_RD || dir == UTCP_SHUT_WR || dir == UTCP_SHUT_RDWR)) {
	debug(c, "%s.%d. invalid\n", __func__, __LINE__);
		errno = EINVAL;
		return -1;
	}

	// TCP does not have a provision for stopping incoming packets.
	// The best we can do is to just ignore them.
	if(dir == UTCP_SHUT_RD || dir == UTCP_SHUT_RDWR) {
		c->recv = NULL;
	}

	// The rest of the code deals with shutting down writes.
	if(dir == UTCP_SHUT_RD) {
	debug(c, "%s.%d. UTCP_SHUT_RD\n", __func__, __LINE__);
		return 0;
	}

	// Only process shutting down writes once.
	if(c->shut_wr) {
	debug(c, "%s.%d. Only process shutting down writes once\n", __func__, __LINE__);
		return 0;
	}

	c->shut_wr = true;

	switch(c->state) {
	case CLOSED:
	case LISTEN:
		errno = ENOTCONN;
	debug(c, "%s.%d. ENOTCONN\n", __func__, __LINE__);
		return -1;

	case SYN_SENT:
	debug(c, "%s.%d. SYN_SENT\n", __func__, __LINE__);
		return 0;

	case SYN_RECEIVED:
	case ESTABLISHED:
		set_state(c, FIN_WAIT_1);
		break;

	case FIN_WAIT_1:
	case FIN_WAIT_2:
	debug(c, "%s.%d. FIN_WAIT\n", __func__, __LINE__);
		return 0;

	case CLOSE_WAIT:
		set_state(c, CLOSING);
		break;

	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
	debug(c, "%s.%d. Closing, last ack, time_wait\n", __func__, __LINE__);
		return 0;
	}

	c->snd.last++;

	ack(c, false);

	if(!timespec_isset(&c->rtrx_timeout)) {
		start_retransmit_timer(c);
	}

	debug(c, "%s.%d. Done\n", __func__, __LINE__);
	return 0;
}

static bool reset_connection(struct utcp_connection *c) {
	debug(c, "%s.%d. Started\n", __func__, __LINE__);
	if(!c) {
		errno = EFAULT;
	debug(c, "%s.%d. EFAULT\n", __func__, __LINE__);
		return false;
	}

	if(c->reapable) {
		debug(c, "abort() called on closed connection\n");
		errno = EBADF;
		return false;
	}

	c->recv = NULL;
	c->poll = NULL;

	switch(c->state) {
	case CLOSED:
	debug(c, "%s.%d. Closed \n", __func__, __LINE__);
		return true;

	case LISTEN:
	case SYN_SENT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		set_state(c, CLOSED);
	debug(c, "%s.%d. Closed\n", __func__, __LINE__);
		return true;

	case SYN_RECEIVED:
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSE_WAIT:
		set_state(c, CLOSED);
	debug(c, "%s.%d. Closed\n", __func__, __LINE__);
		break;
	}

	// Send RST

	struct hdr hdr;

	hdr.src = c->src;
	hdr.dst = c->dst;
	hdr.seq = c->snd.nxt;
	hdr.ack = 0;
	hdr.wnd = 0;
	hdr.ctl = RST;

	print_packet(c, "send", &hdr, sizeof(hdr));
	c->utcp->send(c->utcp, &hdr, sizeof(hdr));
	debug(c, "%s.%d. Done\n", __func__, __LINE__);
	return true;
}

// Closes all the opened connections
void utcp_abort_all_connections(struct utcp *utcp) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(!utcp) {
	debug(NULL, "%s.%d. Invalid\n", __func__, __LINE__);
		errno = EINVAL;
		return;
	}

	debug(NULL, "%s.%d. loop connections\n", __func__, __LINE__);
	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

	debug(c, "%s.%d. Continue if closed or reaped\n", __func__, __LINE__);
		if(c->reapable || c->state == CLOSED) {
			continue;
		}

		utcp_recv_t old_recv = c->recv;
		utcp_poll_t old_poll = c->poll;

	debug(c, "%s.%d. reset connection\n", __func__, __LINE__);
		reset_connection(c);

		if(old_recv) {
			errno = 0;
	debug(c, "%s.%d. old recv\n", __func__, __LINE__);
			old_recv(c, NULL, 0);
		}

		if(old_poll && !c->reapable) {
			errno = 0;
	debug(c, "%s.%d. old poll 0\n", __func__, __LINE__);
			old_poll(c, 0);
		}
	}

	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return;
}

int utcp_close(struct utcp_connection *c) {
	debug(c, "%s.%d. Started\n", __func__, __LINE__);
	if(utcp_shutdown(c, SHUT_RDWR) && errno != ENOTCONN) {
	debug(c, "%s.%d. utcp_shutdown\n", __func__, __LINE__);
		return -1;
	}

	c->recv = NULL;
	c->poll = NULL;
	c->reapable = true;
	debug(c, "%s.%d. Reset and reap the connection\n", __func__, __LINE__);
	return 0;
}

int utcp_abort(struct utcp_connection *c) {
	debug(c, "%s.%d. Started\n", __func__, __LINE__);
	if(!reset_connection(c)) {
	debug(c, "%s.%d. reset connection failed\n", __func__, __LINE__);
		return -1;
	}

	c->reapable = true;
	debug(c, "%s.%d. done\n", __func__, __LINE__);
	return 0;
}

/* Handle timeouts.
 * One call to this function will loop through all connections,
 * checking if something needs to be resent or not.
 * The return value is the time to the next timeout in milliseconds,
 * or maybe a negative value if the timeout is infinite.
 */
struct timespec utcp_timeout(struct utcp *utcp) {
	struct timespec now;
	clock_gettime(UTCP_CLOCK, &now);
	struct timespec next = {now.tv_sec + 3600, now.tv_nsec};

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(!c) {
			continue;
		}

		// delete connections that have been utcp_close()d.
		if(c->state == CLOSED) {
			if(c->reapable) {
				debug(c, "reaping\n");
				free_connection(c);
				i--;
			}

			continue;
		}

		if(timespec_isset(&c->conn_timeout) && timespec_lt(&c->conn_timeout, &now)) {
			errno = ETIMEDOUT;
			c->state = CLOSED;

			if(c->recv) {
				c->recv(c, NULL, 0);
			}

			if(c->poll && !c->reapable) {
				c->poll(c, 0);
			}

			continue;
		}

		if(timespec_isset(&c->rtrx_timeout) && timespec_lt(&c->rtrx_timeout, &now)) {
			debug(c, "retransmitting after timeout\n");
			retransmit(c);
		}

		if(c->poll) {
			if((c->state == ESTABLISHED || c->state == CLOSE_WAIT) && c->do_poll) {
				c->do_poll = false;
				uint32_t len = buffer_free(&c->sndbuf);

				if(len) {
					c->poll(c, len);
				}
			} else if(c->state == CLOSED) {
				c->poll(c, 0);
			}
		}

		if(timespec_isset(&c->conn_timeout) && timespec_lt(&c->conn_timeout, &next)) {
			next = c->conn_timeout;
		}

		if(timespec_isset(&c->rtrx_timeout) && timespec_lt(&c->rtrx_timeout, &next)) {
			next = c->rtrx_timeout;
		}
	}

	struct timespec diff;

	timespec_sub(&next, &now, &diff);

	return diff;
}

bool utcp_is_active(struct utcp *utcp) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(!utcp) {
	debug(NULL, "%s.%d. invalid\n", __func__, __LINE__);
		return false;
	}

	debug(NULL, "%s.%d. Loop connctions\n", __func__, __LINE__);
	for(int i = 0; i < utcp->nconnections; i++)
		if(utcp->connections[i]->state != CLOSED && utcp->connections[i]->state != TIME_WAIT) {
	debug(NULL, "%s.%d. active\n", __func__, __LINE__);
			return true;
		}

	debug(NULL, "%s.%d. not active\n", __func__, __LINE__);
	return false;
}

struct utcp *utcp_init(utcp_accept_t accept, utcp_pre_accept_t pre_accept, utcp_send_t send, void *priv) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(!send) {
		errno = EFAULT;
	debug(NULL, "%s.%d. faulty\n", __func__, __LINE__);
		return NULL;
	}

	struct utcp *utcp = calloc(1, sizeof(*utcp));

	if(!utcp) {
	debug(NULL, "%s.%d. failed mem alloc\n", __func__, __LINE__);
		return NULL;
	}

	debug(NULL, "%s.%d. if CLOCK_GRANULARITY\n", __func__, __LINE__);
	if(!CLOCK_GRANULARITY) {
		struct timespec res;
	debug(NULL, "%s.%d. clock_getres\n", __func__, __LINE__);
		clock_getres(UTCP_CLOCK, &res);
		CLOCK_GRANULARITY = res.tv_sec * USEC_PER_SEC + res.tv_nsec / 1000;
	}

	debug(NULL, "%s.%d. Set MTU\n", __func__, __LINE__);
	utcp->accept = accept;
	utcp->pre_accept = pre_accept;
	utcp->send = send;
	utcp->priv = priv;
	utcp_set_mtu(utcp, DEFAULT_MTU);
	utcp->timeout = DEFAULT_USER_TIMEOUT; // sec

	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
	return utcp;
}

void utcp_exit(struct utcp *utcp) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(!utcp) {
	debug(NULL, "%s.%d. Invalid\n", __func__, __LINE__);
		return;
	}

	debug(NULL, "%s.%d. loop connections\n", __func__, __LINE__);
	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

	debug(NULL, "%s.%d. if new connect\n", __func__, __LINE__);
		if(!c->reapable) {
			if(c->recv) {
	debug(NULL, "%s.%d. invoke closure cb\n", __func__, __LINE__);
				c->recv(c, NULL, 0);
			}

	debug(NULL, "%s.%d. invoke poll cb len =0\n", __func__, __LINE__);
			if(c->poll && !c->reapable) {
				c->poll(c, 0);
			}
		}

	debug(NULL, "%s.%d. free connection\n", __func__, __LINE__);
		buffer_exit(&c->rcvbuf);
		buffer_exit(&c->sndbuf);
		free(c);
	}

	free(utcp->connections);
	free(utcp->pkt);
	free(utcp);
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

uint16_t utcp_get_mtu(struct utcp *utcp) {
	debug(NULL, "%s.%d. called\n", __func__, __LINE__);
	return utcp ? utcp->mtu : 0;
}

uint16_t utcp_get_mss(struct utcp *utcp) {
	debug(NULL, "%s.%d. called\n", __func__, __LINE__);
	return utcp ? utcp->mss : 0;
}

void utcp_set_mtu(struct utcp *utcp, uint16_t mtu) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(!utcp) {
	debug(NULL, "%s.%d. faulty\n", __func__, __LINE__);
		return;
	}

	debug(NULL, "%s.%d. if mtu < header\n", __func__, __LINE__);
	if(mtu <= sizeof(struct hdr)) {
	debug(NULL, "%s.%d. mtu < header\n", __func__, __LINE__);
		return;
	}

	debug(NULL, "%s.%d. if mtu > UTCPMTU\n", __func__, __LINE__);
	if(mtu > utcp->mtu) {
		char *new = realloc(utcp->pkt, mtu + sizeof(struct hdr));

		if(!new) {
	debug(NULL, "%s.%d. realloc failed\n", __func__, __LINE__);
			return;
		}

		utcp->pkt = new;
	}

	utcp->mtu = mtu;
	utcp->mss = mtu - sizeof(struct hdr);
	debug(NULL, "%s.%d. Doneif mtu > UTCPMTU\n", __func__, __LINE__);
}

void utcp_reset_timers(struct utcp *utcp) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(!utcp) {
	debug(NULL, "%s.%d. faulty\n", __func__, __LINE__);
		return;
	}

	struct timespec now, then;

	debug(NULL, "%s.%d. clock_gettime\n", __func__, __LINE__);
	clock_gettime(UTCP_CLOCK, &now);

	then = now;

	then.tv_sec += utcp->timeout;

	debug(NULL, "%s.%d. loop connection\n", __func__, __LINE__);
	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(c->reapable) {
	debug(NULL, "%s.%d. skip if reaped\n", __func__, __LINE__);
			continue;
		}

	debug(NULL, "%s.%d. timespec_isset timespec_isset\n", __func__, __LINE__);
		if(timespec_isset(&c->rtrx_timeout)) {
			c->rtrx_timeout = now;
		}

	debug(NULL, "%s.%d. timespec_isset conn_timeout\n", __func__, __LINE__);
		if(timespec_isset(&c->conn_timeout)) {
			c->conn_timeout = then;
		}

		c->rtt_start.tv_sec = 0;

		if(c->rto > START_RTO) {
			c->rto = START_RTO;
		}
	debug(NULL, "%s.%d. if c->rto > START_RTO then set to it\n", __func__, __LINE__);
	}
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

int utcp_get_user_timeout(struct utcp *u) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	return u ? u->timeout : 0;
}

void utcp_set_user_timeout(struct utcp *u, int timeout) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(u) {
		u->timeout = timeout;
	}
}

size_t utcp_get_sndbuf(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	return c ? c->sndbuf.maxsize : 0;
}

size_t utcp_get_sndbuf_free(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(!c) {
	debug(NULL, "%s.%d. faulty\n", __func__, __LINE__);
		return 0;
	}

	debug(NULL, "%s.%d. Switch to state\n", __func__, __LINE__);
	switch(c->state) {
	case SYN_SENT:
	case SYN_RECEIVED:
	case ESTABLISHED:
	case CLOSE_WAIT:
	debug(NULL, "%s.%d. free buffer\n", __func__, __LINE__);
		return buffer_free(&c->sndbuf);

	default:
	debug(NULL, "%s.%d. defaylt\n", __func__, __LINE__);
		return 0;
	}
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

void utcp_set_sndbuf(struct utcp_connection *c, size_t size) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(!c) {
	debug(NULL, "%s.%d. Faulty\n", __func__, __LINE__);
		return;
	}

	c->sndbuf.maxsize = size;

	if(c->sndbuf.maxsize != size) {
		c->sndbuf.maxsize = -1;
	}

	c->do_poll = buffer_free(&c->sndbuf);
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

size_t utcp_get_rcvbuf(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	return c ? c->rcvbuf.maxsize : 0;
}

size_t utcp_get_rcvbuf_free(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(c && (c->state == ESTABLISHED || c->state == CLOSE_WAIT)) {
	debug(NULL, "%s.%d. buffer freeing\n", __func__, __LINE__);
		return buffer_free(&c->rcvbuf);
	} else {
	debug(NULL, "%s.%d. ret 0\n", __func__, __LINE__);
		return 0;
	}
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

void utcp_set_rcvbuf(struct utcp_connection *c, size_t size) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(!c) {
		return;
	}

	c->rcvbuf.maxsize = size;

	if(c->rcvbuf.maxsize != size) {
		c->rcvbuf.maxsize = -1;
	}
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

size_t utcp_get_sendq(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	return c->sndbuf.used;
}

size_t utcp_get_recvq(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	return c->rcvbuf.used;
}

bool utcp_get_nodelay(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	return c ? c->nodelay : false;
}

void utcp_set_nodelay(struct utcp_connection *c, bool nodelay) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(c) {
		c->nodelay = nodelay;
	}
}

bool utcp_get_keepalive(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	return c ? c->keepalive : false;
}

void utcp_set_keepalive(struct utcp_connection *c, bool keepalive) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(c) {
		c->keepalive = keepalive;
	}
}

size_t utcp_get_outq(struct utcp_connection *c) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	return c ? seqdiff(c->snd.nxt, c->snd.una) : 0;
}

void utcp_set_recv_cb(struct utcp_connection *c, utcp_recv_t recv) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(c) {
		c->recv = recv;
	}
}

void utcp_set_poll_cb(struct utcp_connection *c, utcp_poll_t poll) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(c) {
		c->poll = poll;
		c->do_poll = buffer_free(&c->sndbuf);
	}
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

void utcp_set_accept_cb(struct utcp *utcp, utcp_accept_t accept, utcp_pre_accept_t pre_accept) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	if(utcp) {
		utcp->accept = accept;
		utcp->pre_accept = pre_accept;
	}
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

void utcp_expect_data(struct utcp_connection *c, bool expect) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	if(!c || c->reapable) {
		return;
	}

	if(!(c->state == ESTABLISHED || c->state == FIN_WAIT_1 || c->state == FIN_WAIT_2)) {
		return;
	}

	if(expect) {
		// If we expect data, start the connection timer.
		if(!timespec_isset(&c->conn_timeout)) {
			clock_gettime(UTCP_CLOCK, &c->conn_timeout);
			c->conn_timeout.tv_sec += c->utcp->timeout;
		}
	} else {
		// If we want to cancel expecting data, only clear the timer when there is no unACKed data.
		if(c->snd.una == c->snd.last) {
			timespec_clear(&c->conn_timeout);
		}
	}
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

void utcp_offline(struct utcp *utcp, bool offline) {
	debug(NULL, "%s.%d. Started\n", __func__, __LINE__);
	struct timespec now;
	clock_gettime(UTCP_CLOCK, &now);

	debug(NULL, "%s.%d. loop connections\n", __func__, __LINE__);
	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(c->reapable) {
	debug(NULL, "%s.%d. closed or reaped connection\n", __func__, __LINE__);
			continue;
		}

	debug(NULL, "%s.%d. utcp_expect_data\n", __func__, __LINE__);
		utcp_expect_data(c, offline);

	debug(NULL, "%s.%d. if not offline\n", __func__, __LINE__);
		if(!offline) {
	debug(NULL, "%s.%d. if rtrx_timeout timount is set\n", __func__, __LINE__);
			if(timespec_isset(&c->rtrx_timeout)) {
				c->rtrx_timeout = now;
			}

	debug(NULL, "%s.%d. rtt_start = 0\n", __func__, __LINE__);
			utcp->connections[i]->rtt_start.tv_sec = 0;

	debug(NULL, "%s.%d. if cpnnection rto > START_RTO\n", __func__, __LINE__);
			if(c->rto > START_RTO) {
				c->rto = START_RTO;
			}
	debug(NULL, "%s.%d. next connection\n", __func__, __LINE__);
		}
	}
	debug(NULL, "%s.%d. Done\n", __func__, __LINE__);
}

void utcp_set_clock_granularity(long granularity) {
	debug(NULL, "%s.%d. Called\n", __func__, __LINE__);
	CLOCK_GRANULARITY = granularity;
}
