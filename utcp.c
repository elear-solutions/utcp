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
#include <sys/time.h>
#include <sys/socket.h>

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

#ifndef timersub
#define timersub(a, b, r)\
	do {\
		(r)->tv_sec = (a)->tv_sec - (b)->tv_sec;\
		(r)->tv_usec = (a)->tv_usec - (b)->tv_usec;\
		if((r)->tv_usec < 0)\
			(r)->tv_sec--, (r)->tv_usec += USEC_PER_SEC;\
	} while (0)
#endif

static inline size_t max(size_t a, size_t b) {
	return a > b ? a : b;
}

#define UTCP_DEBUG 1

#ifdef UTCP_DEBUG
#include <stdarg.h>

static void debug(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

static void print_packet(struct utcp *utcp, const char *dir, const void *pkt, size_t len) {
	struct hdr hdr;

	if(len < sizeof(hdr)) {
		debug("%p %s: short packet (%lu bytes)\n", utcp, dir, (unsigned long)len);
		return;
	}

	memcpy(&hdr, pkt, sizeof(hdr));
	debug("%p %s: len=%lu, src=%u dst=%u seq=%u ack=%u wnd=%u aux=%x ctl=", utcp, dir, (unsigned long)len, hdr.src, hdr.dst, hdr.seq, hdr.ack, hdr.wnd, hdr.aux);

	if(hdr.ctl & SYN) {
		debug("SYN");
	}

	if(hdr.ctl & RST) {
		debug("RST");
	}

	if(hdr.ctl & FIN) {
		debug("FIN");
	}

	if(hdr.ctl & ACK) {
		debug("ACK");
	}

	if(len > sizeof(hdr)) {
		uint32_t datalen = len - sizeof(hdr);
		const uint8_t *data = (uint8_t *)pkt + sizeof(hdr);
		char str[datalen * 2 + 1];
		char *p = str;

		for(uint32_t i = 0; i < datalen; i++) {
			*p++ = "0123456789ABCDEF"[data[i] >> 4];
			*p++ = "0123456789ABCDEF"[data[i] & 15];
		}

		*p = 0;

		debug(" data=%s", str);
	}

	debug("\n");
}
#else
#define debug(...) do {} while(0)
#define print_packet(...) do {} while(0)
#endif

static void set_state(struct utcp_connection *c, enum state state) {
	c->state = state;

	if(state == ESTABLISHED) {
		timerclear(&c->conn_timeout);
	}

	debug("%p new state: %s\n", c->utcp, strstate[state]);
}

static bool fin_wanted(struct utcp_connection *c, uint32_t seq) {
	debug("%s.%d. called\n", __func__, __LINE__);
	if(seq != c->snd.last) {
	debug("%s.%d. seq != c->snd.last\n", __func__, __LINE__);
		return false;
	}

	switch(c->state) {
	case FIN_WAIT_1:
	case CLOSING:
	case LAST_ACK:
	debug("%s.%d. LAST ACK\n", __func__, __LINE__);
		return true;

	default:
	debug("%s.%d. Default\n", __func__, __LINE__);
		return false;
	}
	debug("%s.%d. Done\n", __func__, __LINE__);
}

static bool is_reliable(struct utcp_connection *c) {
	debug("%s.%d. called, c: %p, c->flags & UTCP_RELIABLE: %d\n", __func__, __LINE__, c);
	debug("%s.%d. c->flags & UTCP_RELIABLE: %d\n", __func__, __LINE__, c->flags & UTCP_RELIABLE);
	return c->flags & UTCP_RELIABLE;
}

static int32_t seqdiff(uint32_t a, uint32_t b) {
	debug("%s.%d. Called, a: %d b: %d, a-b: %d\n", __func__, __LINE__, a, b, a-b);
	return a - b;
}

// Buffer functions
// TODO: convert to ringbuffers to avoid memmove() operations.

// Store data into the buffer
static ssize_t buffer_put_at(struct buffer *buf, size_t offset, const void *data, size_t len) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	debug("buffer_put_at %lu %lu %lu\n", (unsigned long)buf->used, (unsigned long)offset, (unsigned long)len);

	size_t required = offset + len;

	if(required > buf->maxsize) {
		if(offset >= buf->maxsize) {
			return 0;
		}

		len = buf->maxsize - offset;
		required = buf->maxsize;
	}

	if(required > buf->size) {
		size_t newsize = buf->size;

		if(!newsize) {
			newsize = required;
		} else {
			do {
				newsize *= 2;
			} while(newsize < required);
		}

		if(newsize > buf->maxsize) {
			newsize = buf->maxsize;
		}

		char *newdata = realloc(buf->data, newsize);

		if(!newdata) {
			return -1;
		}

		buf->data = newdata;
		buf->size = newsize;
	}

	memcpy(buf->data + offset, data, len);

	if(required > buf->used) {
		buf->used = required;
	}

	debug("%s.%d. Done\n", __func__, __LINE__);
	return len;
}

static ssize_t buffer_put(struct buffer *buf, const void *data, size_t len) {
	debug("%s.%d. called\n", __func__, __LINE__);
	return buffer_put_at(buf, buf->used, data, len);
}

// Get data from the buffer. data can be NULL.
static ssize_t buffer_get(struct buffer *buf, void *data, size_t len) {
	if(len > buf->used) {
		len = buf->used;
	}

	if(data) {
		memcpy(data, buf->data, len);
	}

	if(len < buf->used) {
		memmove(buf->data, buf->data + len, buf->used - len);
	}

	buf->used -= len;
	return len;
}

// Copy data from the buffer without removing it.
static ssize_t buffer_copy(struct buffer *buf, void *data, size_t offset, size_t len) {
	if(offset >= buf->used) {
		return 0;
	}

	if(offset + len > buf->used) {
		len = buf->used - offset;
	}

	memcpy(data, buf->data + offset, len);
	return len;
}

static bool buffer_init(struct buffer *buf, uint32_t len, uint32_t maxlen) {
	memset(buf, 0, sizeof(*buf));

	if(len) {
		buf->data = malloc(len);

		if(!buf->data) {
			return false;
		}
	}

	buf->size = len;
	buf->maxsize = maxlen;
	return true;
}

static void buffer_exit(struct buffer *buf) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	free(buf->data);
	memset(buf, 0, sizeof(*buf));
	debug("%s.%d. Done\n", __func__, __LINE__);
}

static uint32_t buffer_free(const struct buffer *buf) {
	debug("%s.%d. Buffer free called\n", __func__, __LINE__);
	return buf->maxsize - buf->used;
}

// Connections are stored in a sorted list.
// This gives O(log(N)) lookup time, O(N log(N)) insertion time and O(N) deletion time.

static int compare(const void *va, const void *vb) {
	debug("%s.%d. Compare connections\n", __func__, __LINE__);
	assert(va && vb);

	const struct utcp_connection *a = *(struct utcp_connection **)va;
	const struct utcp_connection *b = *(struct utcp_connection **)vb;

	assert(a && b);
	assert(a->src && b->src);

	int c = (int)a->src - (int)b->src;

	if(c) {
	debug("%s.%d. Done\n", __func__, __LINE__);
		return c;
	}

	c = (int)a->dst - (int)b->dst;
	debug("%s.%d. Done\n", __func__, __LINE__);
	return c;
}

static struct utcp_connection *find_connection(const struct utcp *utcp, uint16_t src, uint16_t dst) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	if(!utcp->nconnections) {
	debug("%s.%d. NULL Done\n", __func__, __LINE__);
		return NULL;
	}

	struct utcp_connection key = {
		.src = src,
		.dst = dst,
	}, *keyp = &key;
	debug("%s.%d. bsearch\n", __func__, __LINE__);
	struct utcp_connection **match = bsearch(&keyp, utcp->connections, utcp->nconnections, sizeof(*utcp->connections), compare);
	debug("%s.%d. Done\n", __func__, __LINE__);
	return match ? *match : NULL;
}

static void free_connection(struct utcp_connection *c) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	struct utcp *utcp = c->utcp;
	struct utcp_connection **cp = bsearch(&c, utcp->connections, utcp->nconnections, sizeof(*utcp->connections), compare);

	assert(cp);

	int i = cp - utcp->connections;
	memmove(cp, cp + 1, (utcp->nconnections - i - 1) * sizeof(*cp));
	utcp->nconnections--;

	buffer_exit(&c->rcvbuf);
	buffer_exit(&c->sndbuf);
	free(c);
	debug("%s.%d. Done\n", __func__, __LINE__);
}

static struct utcp_connection *allocate_connection(struct utcp *utcp, uint16_t src, uint16_t dst) {
	debug("%s.%d. Started\n", __func__, __LINE__);
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

	if(!buffer_init(&c->sndbuf, DEFAULT_SNDBUFSIZE, DEFAULT_MAXSNDBUFSIZE)) {
		free(c);
		return NULL;
	}

	if(!buffer_init(&c->rcvbuf, DEFAULT_RCVBUFSIZE, DEFAULT_MAXRCVBUFSIZE)) {
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
	c->rcv.wnd = utcp->mtu;
	c->snd.last = c->snd.nxt;
	c->snd.cwnd = utcp->mtu;
	c->utcp = utcp;

	// Add it to the sorted list of connections

	utcp->connections[utcp->nconnections++] = c;
	qsort(utcp->connections, utcp->nconnections, sizeof(*utcp->connections), compare);

	debug("%s.%d. Done\n", __func__, __LINE__);
	return c;
}

static inline uint32_t absdiff(uint32_t a, uint32_t b) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(a > b) {
	debug("%s.%d. a - b\n", __func__, __LINE__);
		return a - b;
	} else {
	debug("%s.%d. b - a\n", __func__, __LINE__);
		return b - a;
	}
}

// Update RTT variables. See RFC 6298.
static void update_rtt(struct utcp_connection *c, uint32_t rtt) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	if(!rtt) {
		debug("invalid rtt\n");
		return;
	}

	struct utcp *utcp = c->utcp;

	if(!utcp->srtt) {
		utcp->srtt = rtt;
		utcp->rttvar = rtt / 2;
	} else {
		utcp->rttvar = (utcp->rttvar * 3 + absdiff(utcp->srtt, rtt)) / 4;
		utcp->srtt = (utcp->srtt * 7 + rtt) / 8;
	}

	utcp->rto = utcp->srtt + max(4 * utcp->rttvar, CLOCK_GRANULARITY);

	if(utcp->rto > MAX_RTO) {
		utcp->rto = MAX_RTO;
	}

	debug("rtt %u srtt %u rttvar %u rto %u\n", rtt, utcp->srtt, utcp->rttvar, utcp->rto);
}

static void start_retransmit_timer(struct utcp_connection *c) {
	gettimeofday(&c->rtrx_timeout, NULL);
	c->rtrx_timeout.tv_usec += c->utcp->rto;

	while(c->rtrx_timeout.tv_usec >= 1000000) {
		c->rtrx_timeout.tv_usec -= 1000000;
		c->rtrx_timeout.tv_sec++;
	}

	debug("timeout set to %lu.%06lu (%u)\n", c->rtrx_timeout.tv_sec, c->rtrx_timeout.tv_usec, c->utcp->rto);
}

static void stop_retransmit_timer(struct utcp_connection *c) {
	timerclear(&c->rtrx_timeout);
	debug("timeout cleared\n");
}

struct utcp_connection *utcp_connect_ex(struct utcp *utcp, uint16_t dst, utcp_recv_t recv, void *priv, uint32_t flags) {
	debug("%s.%d. Started\n", __func__, __LINE__);
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
	pkt.hdr.wnd = c->rcv.wnd;
	pkt.hdr.ctl = SYN;
	pkt.hdr.aux = 0x0101;
	pkt.init[0] = 1;
	pkt.init[1] = 0;
	pkt.init[2] = 0;
	pkt.init[3] = flags & 0x7;

	set_state(c, SYN_SENT);

	print_packet(utcp, "send", &pkt, sizeof(pkt));
	utcp->send(utcp, &pkt, sizeof(pkt));

	gettimeofday(&c->conn_timeout, NULL);
	c->conn_timeout.tv_sec += utcp->timeout;

	start_retransmit_timer(c);

	debug("%s.%d. Done\n", __func__, __LINE__);
	return c;
}

struct utcp_connection *utcp_connect(struct utcp *utcp, uint16_t dst, utcp_recv_t recv, void *priv) {
	return utcp_connect_ex(utcp, dst, recv, priv, UTCP_TCP);
}

void utcp_accept(struct utcp_connection *c, utcp_recv_t recv, void *priv) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(c->reapable || c->state != SYN_RECEIVED) {
		debug("Error: accept() called on invalid connection %p in state %s\n", c, strstate[c->state]);
		return;
	}

	debug("%p accepted, %p %p\n", c, recv, priv);
	c->recv = recv;
	c->priv = priv;
	set_state(c, ESTABLISHED);
	debug("%s.%d. Done\n", __func__, __LINE__);
}

static void ack(struct utcp_connection *c, bool sendatleastone) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	int32_t left = seqdiff(c->snd.last, c->snd.nxt);
	int32_t cwndleft = c->snd.cwnd - seqdiff(c->snd.nxt, c->snd.una);
	debug("cwndleft = %d\n", cwndleft);

	debug("%s.%d. cwndleft: %d\n", __func__, __LINE__, cwndleft);
	assert(left >= 0);

	debug("%s.%d. If cwd left size <= 0\n", __func__, __LINE__);
	if(cwndleft <= 0) {
		cwndleft = 0;
	}

	if(cwndleft < left) {
		left = cwndleft;
	}

	debug("cwndleft %d left %d\n", cwndleft, left);

	if(!left && !sendatleastone) {
	debug("%s.%d. !left && !sendatleastone\n", __func__, __LINE__);
		return;
	}

	struct {
		struct hdr hdr;
		uint8_t data[];
	} *pkt;

	pkt = malloc(sizeof(pkt->hdr) + c->utcp->mtu);

	if(!pkt) {
		return;
	}

	pkt->hdr.src = c->src;
	pkt->hdr.dst = c->dst;
	pkt->hdr.ack = c->rcv.nxt;
	pkt->hdr.wnd = c->snd.wnd;
	pkt->hdr.ctl = ACK;
	pkt->hdr.aux = 0;

	debug("%s.%d. Send ACK in a loop\n", __func__, __LINE__);
	do {
		uint32_t seglen = left > c->utcp->mtu ? c->utcp->mtu : left;
		pkt->hdr.seq = c->snd.nxt;

	debug("%s.%d. Buffer copy, offset: %d len: %d\n", __func__, __LINE__, seqdiff(c->snd.nxt, c->snd.una), seglen);
		buffer_copy(&c->sndbuf, pkt->data, seqdiff(c->snd.nxt, c->snd.una), seglen);

	debug("%s.%d. c->snd.nxt: %d seglen: %d, left: %d\n", __func__, __LINE__, c->snd.nxt, seglen, left);
		c->snd.nxt += seglen;
		left -= seglen;
	debug("%s.%d. c->snd.nxt: %d seglen: %d, left: %d\n", __func__, __LINE__, c->snd.nxt, seglen, left);

	debug("%s.%d. Is reliable\n", __func__, __LINE__);
		if(seglen && fin_wanted(c, c->snd.nxt)) {
			seglen--;
			pkt->hdr.ctl |= FIN;
		}

	debug("%s.%d. Start RTT measurment, c->rtt_start.tv_sec: %lu\n", __func__, __LINE__, c->rtt_start.tv_sec);
		if(!c->rtt_start.tv_sec) {
			// Start RTT measurement
			gettimeofday(&c->rtt_start, NULL);
			c->rtt_seq = pkt->hdr.seq + seglen;
			debug("Starting RTT measurement, expecting ack %u\n", c->rtt_seq);
		}

		print_packet(c->utcp, "send", pkt, sizeof(pkt->hdr) + seglen);
	debug("%s.%d. calling utcpsend\n", __func__, __LINE__);
	debug("%s.%d. sizeof(pkt->hdr): %lu, seglen: %lu\n", __func__, __LINE__, sizeof(pkt->hdr), seglen);
	debug("%s.%d. c->utcp: %p, pkt: %p, sizeof(pkt->hdr) + seglen: %lu\n", __func__, __LINE__, c->utcp, pkt, sizeof(pkt->hdr) + seglen);
	debug("%s.%d. c->utcp->send: %p\n", __func__, __LINE__, c->utcp->send);
		c->utcp->send(c->utcp, pkt, sizeof(pkt->hdr) + seglen);
	debug("%s.%d. utcp send done\n", __func__, __LINE__);
	} while(left);

	free(pkt);
}

ssize_t utcp_send(struct utcp_connection *c, const void *data, size_t len) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	if(c->reapable) {
		debug("Error: send() called on closed connection %p\n", c);
		errno = EBADF;
		return -1;
	}

	debug("%s.%d. c->state\n", __func__, __LINE__);
	switch(c->state) {
	case CLOSED:
	case LISTEN:
		debug("Error: send() called on unconnected connection %p\n", c);
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
		debug("Error: send() called on closing connection %p\n", c);
		errno = EPIPE;
		return -1;
	}

	// Exit early if we have nothing to send.

	debug("%s.%d. If len = 0\n", __func__, __LINE__);
	if(!len) {
	debug("%s.%d. Exit early if we have nothing to send.\n", __func__, __LINE__);
		return 0;
	}

	debug("%s.%d. Data is NULL?\n", __func__, __LINE__);
	if(!data) {
		errno = EFAULT;
	debug("%s.%d. Faulty packet\n", __func__, __LINE__);
		return -1;
	}

	// Check if we need to be able to buffer all data

	debug("%s.%d. Check if we need to be able to buffer all data\n", __func__, __LINE__);
	if(c->flags & UTCP_NO_PARTIAL) {
	debug("%s.%d. Free send buffer\n", __func__, __LINE__);
		if(len > buffer_free(&c->sndbuf)) {
			if(len > c->sndbuf.maxsize) {
				errno = EMSGSIZE;
				return -1;
			} else {
				errno = EWOULDBLOCK;
	debug("%s.%d. Would block\n", __func__, __LINE__);
				return 0;
			}
		}
	}

	// Add data to send buffer.

	debug("%s.%d. Add data to send buffer\n", __func__, __LINE__);
	if(is_reliable(c) || (c->state != SYN_SENT && c->state != SYN_RECEIVED)) {
		len = buffer_put(&c->sndbuf, data, len);
	} else {
	debug("%s.%d. Is not reliable\n", __func__, __LINE__);
		return 0;
	}

	debug("%s.%d. if len is -ve\n", __func__, __LINE__);
	if(len <= 0) {
		if(is_reliable(c)) {
	debug("%s.%d. if reliable then error as would block\n", __func__, __LINE__);
			errno = EWOULDBLOCK;
			return 0;
		} else {
	debug("%s.%d. Return len\n", __func__, __LINE__);
			return len;
		}
	}

	c->snd.last += len;

	// Don't send anything yet if the connection has not fully established yet

	debug("%s.%d. Don't send anything yet if the connection has not fully established yet\n", __func__, __LINE__);
	if(c->state == SYN_SENT || c->state == SYN_RECEIVED) {
	debug("%s.%d. SYN send and received\n", __func__, __LINE__);
		return len;
	}

	debug("%s.%d. Send ACK\n", __func__, __LINE__);
	ack(c, false);

	debug("%s.%d. Is not reliable hen discard and poll\n", __func__, __LINE__);
	if(!is_reliable(c)) {
		c->snd.una = c->snd.nxt = c->snd.last;
		buffer_get(&c->sndbuf, NULL, c->sndbuf.used);
	}

	debug("%s.%d. Is reliable and rtxx set\n", __func__, __LINE__);
	if(is_reliable(c) && !timerisset(&c->rtrx_timeout)) {
		start_retransmit_timer(c);
	}

	debug("%s.%d. Is reliable and connection set\n", __func__, __LINE__);
	if(is_reliable(c) && !timerisset(&c->conn_timeout)) {
		gettimeofday(&c->conn_timeout, NULL);
		c->conn_timeout.tv_sec += c->utcp->timeout;
	}

	debug("%s.%d. Done\n", __func__, __LINE__);
	return len;
}

static void swap_ports(struct hdr *hdr) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	uint16_t tmp = hdr->src;
	hdr->src = hdr->dst;
	hdr->dst = tmp;
}

static void retransmit(struct utcp_connection *c) {
	if(c->state == CLOSED || c->snd.last == c->snd.una) {
		debug("Retransmit() called but nothing to retransmit!\n");
		stop_retransmit_timer(c);
		return;
	}

	struct utcp *utcp = c->utcp;

	struct {
		struct hdr hdr;
		uint8_t data[];
	} *pkt;

	pkt = malloc(sizeof(pkt->hdr) + c->utcp->mtu);

	if(!pkt) {
		return;
	}

	pkt->hdr.src = c->src;
	pkt->hdr.dst = c->dst;
	pkt->hdr.wnd = c->rcv.wnd;
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
		print_packet(c->utcp, "rtrx", pkt, sizeof(pkt->hdr) + 4);
		utcp->send(utcp, pkt, sizeof(pkt->hdr) + 4);
		break;

	case SYN_RECEIVED:
		// Send SYNACK again
		pkt->hdr.seq = c->snd.nxt;
		pkt->hdr.ack = c->rcv.nxt;
		pkt->hdr.ctl = SYN | ACK;
		print_packet(c->utcp, "rtrx", pkt, sizeof(pkt->hdr));
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
		uint32_t len = seqdiff(c->snd.last, c->snd.una);

		if(len > utcp->mtu) {
			len = utcp->mtu;
		}

		if(fin_wanted(c, c->snd.una + len)) {
			len--;
			pkt->hdr.ctl |= FIN;
		}

		c->snd.nxt = c->snd.una + len;
		c->snd.cwnd = utcp->mtu; // reduce cwnd on retransmit
		buffer_copy(&c->sndbuf, pkt->data, 0, len);
		print_packet(c->utcp, "rtrx", pkt, sizeof(pkt->hdr) + len);
		utcp->send(utcp, pkt, sizeof(pkt->hdr) + len);
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
	utcp->rto *= 2;

	if(utcp->rto > MAX_RTO) {
		utcp->rto = MAX_RTO;
	}

	c->rtt_start.tv_sec = 0; // invalidate RTT timer

cleanup:
	free(pkt);
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
	debug("sack_consume %lu\n", (unsigned long)len);

	if(len > c->rcvbuf.used) {
		debug("All SACK entries consumed");
		c->sacks[0].len = 0;
		return;
	}

	buffer_get(&c->rcvbuf, NULL, len);

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
		debug("SACK[%d] offset %u len %u\n", i, c->sacks[i].offset, c->sacks[i].len);
	}
}

static void handle_out_of_order(struct utcp_connection *c, uint32_t offset, const void *data, size_t len) {
	debug("out of order packet, offset %u\n", offset);
	// Packet loss or reordering occured. Store the data in the buffer.
	ssize_t rxd = buffer_put_at(&c->rcvbuf, offset, data, len);

	if(rxd < 0 || (size_t)rxd < len) {
		abort();
	}

	// Make note of where we put it.
	for(int i = 0; i < NSACKS; i++) {
		if(!c->sacks[i].len) { // nothing to merge, add new entry
			debug("New SACK entry %d\n", i);
			c->sacks[i].offset = offset;
			c->sacks[i].len = rxd;
			break;
		} else if(offset < c->sacks[i].offset) {
			if(offset + rxd < c->sacks[i].offset) { // insert before
				if(!c->sacks[NSACKS - 1].len) { // only if room left
					debug("Insert SACK entry at %d\n", i);
					memmove(&c->sacks[i + 1], &c->sacks[i], (NSACKS - i - 1) * sizeof(c->sacks)[i]);
					c->sacks[i].offset = offset;
					c->sacks[i].len = rxd;
				} else {
					debug("SACK entries full, dropping packet\n");
				}

				break;
			} else { // merge
				debug("Merge with start of SACK entry at %d\n", i);
				c->sacks[i].offset = offset;
				break;
			}
		} else if(offset <= c->sacks[i].offset + c->sacks[i].len) {
			if(offset + rxd > c->sacks[i].offset + c->sacks[i].len) { // merge
				debug("Merge with end of SACK entry at %d\n", i);
				c->sacks[i].len = offset + rxd - c->sacks[i].offset;
				// TODO: handle potential merge with next entry
			}

			break;
		}
	}

	for(int i = 0; i < NSACKS && c->sacks[i].len; i++) {
		debug("SACK[%d] offset %u len %u\n", i, c->sacks[i].offset, c->sacks[i].len);
	}
}

static void handle_in_order(struct utcp_connection *c, const void *data, size_t len) {
	// Check if we can process out-of-order data now.
	if(c->sacks[0].len && len >= c->sacks[0].offset) { // TODO: handle overlap with second SACK
		debug("incoming packet len %lu connected with SACK at %u\n", (unsigned long)len, c->sacks[0].offset);
		buffer_put_at(&c->rcvbuf, 0, data, len); // TODO: handle return value
		len = max(len, c->sacks[0].offset + c->sacks[0].len);
		data = c->rcvbuf.data;
	}

	if(c->recv) {
		ssize_t rxd = c->recv(c, data, len);

		if(rxd < 0 || (size_t)rxd != len) {
			// TODO: handle the application not accepting all data.
			abort();
		}
	}

	if(c->rcvbuf.used) {
		sack_consume(c, len);
	}

	c->rcv.nxt += len;
}


static void handle_incoming_data(struct utcp_connection *c, uint32_t seq, const void *data, size_t len) {
	if(!is_reliable(c)) {
		c->recv(c, data, len);
		c->rcv.nxt = seq + len;
		return;
	}

	uint32_t offset = seqdiff(seq, c->rcv.nxt);

	debug("%s.%d. offset len > max rcv buf size?\n", __func__, __LINE__);
	if(offset + len > c->rcvbuf.maxsize) {
		abort();
	}

	debug("%s.%d. Handle the offset, in or out of order\n", __func__, __LINE__);
	if(offset) {
		handle_out_of_order(c, offset, data, len);
	} else {
		handle_in_order(c, data, len);
	}
	debug("%s.%d. Done\n", __func__, __LINE__);
}


ssize_t utcp_recv(struct utcp *utcp, const void *data, size_t len) {
	debug("%s.%d. Started\n", __func__, __LINE__);
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

	print_packet(utcp, "recv", data, len);

	// Drop packets smaller than the header

	struct hdr hdr;

	if(len < sizeof(hdr)) {
		errno = EBADMSG;
		return -1;
	}

	// Make a copy from the potentially unaligned data to a struct hdr

	memcpy(&hdr, ptr, sizeof(hdr));
	ptr += sizeof(hdr);
	len -= sizeof(hdr);

	// Drop packets with an unknown CTL flag

	if(hdr.ctl & ~(SYN | ACK | RST | FIN)) {
		errno = EBADMSG;
	debug("%s.%d. Bad msg\n", __func__, __LINE__);
		return -1;
	}

	// Check for auxiliary headers
	debug("%s.%d. Check for auxiliary headers\n", __func__, __LINE__);

	const uint8_t *init = NULL;

	uint16_t aux = hdr.aux;

	while(aux) {
		size_t auxlen = 4 * (aux >> 8) & 0xf;
		uint8_t auxtype = aux & 0xff;

		if(len < auxlen) {
			errno = EBADMSG;
	debug("%s.%d. EBADMSG\n", __func__, __LINE__);
			return -1;
		}

	debug("%s.%d. Switch aux type\n", __func__, __LINE__);
		switch(auxtype) {
		case AUX_INIT:
			if(!(hdr.ctl & SYN) || auxlen != 4) {
				errno = EBADMSG;
	debug("%s.%d. BAD MSG\n", __func__, __LINE__);
				return -1;
			}

			init = ptr;
			break;

		default:
			errno = EBADMSG;
	debug("%s.%d. BAD MSG\n", __func__, __LINE__);
			return -1;
		}

		len -= auxlen;
		ptr += auxlen;

		if(!(aux & 0x800)) {
			break;
		}

		if(len < 2) {
			errno = EBADMSG;
	debug("%s.%d. BAD MSG\n", __func__, __LINE__);
			return -1;
		}

		memcpy(&aux, ptr, 2);
		len -= 2;
		ptr += 2;
	}

	bool has_data = len || (hdr.ctl & (SYN | FIN));

	// Try to match the packet to an existing connection

	struct utcp_connection *c = find_connection(utcp, hdr.dst, hdr.src);

	// Is it for a new connection?

	debug("%s.%d. Is it for a new connection?\n", __func__, __LINE__);
	if(!c) {
		// Ignore RST packets

	debug("%s.%d. Ignore RST packets\n", __func__, __LINE__);
		if(hdr.ctl & RST) {
	debug("%s.%d. Ignored RST packets\n", __func__, __LINE__);
			return 0;
		}

		// Is it a SYN packet and are we LISTENing?

	debug("%s.%d. Is it a SYN packet and are we LISTENing?\n", __func__, __LINE__);
		if(hdr.ctl & SYN && !(hdr.ctl & ACK) && utcp->accept) {
			// If we don't want to accept it, send a RST back
	debug("%s.%d. If we don't want to accept it, send a RST back\n", __func__, __LINE__);
			if((utcp->pre_accept && !utcp->pre_accept(utcp, hdr.dst))) {
				len = 1;
	debug("%s.%d. reset\n", __func__, __LINE__);
				goto reset;
			}

			// Try to allocate memory, otherwise send a RST back
			c = allocate_connection(utcp, hdr.dst, hdr.src);
	debug("%s.%d. allocated memory, otherwise sent a RST back\n", __func__, __LINE__);

			if(!c) {
				len = 1;
	debug("%s.%d. reset\n", __func__, __LINE__);
				goto reset;
			}

			// Parse auxilliary information
	debug("%s.%d. Parse auxilliary information\n", __func__, __LINE__);
			if(init) {
				if(init[0] < 1) {
					len = 1;
	debug("%s.%d. reset\n", __func__, __LINE__);
					goto reset;
				}

				c->flags = init[3] & 0x7;
			} else {
				c->flags = UTCP_TCP;
			}

synack:
			// Return SYN+ACK, go to SYN_RECEIVED state
	debug("%s.%d. Return SYN+ACK, go to SYN_RECEIVED state\n", __func__, __LINE__);
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
			pkt.hdr.wnd = c->rcv.wnd;
			pkt.hdr.ctl = SYN | ACK;

	debug("%s.%d. Send SYN ACK\n", __func__, __LINE__);
			if(init) {
				pkt.hdr.aux = 0x0101;
				pkt.data[0] = 1;
				pkt.data[1] = 0;
				pkt.data[2] = 0;
				pkt.data[3] = c->flags & 0x7;
				print_packet(c->utcp, "send", &pkt, sizeof(hdr) + 4);
				utcp->send(utcp, &pkt, sizeof(hdr) + 4);
			} else {
				pkt.hdr.aux = 0;
				print_packet(c->utcp, "send", &pkt, sizeof(hdr));
				utcp->send(utcp, &pkt, sizeof(hdr));
			}
		} else {
			// No, we don't want your packets, send a RST back
	debug("%s.%d. No, we don't want your packets, send a RST back\n", __func__, __LINE__);
			len = 1;
			goto reset;
		}

	debug("%s.%d. Synack done\n", __func__, __LINE__);
		return 0;
	}

	debug("%p state %s\n", c->utcp, strstate[c->state]);

	// In case this is for a CLOSED connection, ignore the packet.
	// TODO: make it so incoming packets can never match a CLOSED connection.

	if(c->state == CLOSED) {
		debug("Got packet for closed connection\n");
		return 0;
	}

	// It is for an existing connection.

	// 1. Drop invalid packets.

	// 1a. Drop packets that should not happen in our current state.
	debug("%s.%d. Drop packets that should not happen in our current state.\n", __func__, __LINE__);

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

	debug("%s.%d. Discard data that is not in our receive window.\n", __func__, __LINE__);
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
			debug("Packet not acceptable, %u <= %u + %lu < %u\n", c->rcv.nxt, hdr.seq, (unsigned long)len, c->rcv.nxt + c->rcvbuf.maxsize);

			// Ignore unacceptable RST packets.
			if(hdr.ctl & RST) {
				return 0;
			}

			// Otherwise, continue processing.
			len = 0;
		}
	}

	c->snd.wnd = hdr.wnd; // TODO: move below

	// 1c. Drop packets with an invalid ACK.
	// ackno should not roll back, and it should also not be bigger than what we ever could have sent
	// (= snd.una + c->sndbuf.used).
	debug("%s.%d.  Drop packets with an invalid ACK\n", __func__, __LINE__);

	if(!is_reliable(c)) {
		if(hdr.ack != c->snd.last && c->state >= ESTABLISHED) {
			hdr.ack = c->snd.una;
		}
	}

	if(hdr.ctl & ACK && (seqdiff(hdr.ack, c->snd.last) > 0 || seqdiff(hdr.ack, c->snd.una) < 0)) {
		debug("Packet ack seqno out of range, %u <= %u < %u\n", c->snd.una, hdr.ack, c->snd.una + c->sndbuf.used);

		// Ignore unacceptable RST packets.
	debug("%s.%d.  Ignore unacceptable RST packets.\n", __func__, __LINE__);
		if(hdr.ctl & RST) {
			return 0;
		}

	debug("%s.%d.  goto reset\n", __func__, __LINE__);
		goto reset;
	}

	// 2. Handle RST packets

	debug("%s.%d.  Handle RST packets\n", __func__, __LINE__);
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

	debug("%s.%d. if header is ACK\n", __func__, __LINE__);
	if(!(hdr.ctl & ACK)) {
		advanced = 0;
	debug("%s.%d. goto skip_ack\n", __func__, __LINE__);
		goto skip_ack;
	}

	// 3. Advance snd.una

	debug("%s.%d. After snd.una\n", __func__, __LINE__);
	advanced = seqdiff(hdr.ack, c->snd.una);
	debug("%s.%d. If advanced\n", __func__, __LINE__);

	if(advanced) {
	debug("%s.%d. Advanced, RTT measurement\n", __func__, __LINE__);
		// RTT measurement
		if(c->rtt_start.tv_sec) {
	debug("%s.%d. If RTT start\n", __func__, __LINE__);
			if(c->rtt_seq == hdr.ack) {
				struct timeval now, diff;
				gettimeofday(&now, NULL);
				timersub(&now, &c->rtt_start, &diff);
				update_rtt(c, diff.tv_sec * 1000000 + diff.tv_usec);
				c->rtt_start.tv_sec = 0;
			} else if(c->rtt_seq < hdr.ack) {
				debug("Cancelling RTT measurement: %u < %u\n", c->rtt_seq, hdr.ack);
				c->rtt_start.tv_sec = 0;
				debug("%s.%d. c->rtt_start.tv_sec reset\n", __func__, __LINE__);
			}
	debug("%s.%d. out of rtt measurement\n", __func__, __LINE__);
		}
	debug("%s.%d. out advanced condition\n", __func__, __LINE__);

		int32_t data_acked = advanced;

		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
	debug("%s.%d. SYN_RECEIVED\n", __func__, __LINE__);
			data_acked--;
	debug("%s.%d. SYN_RECEIVED, data_acked--\n", __func__, __LINE__);
			break;

		// TODO: handle FIN as well.
		default:
			break;
		}

	debug("%s.%d. data_acked is -ve?\n", __func__, __LINE__);
		assert(data_acked >= 0);

#ifndef NDEBUG
		int32_t bufused = seqdiff(c->snd.last, c->snd.una);
		assert(data_acked <= bufused);
#endif

	debug("%s.%d. if data_acked\n", __func__, __LINE__);
		if(data_acked) {
	debug("%s.%d. discard send buffer, data acked\n", __func__, __LINE__);
			buffer_get(&c->sndbuf, NULL, data_acked);
		}

		// Also advance snd.nxt if possible
	debug("%s.%d. Also advance snd.nxt if possible\n", __func__, __LINE__);
		if(seqdiff(c->snd.nxt, hdr.ack) < 0) {
	debug("%s.%d. send next with ack header\n", __func__, __LINE__);
			c->snd.nxt = hdr.ack;
	debug("%s.%d. send next with ack header is set to the connection\n", __func__, __LINE__);
		}

	debug("%s.%d. send next with ack header\n", __func__, __LINE__);
		c->snd.una = hdr.ack;

		c->dupack = 0;
		c->snd.cwnd += utcp->mtu;

		if(c->snd.cwnd > c->sndbuf.maxsize) {
	debug("%s.%d. Set send cwnd to max size\n", __func__, __LINE__);
			c->snd.cwnd = c->sndbuf.maxsize;
		}
	debug("%s.%d. Print cwnd\n", __func__, __LINE__);

		// Check if we have sent a FIN that is now ACKed.
	debug("%s.%d. Check if we have sent a FIN that is now ACKed\n", __func__, __LINE__);
		switch(c->state) {
		case FIN_WAIT_1:
	debug("%s.%d. If connetion state is FIN_WAIT_1\n", __func__, __LINE__);
			if(c->snd.una == c->snd.last) {
	debug("%s.%d. Set connection state to FIN_WAIT_2\n", __func__, __LINE__);
				set_state(c, FIN_WAIT_2);
			}
	debug("%s.%d. Case FIN_WAIT_1 break\n", __func__, __LINE__);

			break;

		case CLOSING:
	debug("%s.%d. If connetion state is CLOSING\n", __func__, __LINE__);
			if(c->snd.una == c->snd.last) {
				gettimeofday(&c->conn_timeout, NULL);
				c->conn_timeout.tv_sec += utcp->timeout;
	debug("%s.%d. Set connection state to TIME_WAIT\n", __func__, __LINE__);
				set_state(c, TIME_WAIT);
			}
	debug("%s.%d. Case CLOSING break\n", __func__, __LINE__);

			break;

		default:
			break;
		}
	debug("%s.%d. Validated if we have sent a FIN that is now ACKed\n", __func__, __LINE__);
	} else {
	debug("%s.%d. If not advanced\n", __func__, __LINE__);
		if(!len && is_reliable(c)) {
			c->dupack++;
			debug("duplicate ACK %d\n", c->dupack);

			if(c->dupack == 3) {
				debug("Triplicate ACK\n");
				//TODO: Resend one packet and go to fast recovery mode. See RFC 6582.
				//We do a very simple variant here; reset the nxt pointer to the last acknowledged packet from the peer.
				//Reset the congestion window so we wait for ACKs.
				c->snd.nxt = c->snd.una;
				c->snd.cwnd = utcp->mtu;
				start_retransmit_timer(c);
			}
		}
	debug("%s.%d. Else advanced end\n", __func__, __LINE__);
	}

	// 4. Update timers

	debug("%s.%d. Update timers\n", __func__, __LINE__);
	if(advanced) {
	debug("%s.%d. If advanced\n", __func__, __LINE__);
		if(c->snd.una == c->snd.last) {
	debug("%s.%d. Stop retransmit timer\n", __func__, __LINE__);
			stop_retransmit_timer(c);
			timerclear(&c->conn_timeout);
		} else if(is_reliable(c)) {
	debug("%s.%d. Else if connection is reliable\n", __func__, __LINE__);
			start_retransmit_timer(c);
			gettimeofday(&c->conn_timeout, NULL);
			c->conn_timeout.tv_sec += utcp->timeout;
	debug("%s.%d. Increased connection timeout by utcp timeout\n", __func__, __LINE__);
		}
	}
	debug("%s.%d. Updated timers\n", __func__, __LINE__);

skip_ack:
	// 5. Process SYN stuff

	debug("%s.%d. Process SYN stuff\n", __func__, __LINE__);
	if(hdr.ctl & SYN) {
		switch(c->state) {
		case SYN_SENT:

			// This is a SYNACK. It should always have ACKed the SYN.
	debug("%s.%d. This is a SYNACK. It should always have ACKed the SYN.\n", __func__, __LINE__);
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
	debug("%s.%d. Setting the state is done\n", __func__, __LINE__);

			// TODO: notify application of this somehow.
			break;

		case SYN_RECEIVED:
			// This is a retransmit of a SYN, send back the SYNACK.
	debug("%s.%d. This is a retransmit of a SYN, send back the SYNACK.\n", __func__, __LINE__);
			goto synack;

		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// Ehm, no. We should never receive a second SYN.
	debug("%s.%d. Ehm, no. We should never receive a second SYN.\n", __func__, __LINE__);
			return 0;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;
		}

		// SYN counts as one sequence number
	debug("%s.%d. SYN counts as one sequence number\n", __func__, __LINE__);
		c->rcv.nxt++;
	}

	// 6. Process new data

	debug("%s.%d. Process new data\n", __func__, __LINE__);
	if(c->state == SYN_RECEIVED) {
		// This is the ACK after the SYNACK. It should always have ACKed the SYNACK.
	debug("%s.%d. This is the ACK after the SYNACK. It should always have ACKed the SYNACK.\n", __func__, __LINE__);
		if(!advanced) {
	debug("%s.%d. If not advaced reset\n", __func__, __LINE__);
			goto reset;
		}

		// Are we still LISTENing?
	debug("%s.%d. Are we still LISTENing?\n", __func__, __LINE__);
		if(utcp->accept) {
	debug("%s.%d. Invoke accept cb\n", __func__, __LINE__);
			utcp->accept(c, c->src);
		}

	debug("%s.%d. If not established then close\n", __func__, __LINE__);
		if(c->state != ESTABLISHED) {
			set_state(c, CLOSED);
			c->reapable = true;
	debug("%s.%d. reap and reaset after close\n", __func__, __LINE__);
			goto reset;
		}
	}

	debug("%s.%d. if len != 0\n", __func__, __LINE__);
	if(len) {
		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
			// This should never happen.
	debug("%s.%d. This should never happe\n", __func__, __LINE__);
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;

		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
	debug("%s.%d. estd, finwait1,2\n", __func__, __LINE__);
			break;

		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// Ehm no, We should never receive more data after a FIN.
	debug("%s.%d. Ehm no, We should never receive more data after a FIN, reset\n", __func__, __LINE__);
			goto reset;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;
		}

	debug("%s.%d. Handle inoming data\n", __func__, __LINE__);
		handle_incoming_data(c, hdr.seq, ptr, len);
	}

	// 7. Process FIN stuff

	debug("%s.%d. Process FIN stuff\n", __func__, __LINE__);
	if((hdr.ctl & FIN) && (!is_reliable(c) || hdr.seq + len == c->rcv.nxt)) {
	debug("%s.%d. Swith state\n", __func__, __LINE__);
		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
			// This should never happen.
	debug("%s.%d. This should never happe\n", __func__, __LINE__);
#ifdef UTCP_DEBUG
			abort();
#endif
			break;

		case ESTABLISHED:
	debug("%s.%d. Ested, set state to close wait\n", __func__, __LINE__);
			set_state(c, CLOSE_WAIT);
			break;

		case FIN_WAIT_1:
	debug("%s.%d. set state to closing\n", __func__, __LINE__);
			set_state(c, CLOSING);
			break;

		case FIN_WAIT_2:
			gettimeofday(&c->conn_timeout, NULL);
			c->conn_timeout.tv_sec += utcp->timeout;
			set_state(c, TIME_WAIT);
	debug("%s.%d. Set state to TIME WAIT\n", __func__, __LINE__);
			break;

		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
	debug("%s.%d. CLOSE_WAIT, CLOSE_WAIT, LAST_ACK and TIME_WAIT go reset\n", __func__, __LINE__);
			// Ehm, no. We should never receive a second FIN.
			goto reset;

		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			break;
		}

		// FIN counts as one sequence number
	debug("%s.%d. FIN counts as one sequence number\n", __func__, __LINE__);
		c->rcv.nxt++;
		len++;

		// Inform the application that the peer closed its end of the connection.
	debug("%s.%d. Inform the application that the peer closed its end of the connection\n", __func__, __LINE__);
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

	debug("%s.%d. send seomething back if possible\n", __func__, __LINE__);
	if(is_reliable(c) || hdr.ctl & SYN || hdr.ctl & FIN) {
		ack(c, has_data);
	}

	debug("%s.%d. Done\n", __func__, __LINE__);
	return 0;

reset:
	debug("%s.%d. Start reset\n", __func__, __LINE__);
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

	print_packet(utcp, "send", &hdr, sizeof(hdr));
	utcp->send(utcp, &hdr, sizeof(hdr));
	debug("%s.%d. reset done\n", __func__, __LINE__);
	return 0;

}

int utcp_shutdown(struct utcp_connection *c, int dir) {
	debug("%p shutdown %d at %u\n", c ? c->utcp : NULL, dir, c ? c->snd.last : 0);

	if(!c) {
		errno = EFAULT;
		return -1;
	}

	if(c->reapable) {
		debug("Error: shutdown() called on closed connection %p\n", c);
		errno = EBADF;
		return -1;
	}

	if(!(dir == UTCP_SHUT_RD || dir == UTCP_SHUT_WR || dir == UTCP_SHUT_RDWR)) {
	debug("%s.%d. invalid\n", __func__, __LINE__);
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
	debug("%s.%d. UTCP_SHUT_RD\n", __func__, __LINE__);
		return 0;
	}

	// Only process shutting down writes once.
	if(c->shut_wr) {
	debug("%s.%d. Only process shutting down writes once\n", __func__, __LINE__);
		return 0;
	}

	c->shut_wr = true;

	switch(c->state) {
	case CLOSED:
	case LISTEN:
		errno = ENOTCONN;
	debug("%s.%d. ENOTCONN\n", __func__, __LINE__);
		return -1;

	case SYN_SENT:
	debug("%s.%d. SYN_SENT\n", __func__, __LINE__);
		return 0;

	case SYN_RECEIVED:
	case ESTABLISHED:
		set_state(c, FIN_WAIT_1);
		break;

	case FIN_WAIT_1:
	case FIN_WAIT_2:
	debug("%s.%d. FIN_WAIT\n", __func__, __LINE__);
		return 0;

	case CLOSE_WAIT:
		set_state(c, CLOSING);
		break;

	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
	debug("%s.%d. Closing, last ack, time_wait\n", __func__, __LINE__);
		return 0;
	}

	c->snd.last++;

	ack(c, false);

	if(!timerisset(&c->rtrx_timeout)) {
		start_retransmit_timer(c);
	}

	debug("%s.%d. Done\n", __func__, __LINE__);
	return 0;
}

static bool reset_connection(struct utcp_connection *c) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	if(!c) {
		errno = EFAULT;
	debug("%s.%d. EFAULT\n", __func__, __LINE__);
		return false;
	}

	if(c->reapable) {
		debug("Error: abort() called on closed connection %p\n", c);
		errno = EBADF;
		return false;
	}

	c->recv = NULL;
	c->poll = NULL;

	switch(c->state) {
	case CLOSED:
	debug("%s.%d. Closed \n", __func__, __LINE__);
		return true;

	case LISTEN:
	case SYN_SENT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		set_state(c, CLOSED);
	debug("%s.%d. Closed\n", __func__, __LINE__);
		return true;

	case SYN_RECEIVED:
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSE_WAIT:
		set_state(c, CLOSED);
	debug("%s.%d. Closed\n", __func__, __LINE__);
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

	print_packet(c->utcp, "send", &hdr, sizeof(hdr));
	c->utcp->send(c->utcp, &hdr, sizeof(hdr));
	debug("%s.%d. Done\n", __func__, __LINE__);
	return true;
}

// Closes all the opened connections
void utcp_abort_all_connections(struct utcp *utcp) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	if(!utcp) {
	debug("%s.%d. Invalid\n", __func__, __LINE__);
		errno = EINVAL;
		return;
	}

	debug("%s.%d. loop connections\n", __func__, __LINE__);
	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

	debug("%s.%d. Continue if closed or reaped\n", __func__, __LINE__);
		if(c->reapable || c->state == CLOSED) {
			continue;
		}

		utcp_recv_t old_recv = c->recv;
		utcp_poll_t old_poll = c->poll;

	debug("%s.%d. reset connection\n", __func__, __LINE__);
		reset_connection(c);

		if(old_recv) {
			errno = 0;
	debug("%s.%d. old recv\n", __func__, __LINE__);
			old_recv(c, NULL, 0);
		}

		if(old_poll && !c->reapable) {
			errno = 0;
	debug("%s.%d. old poll 0\n", __func__, __LINE__);
			old_poll(c, 0);
		}
	}

	debug("%s.%d. Done\n", __func__, __LINE__);
	return;
}

int utcp_close(struct utcp_connection *c) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	if(utcp_shutdown(c, SHUT_RDWR) && errno != ENOTCONN) {
	debug("%s.%d. utcp_shutdown\n", __func__, __LINE__);
		return -1;
	}

	c->recv = NULL;
	c->poll = NULL;
	c->reapable = true;
	debug("%s.%d. Reset and reap the connection\n", __func__, __LINE__);
	return 0;
}

int utcp_abort(struct utcp_connection *c) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	if(!reset_connection(c)) {
	debug("%s.%d. reset connection failed\n", __func__, __LINE__);
		return -1;
	}

	c->reapable = true;
	debug("%s.%d. done\n", __func__, __LINE__);
	return 0;
}

/* Handle timeouts.
 * One call to this function will loop through all connections,
 * checking if something needs to be resent or not.
 * The return value is the time to the next timeout in milliseconds,
 * or maybe a negative value if the timeout is infinite.
 */
struct timeval utcp_timeout(struct utcp *utcp) {
	struct timeval now;
	gettimeofday(&now, NULL);
	struct timeval next = {now.tv_sec + 3600, now.tv_usec};

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(!c) {
			continue;
		}

		// delete connections that have been utcp_close()d.
		if(c->state == CLOSED) {
			if(c->reapable) {
				debug("Reaping %p\n", c);
				free_connection(c);
				i--;
			}

			continue;
		}

		if(timerisset(&c->conn_timeout) && timercmp(&c->conn_timeout, &now, <)) {
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

		if(timerisset(&c->rtrx_timeout) && timercmp(&c->rtrx_timeout, &now, <)) {
			debug("retransmit()\n");
			retransmit(c);
		}

		if(c->poll) {
			if((c->state == ESTABLISHED || c->state == CLOSE_WAIT)) {
				uint32_t len =  buffer_free(&c->sndbuf);

				if(len) {
					c->poll(c, len);
				}
			} else if(c->state == CLOSED) {
				c->poll(c, 0);
			}
		}

		if(timerisset(&c->conn_timeout) && timercmp(&c->conn_timeout, &next, <)) {
			next = c->conn_timeout;
		}

		if(timerisset(&c->rtrx_timeout) && timercmp(&c->rtrx_timeout, &next, <)) {
			next = c->rtrx_timeout;
		}
	}

	struct timeval diff;

	timersub(&next, &now, &diff);

	return diff;
}

bool utcp_is_active(struct utcp *utcp) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	if(!utcp) {
	debug("%s.%d. invalid\n", __func__, __LINE__);
		return false;
	}

	debug("%s.%d. Loop connctions\n", __func__, __LINE__);
	for(int i = 0; i < utcp->nconnections; i++)
		if(utcp->connections[i]->state != CLOSED && utcp->connections[i]->state != TIME_WAIT) {
	debug("%s.%d. active\n", __func__, __LINE__);
			return true;
		}

	return false;
}

struct utcp *utcp_init(utcp_accept_t accept, utcp_pre_accept_t pre_accept, utcp_send_t send, void *priv) {
	if(!send) {
		errno = EFAULT;
		return NULL;
	}

	struct utcp *utcp = calloc(1, sizeof(*utcp));

	if(!utcp) {
		return NULL;
	}

	utcp->accept = accept;
	utcp->pre_accept = pre_accept;
	utcp->send = send;
	utcp->priv = priv;
	utcp->mtu = DEFAULT_MTU;
	utcp->timeout = DEFAULT_USER_TIMEOUT; // sec
	utcp->rto = START_RTO; // usec

	return utcp;
}

void utcp_exit(struct utcp *utcp) {
	if(!utcp) {
		return;
	}

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(!c->reapable) {
			if(c->recv) {
				c->recv(c, NULL, 0);
			}

			if(c->poll && !c->reapable) {
				c->poll(c, 0);
			}
		}

		buffer_exit(&c->rcvbuf);
		buffer_exit(&c->sndbuf);
		free(c);
	}

	free(utcp->connections);
	free(utcp);
}

uint16_t utcp_get_mtu(struct utcp *utcp) {
	return utcp ? utcp->mtu : 0;
}

void utcp_set_mtu(struct utcp *utcp, uint16_t mtu) {
	// TODO: handle overhead of the header
	if(utcp) {
		utcp->mtu = mtu;
	}
}

void utcp_reset_timers(struct utcp *utcp) {
	if(!utcp) {
		return;
	}

	struct timeval now, then;

	gettimeofday(&now, NULL);

	then = now;

	then.tv_sec += utcp->timeout;

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(c->reapable) {
			continue;
		}

		if(timerisset(&c->rtrx_timeout)) {
			c->rtrx_timeout = now;
		}

		if(timerisset(&c->conn_timeout)) {
			c->conn_timeout = then;
		}

		c->rtt_start.tv_sec = 0;
	}

	if(utcp->rto > START_RTO) {
		utcp->rto = START_RTO;
	}
	debug("%s.%d. Done\n", __func__, __LINE__);
}

int utcp_get_user_timeout(struct utcp *u) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	return u ? u->timeout : 0;
}

void utcp_set_user_timeout(struct utcp *u, int timeout) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(u) {
		u->timeout = timeout;
	}
}

size_t utcp_get_sndbuf(struct utcp_connection *c) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	return c ? c->sndbuf.maxsize : 0;
}

size_t utcp_get_sndbuf_free(struct utcp_connection *c) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(!c) {
	debug("%s.%d. faulty\n", __func__, __LINE__);
		return 0;
	}

	debug("%s.%d. Switch to state\n", __func__, __LINE__);
	switch(c->state) {
	case SYN_SENT:
	case SYN_RECEIVED:
	case ESTABLISHED:
	case CLOSE_WAIT:
	debug("%s.%d. free buffer\n", __func__, __LINE__);
		return buffer_free(&c->sndbuf);

	default:
	debug("%s.%d. defaylt\n", __func__, __LINE__);
		return 0;
	}
	debug("%s.%d. Done\n", __func__, __LINE__);
}

void utcp_set_sndbuf(struct utcp_connection *c, size_t size) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(!c) {
	debug("%s.%d. Faulty\n", __func__, __LINE__);
		return;
	}

	c->sndbuf.maxsize = size;

	if(c->sndbuf.maxsize != size) {
		c->sndbuf.maxsize = -1;
	}
}

size_t utcp_get_rcvbuf(struct utcp_connection *c) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	return c ? c->rcvbuf.maxsize : 0;
}

size_t utcp_get_rcvbuf_free(struct utcp_connection *c) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(c && (c->state == ESTABLISHED || c->state == CLOSE_WAIT)) {
	debug("%s.%d. buffer freeing\n", __func__, __LINE__);
		return buffer_free(&c->rcvbuf);
	} else {
	debug("%s.%d. ret 0\n", __func__, __LINE__);
		return 0;
	}
	debug("%s.%d. Done\n", __func__, __LINE__);
}

void utcp_set_rcvbuf(struct utcp_connection *c, size_t size) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(!c) {
		return;
	}

	c->rcvbuf.maxsize = size;

	if(c->rcvbuf.maxsize != size) {
		c->rcvbuf.maxsize = -1;
	}
	debug("%s.%d. Done\n", __func__, __LINE__);
}

size_t utcp_get_sendq(struct utcp_connection *c) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	return c->sndbuf.used;
}

size_t utcp_get_recvq(struct utcp_connection *c) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	return c->rcvbuf.used;
}

bool utcp_get_nodelay(struct utcp_connection *c) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	return c ? c->nodelay : false;
}

void utcp_set_nodelay(struct utcp_connection *c, bool nodelay) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(c) {
		c->nodelay = nodelay;
	}
}

bool utcp_get_keepalive(struct utcp_connection *c) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	return c ? c->keepalive : false;
}

void utcp_set_keepalive(struct utcp_connection *c, bool keepalive) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(c) {
		c->keepalive = keepalive;
	}
}

size_t utcp_get_outq(struct utcp_connection *c) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	return c ? seqdiff(c->snd.nxt, c->snd.una) : 0;
}

void utcp_set_recv_cb(struct utcp_connection *c, utcp_recv_t recv) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(c) {
		c->recv = recv;
	}
}

void utcp_set_poll_cb(struct utcp_connection *c, utcp_poll_t poll) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	if(c) {
		c->poll = poll;
	}
	debug("%s.%d. Done\n", __func__, __LINE__);
}

void utcp_set_accept_cb(struct utcp *utcp, utcp_accept_t accept, utcp_pre_accept_t pre_accept) {
	debug("%s.%d. Called\n", __func__, __LINE__);
	if(utcp) {
		utcp->accept = accept;
		utcp->pre_accept = pre_accept;
	}
	debug("%s.%d. Done\n", __func__, __LINE__);
}

void utcp_expect_data(struct utcp_connection *c, bool expect) {
	debug("%s.%d. Started\n", __func__, __LINE__);
	if(!c || c->reapable) {
		return;
	}

	if(!(c->state == ESTABLISHED || c->state == FIN_WAIT_1 || c->state == FIN_WAIT_2)) {
		return;
	}

	if(expect) {
		// If we expect data, start the connection timer.
		if(!timerisset(&c->conn_timeout)) {
			gettimeofday(&c->conn_timeout, NULL);
			c->conn_timeout.tv_sec += c->utcp->timeout;
		}
	} else {
		// If we want to cancel expecting data, only clear the timer when there is no unACKed data.
		if(c->snd.una == c->snd.last) {
			timerclear(&c->conn_timeout);
		}
	}
	debug("%s.%d. Done\n", __func__, __LINE__);
}

void utcp_offline(struct utcp *utcp, bool offline) {
	struct timeval now;
	gettimeofday(&now, NULL);

	debug("%s.%d. loop connections\n", __func__, __LINE__);
	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];

		if(c->reapable) {
	debug("%s.%d. closed or reaped connection\n", __func__, __LINE__);
			continue;
		}

	debug("%s.%d. utcp_expect_data\n", __func__, __LINE__);
		utcp_expect_data(c, offline);

	debug("%s.%d. if not offline\n", __func__, __LINE__);
		if(!offline) {
	debug("%s.%d. if rtrx_timeout timount is set\n", __func__, __LINE__);
			if(timerisset(&c->rtrx_timeout)) {
				c->rtrx_timeout = now;
			}

	debug("%s.%d. rtt_start = 0\n", __func__, __LINE__);
			utcp->connections[i]->rtt_start.tv_sec = 0;
		}
	}

	if(!offline && utcp->rto > START_RTO) {
		utcp->rto = START_RTO;
	}
	debug("%s.%d. Done\n", __func__, __LINE__);
}
