/**
 * Copyright(c) 2019, Tessares S.A.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and / or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *        SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *        OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <libsyscall_intercept_hook_point.h>
#include <log.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "convert.h"
#include "convert_util.h"
#include "bsd_queue.h"

#define CONVERT_PORT 1234

/* The hook function registered in libsyscall_intercept must return either
 * of the following value. */
enum {
	/* Tell the library that the default syscall is skipped. */
	SYSCALL_SKIP	= 0,
	/* The the library that the default syscall must be called. */
	SYSCALL_RUN	= 1,
};

/* State for each created TCP-based socket */
typedef struct socket_state {
	LIST_ENTRY(socket_state) list;
	int	fd;
	int	established;
} socket_state_t;

#define NUM_BUCKETS 1024
static LIST_HEAD(, socket_state) _socket_htable[NUM_BUCKETS];
/* note: global hash table mutex, improvement: lock per bucket */
static pthread_mutex_t _socket_htable_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct in_addr	_convert_addr4;
static struct in6_addr	_convert_addr6;
static uint16_t		_convert_port = CONVERT_PORT;

static FILE *		_log;
static pthread_mutex_t	_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static int
_hash(int fd)
{
	return fd % NUM_BUCKETS;
}

static socket_state_t *
_lookup(int fd)
{
	int		hash = _hash(fd);
	socket_state_t *state;
	socket_state_t *ret = NULL;

	pthread_mutex_lock(&_socket_htable_mutex);
	LIST_FOREACH (state, &_socket_htable[hash], list) {
		if (state->fd == fd) {
			ret = state;
			break;
		}
	}
	pthread_mutex_unlock(&_socket_htable_mutex);
	return ret;
}

static void
_alloc(int fd)
{
	socket_state_t *state;
	int		hash = _hash(fd);

	state = (socket_state_t *)malloc(sizeof(*state));
	if (!state)
		return;

	log_debug("allocate state for fd %d", fd);

	state->fd = fd;

	pthread_mutex_lock(&_socket_htable_mutex);
	LIST_INSERT_HEAD(&_socket_htable[hash], state, list);
	pthread_mutex_unlock(&_socket_htable_mutex);
}

static void
_free_state(socket_state_t *state)
{
	pthread_mutex_lock(&_socket_htable_mutex);
	LIST_REMOVE(state, list);
	pthread_mutex_unlock(&_socket_htable_mutex);

	free(state);
}

static void
_free(int fd)
{
	socket_state_t *state;

	state = _lookup(fd);
	if (!state)
		/* no state associated with this fd. */
		return;

	log_debug("release state for fd %d", fd);

	_free_state(state);
}

static void
_to_v4mapped(in_addr_t from, struct in6_addr *to)
{
	*to = (struct in6_addr) {
		.s6_addr32 = {
			0, 0, htonl(0xffff), from,
		},
	};
}

static ssize_t
_redirect_connect_tlv(uint8_t *buf, size_t buf_len, struct sockaddr *addr)
{
	ssize_t			ret;
	struct convert_opts	opts = { 0 };

	opts.flags = CONVERT_F_CONNECT;

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *in = (struct sockaddr_in *)addr;

		/* already in network bytes */
		_to_v4mapped(in->sin_addr.s_addr, &opts.remote_addr);
		opts.remote_port = in->sin_port;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;

		/* already in network bytes */
		memcpy(&opts.remote_addr, &in6->sin6_addr,
		       sizeof(opts.remote_addr));
		opts.remote_port = in6->sin6_port;
		break;
	}
	default:
		return -EAFNOSUPPORT;
	}

	ret = convert_write(buf, buf_len, &opts);
	if (ret < 0) {
		log_error("unable to allocate the convert header");
		ret = -EOPNOTSUPP;
	}
	return ret;
}

static int
_redirect(socket_state_t *state, struct sockaddr *addr, socklen_t addr_len,
          struct sockaddr *dest)
{
	uint8_t buf[1024];
	ssize_t len;

	len = _redirect_connect_tlv(buf, sizeof(buf), dest);

	if (len < 0)
		return len;

	return syscall_no_intercept(SYS_sendto, state->fd, buf, len,
	                            MSG_FASTOPEN, addr, addr_len);
}

static int
_redirect4(socket_state_t *state, struct sockaddr *dest)
{
	struct sockaddr_in addr =
	{
		.sin_family	= AF_INET,
		.sin_port	= htons(_convert_port),
		.sin_addr	= _convert_addr4,
	};

	return _redirect(state, (struct sockaddr *)&addr, sizeof(addr), dest);
}

static int
_redirect6(socket_state_t *state, struct sockaddr *dest)
{
	struct sockaddr_in6 addr =
	{
		.sin6_family	= AF_INET6,
		.sin6_port	= htons(_convert_port),
		.sin6_addr	= _convert_addr6,
	};

	return _redirect(state, (struct sockaddr *)&addr, sizeof(addr), dest);
}

static int
_handle_socket(long arg0, long arg1, long arg2, long *result)
{
	/* Only consider TCP-based sockets. */
	if (((arg0 == AF_INET) || (arg0 == AF_INET6)) && (arg1 == SOCK_STREAM)) {
		log_debug("handle socket(%ld, %ld, %ld)", arg0, arg1, arg2);

		/* execute the socket() syscall to learn the file descriptor */
		*result = syscall_no_intercept(SYS_socket, arg0, arg1, arg2);

		log_debug("-> fd: %d", (int)*result);

		if (*result >= 0)
			_alloc((int)*result);

		/* skip as we executed the syscall ourself. */
		return SYSCALL_SKIP;
	}
	return SYSCALL_RUN;
}

static int
_handle_connect(long arg0, long arg1, long arg2, long *result)
{
	socket_state_t *	state;
	struct sockaddr *	dest	= (struct sockaddr *)arg1;
	int			fd	= (int)arg0;

	state = _lookup(fd);
	if (!state)
		return SYSCALL_RUN;

	log_debug("redirecting fd %d", fd);

	switch (dest->sa_family) {
	case AF_INET:
		*result = _redirect4(state, dest);
		break;
	case AF_INET6:
		*result = _redirect6(state, dest);
		break;
	default:
		log_warn("fd %d specified an invalid address family %d", fd,
		         dest->sa_family);
		goto error;
	}

	if (*result >= 0) {
		log_debug("redirection of fd %d in progress", fd);
		return SYSCALL_SKIP;
	}

	log_warn("the redirection of fd %d failed with error: %d", fd, *result);

	/* If the redirection failed during the connect() there are no benefit to
	 * keep the allocated state. Clear it and behave like we never handled
	 * that file descriptor.
	 */
error:
	_free_state(state);
	return SYSCALL_RUN;
}

static int
_handle_close(long fd)
{
	/* free any state created. */
	_free((int)fd);

	return SYSCALL_RUN;
}

#define CONVERT_HDR_LEN sizeof(struct convert_header)

static int
_read_convert(socket_state_t *state, long *result)
{
	uint8_t hdr[CONVERT_HDR_LEN];
	int	ret;
	size_t	length;

	log_debug("peek fd %d to see whether data is in the receive "
	          "queue", state->fd);

	ret = syscall_no_intercept(SYS_recvfrom, state->fd, hdr,
	                           CONVERT_HDR_LEN,
	                           MSG_WAITALL, NULL, NULL);

	log_debug("peek returned %d", ret);
	if (ret < 0) {
		/* In case of error we want to skip the actual call.
		 * Moreover, if return EAGAIN (non-blocking) we don't
		 * want to app to receive the buffer.
		 */
		*result = ret;
		goto skip;
	}

	if (convert_parse_header(hdr, ret, &length) < 0) {
		log_error("[%d] unable to read the convert header",
		          state->fd);
		goto error;
	}

	if (length) {
		uint8_t			buffer[length];
		struct convert_opts	opts;

		ret = syscall_no_intercept(SYS_recvfrom, state->fd,
		                           buffer, length, MSG_WAITALL,
		                           NULL, NULL);
		if (ret != (int)length || ret < 0) {
			log_error("[%d] unable to read the convert"
			          " tlvs", state->fd);
			goto error;
		}

		ret = convert_parse_tlvs(buffer, length, &opts);
		if (ret < 0)
			goto error;

		/* if we receive the TLV error we need to inform the app */
		if (opts.flags & CONVERT_F_ERROR) {
			log_info("received TLV error: %u", opts.error_code);
			goto error;
		}
	}

	/* everything was fine : free the state */
	_free_state(state);

	return SYSCALL_RUN;

skip:
	return SYSCALL_SKIP;

error:
	log_debug("return -ECONNREFUSED");
	*result = -ECONNREFUSED;
	_free_state(state);
	goto skip;
}
static int
_handle_recv(long arg0, long *result)
{
	int		fd = (int)arg0;
	socket_state_t *state;

	state = _lookup(fd);
	if (!state)
		return SYSCALL_RUN;

	return _read_convert(state, result);
}

static int
_hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4,
      long arg5, long *result)
{
	switch (syscall_number) {
	case SYS_socket:
		return _handle_socket(arg0, arg1, arg2, result);
	case SYS_connect:
		return _handle_connect(arg0, arg1, arg2, result);
	case SYS_close:
		return _handle_close(arg0);
	case SYS_recvfrom:
		return _handle_recv(arg0, result);
	default:
		/* The default behavior is to run the default syscall. */
		return SYSCALL_RUN;
	}
}

static int
_read_sysctl_fastopen(unsigned int *flags, char *err_buf, size_t len)
{
	int	fd;
	int	rc;
	char	buffer[1024];
	char *	endp;

	fd = open("/proc/sys/net/ipv4/tcp_fastopen", O_RDONLY);
	if (fd < 0) {
		snprintf(err_buf, len,
		         "unable to open /proc/sys/net/ipv4/tcp_fastopen: %s",
		         strerror(errno));
		return fd;
	}

	rc = read(fd, buffer, sizeof(buffer));
	close(fd);

	if (rc < 0) {
		snprintf(err_buf, len,
		         "unable to read /proc/sys/net/ipv4/tcp_fastopen: %s",
		         strerror(errno));
		return rc;
	}

	/* contains a base 10 number */
	*flags = strtol(buffer, &endp, 10);

	if (*endp && *endp != '\n') {
		snprintf(err_buf, len,
		         "unable to parse /proc/sys/net/ipv4/tcp_fastopen");
		return -1;
	}

	return 0;
}

static int
_validate_sysctl_fastopen(char *err_buf, size_t len)
{
	unsigned int	flags		= 0;
	unsigned int	expected_flags	= (0x1 | 0x4);

	if (_read_sysctl_fastopen(&flags, err_buf, len) < 0)
		return -1;

	/* We use the fastopen backend without requiring exchange of actual
	 * fastopen options. expected_flags are: 0x1 (sending data in SYN) and
	 * 0x4 (regardless of cookie availability and without a cookie option).
	 */
	if ((flags & expected_flags) != expected_flags) {
		snprintf(err_buf, len,
		         "the sysctl tcp_fastopen has an inappropriate value. Expect %x got %x.", expected_flags,
		         flags);
		return -1;
	}

	log_debug("fastopen sysctl is %x, expect flags %x to be set", flags,
	          expected_flags);


	return 0;
}

static void
_set_convert_addr(struct hostent *host, int type, void *buf, size_t buf_len)
{
	if (host->h_addr_list[0])
		memcpy(buf, host->h_addr_list[0], buf_len);
}

static int
_validate_and_set_conver_addr_num(const char *name)
{
	struct addrinfo *	ai;
	int			ret;

	ret = getaddrinfo(name, NULL, NULL, &ai);
	if (ret < 0)
		return ret;

	/* name is an IP address */
	switch (ai->ai_family) {
	case AF_INET:
		_convert_addr4 = ((struct sockaddr_in *)ai->ai_addr)->sin_addr;
		break;
	case AF_INET6:
		memcpy(&_convert_addr6,
		       &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
		       sizeof(_convert_addr6));
		break;
	default:
		return -1;
	}

	freeaddrinfo(ai);
	return 0;
}


static int
_validate_and_set_convert_addr(const char *name)
{
	struct hostent *host;
	int		count = 0;
	char		addr_str[INET6_ADDRSTRLEN];

	if (_validate_and_set_conver_addr_num(name) == 0)
		return 0;

	host = gethostbyname2(name, AF_INET);
	if (!host)
		goto inet6;

	_set_convert_addr(host, AF_INET, &_convert_addr4,
	                  sizeof(_convert_addr4));

	inet_ntop(AF_INET, &_convert_addr4, addr_str, sizeof(addr_str));
	log_info("using convert address: %s for ipv4 connections", addr_str);

	count++;

inet6:
	host = gethostbyname2(name, AF_INET6);
	if (!host)
		goto exit;

	_set_convert_addr(host, AF_INET6, &_convert_addr6,
	                  sizeof(_convert_addr6));

	inet_ntop(AF_INET6, &_convert_addr6, addr_str, sizeof(addr_str));
	log_info("using convert address: %s for ipv6 connections", addr_str);

	count++;

exit:
	return count ? 0 : -1;
}

static int
_validate_parameters(char *err_buf, size_t len)
{
	const char *	convert_addr	= getenv("CONVERT_ADDR");
	const char *	convert_port	= getenv("CONVERT_PORT");

	if (!convert_addr) {
		snprintf(err_buf, len,
		         "environment variable 'CONVERT_ADDR' missing");
		return -1;
	}

	/* resolve address */
	if (_validate_and_set_convert_addr(convert_addr) < 0) {
		snprintf(err_buf, len, "unable to resolve '%s'", convert_addr);
		return -1;
	}

	/* set port */
	if (convert_port) {
		char *		endp;
		uint16_t	port;

		/* contains a base 10 number */
		port = strtol(convert_port, &endp, 10);

		if (*endp && *endp != '\n')
			log_warn(
			        "unable to parse port: %s. Falling back to default port.",
			        convert_port);
		else
			_convert_port = port;
	}

	log_info("using port %zu to connect to the convert service",
	         _convert_port);

	return 0;
}

static int
_validate_config(char *err_buf, size_t len)
{
	int ret = 0;

	ret = _validate_sysctl_fastopen(err_buf, len);
	if (ret < 0)
		return ret;

	return _validate_parameters(err_buf, len);
}

static void
_log_lock(void *udata, int lock)
{
	if (lock)
		pthread_mutex_lock(&_log_mutex);
	else
		pthread_mutex_unlock(&_log_mutex);
}

static __attribute__((constructor)) void
init(void)
{
	char		err_buf[1024];
	const char *	log_path = getenv("CONVERT_LOG");

	log_set_quiet(1);
	log_set_lock(_log_lock);

	/* open the log iff specified */
	if (log_path) {
		_log = fopen(log_path, "w");
		if (!_log)
			fprintf(stderr, "convert: unable to open log %s: %s",
			        log_path, strerror(errno));
		log_set_fp(_log);
	}

	log_info("Starting interception");

	if (_validate_config(err_buf, sizeof(err_buf)) < 0)
		log_error("Unable to setup connection interception: %s.",
		          err_buf);
	else
		/* Set up the callback function */
		intercept_hook_point = _hook;
}

static __attribute__((destructor)) void
fini(void)
{
	log_info("Terminating interception");
	if (_log)
		fclose(_log);
}
