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

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "bsd_queue.h"

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
	int fd;
} socket_state_t;

#define NUM_BUCKETS 1024
static LIST_HEAD(, socket_state) _socket_htable[NUM_BUCKETS];
/* note: global hash table mutex, improvement: lock per bucket */
static pthread_mutex_t _socket_htable_mutex = PTHREAD_MUTEX_INITIALIZER;

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
_free(int fd)
{
	socket_state_t *state;

	state = _lookup(fd);
	if (!state)
		/* no state associated with this fd. */
		return;

	log_debug("release state for fd %d", fd);

	pthread_mutex_lock(&_socket_htable_mutex);
	LIST_REMOVE(state, list);
	pthread_mutex_unlock(&_socket_htable_mutex);

	free(state);
}


static int
_handle_socket(long arg0, long arg1, long arg2, long *result)
{
	/* Only consider TCP-based sockets. */
	if (((arg0 == AF_INET) || (arg0 == AF_INET6)) && (arg1 == SOCK_STREAM)) {
		int fd;

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
_handle_close(long fd)
{
	/* free any state created. */
	_free((int)fd);

	return SYSCALL_RUN;
}

static int
_hook(long syscall_number, long arg0, long arg1, long arg2, long arg3, long arg4,
      long arg5, long *result)
{
	switch (syscall_number) {
	case SYS_socket:
		return _handle_socket(arg0, arg1, arg2, result);
	case SYS_close:
		return _handle_close(arg0);
	default:
		/* The default behavior is to run the default syscall. */
		return SYSCALL_RUN;
	}
}

static int
_read_sysctl_fastopen(unsigned int *flags)
{
	int	fd;
	int	rc;
	char	buffer[1024];
	char *	endp;

	fd = open("/proc/sys/net/ipv4/tcp_fastopen", O_RDONLY);
	if (fd < 0) {
		log_error("unable to open /proc/sys/net/ipv4/tcp_fastopen: %s",
		          strerror(errno));
		return fd;
	}

	rc = read(fd, buffer, sizeof(buffer));
	close(fd);

	if (rc < 0) {
		log_error("unable to read /proc/sys/net/ipv4/tcp_fastopen: %s",
		          strerror(errno));
		return rc;
	}

	/* contains a base 10 number */
	*flags = strtol(buffer, &endp, 10);

	if (*endp && *endp != '\n') {
		log_error("unable to parse /proc/sys/net/ipv4/tcp_fastopen");
		return -1;
	}

	return 0;
}

static int
_validate_sysctl_fastopen(void)
{
	unsigned int	flags		= 0;
	unsigned int	expected_flags	= (0x1 | 0x4);

	if (_read_sysctl_fastopen(&flags) < 0)
		return -1;

	log_debug("fastopen sysctl is %x, expect flags %x to be set", flags,
	          expected_flags);

	/* We use the fastopen backend without requiring exchange of actual
	 * fastopen options. expected_flags are: 0x1 (sending data in SYN) and
	 * 0x4 (regardless of cookie availability and without a cookie option).
	 */
	if ((flags & expected_flags) != expected_flags)
		return -1;

	return 0;
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
	const char *log_path = getenv("CONVERTER_LOG");

	log_set_quiet(1);
	log_set_lock(_log_lock);

	/* open the log iff specified */
	if (log_path) {
		_log = fopen(log_path, "w");
		if (!_log)
			fprintf(stderr, "converter: unable to open log %s: %s",
			        log_path, strerror(errno));
		log_set_fp(_log);
	}

	log_info("Starting interception");

	if (_validate_sysctl_fastopen() < 0)
		log_error("Disabling the interception of TCP connections, setup "
		          "the sysctl tcp_fastopen to an appropriate value^");
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
