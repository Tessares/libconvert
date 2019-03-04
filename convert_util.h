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

#ifndef _CONVERT_UTIL_H_
#define _CONVERT_UTIL_H_

#include "convert.h"

#ifndef UNUSED
#ifdef __GNUC__
#define UNUSED __attribute__((__unused__))
#else
#define UNUSED
#endif
#endif

enum {
	_CONVERT_F_INFO = 0,
	_CONVERT_F_CONNECT,
	_CONVERT_F_EXTENDED_TCP_HDR,
	_CONVERT_F_SUPPORTED_TCP_EXT,
	_CONVERT_F_COOKIE,
	_CONVERT_F_ERROR,
	_CONVERT_F_MAX,
};

enum {
	CONVERT_F_INFO			= (1 << _CONVERT_F_INFO),
	CONVERT_F_CONNECT		= (1 << _CONVERT_F_CONNECT),
	CONVERT_F_EXTENDED_TCP_HDR	= (1 << _CONVERT_F_EXTENDED_TCP_HDR),
	CONVERT_F_SUPPORTED_TCP_EXT	= (1 << _CONVERT_F_SUPPORTED_TCP_EXT),
	CONVERT_F_COOKIE		= (1 << _CONVERT_F_COOKIE),
	CONVERT_F_ERROR			= (1 << _CONVERT_F_ERROR),
};

struct convert_opts {
	uint8_t			flags;

	/* if CONVERT_F_CONNECT is set in flags
	 * The sin_port and sin_addr members shall be in network byte order.
	 */
	struct sockaddr_in6	remote_addr;

	/* if CONVERT_F_ERROR is set in flags */
	uint8_t			error_code;

	/* if CONVERT_F_EXTENDED_TCP_HDR is set in flags */
	uint8_t *		tcp_options;
	size_t			tcp_options_len;

	/* TODO extend to support more TLVs. */
};

void
convert_free_opts(struct convert_opts *opts);

int
convert_parse_header(const uint8_t *buff, size_t buff_len, size_t *tlvs_length);

/* Returns a pointer to struct convert_opts, which must be freed by the caller
 * using convert_free_opts(). Returns NULL upon failure.
 */
struct convert_opts *
convert_parse_tlvs(const uint8_t *buff, size_t buff_len);

ssize_t
convert_write(uint8_t *buff, size_t buff_len, const struct convert_opts *opts);

#endif
