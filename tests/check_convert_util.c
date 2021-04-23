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

#include <arpa/inet.h>
#include <check.h>
#include <stdlib.h>
#include "convert_util.h"

struct convert_error *
sample_convert_error_tlv(size_t *len)
{
	/* Error TLV is variable length. Value in this example is 1-byte long. */
	*len = sizeof(struct convert_error) + 1;
	struct convert_error *	error	= malloc(*len);
	struct convert_tlv *	tlv	= (struct convert_tlv *)error;

	tlv->length		= 1;    /* In 32-bit words */
	tlv->type		= CONVERT_ERROR;
	error->error_code	= 96;   /* Connection Reset */
	error->value[0]		= 0;

	return error;
}

struct convert_connect *
sample_convert_connect_tlv(size_t *len)
{
	*len = sizeof(struct convert_connect);
	struct convert_connect *connect = malloc(*len);
	struct convert_tlv *	tlv	= (struct convert_tlv *)connect;

	tlv->length		= 5; /* In 32-bit words */
	tlv->type		= CONVERT_CONNECT;
	connect->remote_port	= htons(12345);
	inet_pton(AF_INET6, "::1:5ee:bad:c0de", &(connect->remote_addr));

	return connect;
}

struct convert_extended_tcp_hdr *
sample_convert_tcp_ext_hdr_tlv(size_t *len)
{
	unsigned int	i		= 0;
	size_t		tcp_opts_len	= 8;

	*len = sizeof(struct convert_extended_tcp_hdr) + tcp_opts_len;
	struct convert_extended_tcp_hdr *	ext_tcp_hdr	= malloc(*len);
	struct convert_tlv *			tlv		=
		(struct convert_tlv *)ext_tcp_hdr;

	tlv->length		= 3; /* In 32-bit words */
	tlv->type		= CONVERT_EXTENDED_TCP_HDR;
	ext_tcp_hdr->unassigned = 0;
	for (i = 0; i < tcp_opts_len; i++)
		ext_tcp_hdr->tcp_options[i] = rand() % 256;

	return ext_tcp_hdr;
}

struct convert_cookie *
sample_convert_cookie_tlv(size_t *len)
{
	unsigned int	i		= 0;
	size_t		cookie_len	= 8;

	*len = sizeof(struct convert_cookie) + cookie_len;
	struct convert_cookie * cookie	= malloc(*len);
	struct convert_tlv *	tlv	= (struct convert_tlv *)cookie;

	tlv->length		= 3; /* In 32-bit words */
	tlv->type		= CONVERT_COOKIE;
	cookie->reserved	= 0;
	for (i = 0; i < cookie_len; i++)
		cookie->opaque[i] = rand() % 256;

	return cookie;
}

START_TEST (test_convert_parse_header) {
	int			ret;
	struct convert_header	hdr;
	uint8_t *		buff = (uint8_t *)&hdr;
	size_t			tlvs_length;

	ret = convert_parse_header(buff, sizeof(hdr) - 1, &tlvs_length);
	ck_assert_msg(ret == -1, "Should fail: buff too short");

	ret = convert_parse_header(buff, sizeof(hdr) + 1, &tlvs_length);
	ck_assert_msg(ret == -1, "Should fail: buff too long");

	hdr.version	= CONVERT_VERSION + 1;
	ret		= convert_parse_header(buff, sizeof(hdr), &tlvs_length);
	ck_assert_msg(ret == -1, "Should fail: unsupported version");

	hdr.version		= CONVERT_VERSION;
	hdr.magic_no		= htons(CONVERT_MAGIC_NO);
	hdr.total_length	= 2;
	ret			= convert_parse_header(buff, sizeof(hdr),
	                                               &tlvs_length);
	/* hdr.total_length is in 32-bit words, and include the Convert Header.
	 * tlvs_length is total length of TLVs in bytes, excluding Convert
	 * Header. We thus expect tlvs_length==4, which is total length (2*4)
	 * minus the Convert Header size (4).
	 */
	ck_assert_msg(ret == 0, "Should parse a valid Convert Header");
	ck_assert_msg(tlvs_length == 4,
	              "Should set tlvs_length to the total size of TLVs in bytes");
}
END_TEST

START_TEST (test_convert_parse_tlvs_generic) {
	struct convert_opts *	opts;
	uint8_t *		buff;
	size_t			buff_len;
	struct convert_tlv *	tlv;

	buff	= (uint8_t *)sample_convert_connect_tlv(&buff_len);
	tlv	= (struct convert_tlv *)buff;

	opts = convert_parse_tlvs(buff, 0);
	ck_assert_msg(opts == NULL, "Should fail: 0-len buff");

	opts = convert_parse_tlvs(buff, sizeof(struct convert_tlv) - 1);
	ck_assert_msg(opts == NULL,
	              "Should fail: buff len shorter than TLV header");

	opts = convert_parse_tlvs(buff, buff_len - 1);
	ck_assert_msg(opts == NULL,
	              "Should fail: buff len shorter than TLV length");

	tlv->type	= 42;
	opts		= convert_parse_tlvs(buff, buff_len);
	ck_assert_msg(opts == NULL, "Should fail: unknown TLV type");

	free(buff);
}
END_TEST

START_TEST (test_convert_parse_tlvs_connect) {
	struct convert_opts *	opts;
	uint8_t *		buff;
	size_t			buff_len;
	struct convert_connect *connect;

	buff	= (uint8_t *)sample_convert_connect_tlv(&buff_len);
	connect = (struct convert_connect *)buff;

	opts = convert_parse_tlvs(buff, sizeof(struct convert_connect) - 1);
	ck_assert_msg(opts == NULL,
	              "Should fail: buff len shorter than Connect TLV");

	opts = convert_parse_tlvs(buff, buff_len);
	ck_assert_msg(opts != NULL, "Should parse valid Convert Connect TLV");
	ck_assert_msg(opts->flags & CONVERT_F_CONNECT,
	              "Should set CONNECT flag");
	ck_assert_msg(opts->remote_addr.sin6_port == connect->remote_port,
	              "Should parse remote_port");
	unsigned int i = 0;
	for (i = 0; i < sizeof(opts->remote_addr.sin6_addr.s6_addr); ++i)
		ck_assert_msg(
			opts->remote_addr.sin6_addr.s6_addr[i] ==
			connect->remote_addr.s6_addr[i],
			"Should parse remote_addr");

	convert_free_opts(opts);
	free(buff);
}
END_TEST

START_TEST (test_convert_parse_tlvs_error) {
	struct convert_opts *	opts;
	uint8_t *		buff;
	size_t			buff_len;
	struct convert_error *	error;

	buff	= (uint8_t *)sample_convert_error_tlv(&buff_len);
	error	= (struct convert_error *)buff;

	opts = convert_parse_tlvs(buff, sizeof(struct convert_error) - 1);
	ck_assert_msg(opts == NULL,
	              "Should fail: buff len shorter than Error TLV");

	opts = convert_parse_tlvs(buff, buff_len);
	ck_assert_msg(opts != NULL, "Should parse valid Convert Error TLV");
	ck_assert_msg(opts->flags & CONVERT_F_ERROR, "Should set ERROR flag");
	ck_assert_msg(opts->error_code == error->error_code,
	              "Should parse error_code");

	convert_free_opts(opts);
	free(buff);
}
END_TEST

START_TEST (test_convert_parse_tlvs_ext_tcp_hdr) {
	struct convert_opts *			opts;
	uint8_t *				buff;
	size_t					buff_len;
	struct convert_extended_tcp_hdr *	ext_tcp_hdr;
	unsigned int				i;
	size_t					tcp_opts_len;

	buff		= (uint8_t *)sample_convert_tcp_ext_hdr_tlv(&buff_len);
	ext_tcp_hdr	= (struct convert_extended_tcp_hdr *)buff;

	opts = convert_parse_tlvs(buff,
	                          sizeof(struct convert_extended_tcp_hdr) - 1);
	ck_assert_msg(opts == NULL,
	              "Should fail: buff len shorter than Extended TCP Header TLV");

	opts = convert_parse_tlvs(buff, buff_len);
	ck_assert_msg(opts != NULL,
	              "Should parse valid Convert Extended TCP Header TLV");
	ck_assert_msg(opts->flags & CONVERT_F_EXTENDED_TCP_HDR,
	              "Should set EXTENDED_TCP_HDR flag");

	tcp_opts_len = buff_len - sizeof(struct convert_extended_tcp_hdr);
	ck_assert_msg(opts->tcp_options_len == tcp_opts_len,
	              "Should set tcp_options_len");

	for (i = 0; i < tcp_opts_len; ++i)
		ck_assert_msg(
			opts->tcp_options[i] == ext_tcp_hdr->tcp_options[i],
			"Should return exact copy TCP options");

	convert_free_opts(opts);
	free(buff);
}
END_TEST

START_TEST (test_convert_parse_tlvs_cookie) {
	struct convert_opts *	opts;
	uint8_t *		buff;
	size_t			buff_len;
	struct convert_cookie * cookie;
	unsigned int		i;
	size_t			cookie_len;

	buff	= (uint8_t *)sample_convert_cookie_tlv(&buff_len);
	cookie	= (struct convert_cookie *)buff;

	opts = convert_parse_tlvs(buff, sizeof(struct convert_cookie) - 1);
	ck_assert_msg(opts == NULL,
	              "Should fail: buff len shorter than Cookie TLV");

	opts = convert_parse_tlvs(buff, buff_len);
	ck_assert_msg(opts != NULL, "Should parse valid Convert Cookie TLV");
	ck_assert_msg(opts->flags & CONVERT_F_COOKIE, "Should set COOKIE flag");

	cookie_len = buff_len - sizeof(struct convert_cookie);
	ck_assert_msg(opts->cookie_len == cookie_len, "Should set cookie_len");

	for (i = 0; i < cookie_len; ++i)
		ck_assert_msg(opts->cookie_data[i] == cookie->opaque[i],
		              "Should return exact copy TCP options");

	convert_free_opts(opts);
	free(buff);
}
END_TEST

START_TEST (test_convert_parse_tlvs_multiple) {
	struct convert_opts *	opts;
	uint8_t *		buff;
	size_t			buff_len, tlv1_len, tlv2_len;
	uint8_t *		tlv1, *tlv2;

	tlv1	= (uint8_t *)sample_convert_connect_tlv(&tlv1_len);
	tlv2	= (uint8_t *)sample_convert_error_tlv(&tlv2_len);

	buff_len	= tlv1_len + tlv2_len;
	buff		= malloc(buff_len);
	memcpy(buff, tlv1, tlv1_len);
	memcpy(buff + tlv1_len, tlv2, tlv2_len);

	opts = convert_parse_tlvs(buff, buff_len);
	ck_assert_msg(opts != NULL, "Should parse multiple TLVs");
	ck_assert_msg(opts->flags & CONVERT_F_CONNECT,
	              "Should set flag of first TLV");
	ck_assert_msg(opts->flags & CONVERT_F_ERROR,
	              "Should set flag of second TLV");

	convert_free_opts(opts);
	free(tlv1);
	free(tlv2);
	free(buff);
}
END_TEST

START_TEST (test_convert_write_tlvs) {
	unsigned int	i;
	uint8_t *	(*tlv_builders[3])(size_t *len) = {
		(uint8_t * (*)(size_t *))sample_convert_connect_tlv,
		(uint8_t * (*)(size_t *))sample_convert_error_tlv,
		(uint8_t * (*)(size_t *))sample_convert_tcp_ext_hdr_tlv
	};

	/* For each TLV type, we expect convert_write(convert_read(TLV)) == TLV,
	 * modulo the Convert Header, as convert_write() preprends the Header,
	 * while convert_read() accepts a buffer without the Convert Header.
	 */
	for (i = 0; i < sizeof(tlv_builders) / sizeof(void *); i++) {
		size_t			tlv_orig_len, hdr_and_tlv_len;
		uint8_t *		tlv_orig, *tlv_copy;
		struct convert_opts *	opts;
		ssize_t			ret;
		unsigned int		j;

		tlv_orig	= tlv_builders[i](&tlv_orig_len);
		opts		= convert_parse_tlvs(tlv_orig, tlv_orig_len);
		hdr_and_tlv_len = tlv_orig_len + sizeof(struct convert_header);
		uint8_t copy[hdr_and_tlv_len];
		tlv_copy = copy + sizeof(struct convert_header);

		ret = convert_write(copy, sizeof(copy), opts);
		/* Cast to ssize_t is safe as tlv_orig_len < SSIZE_MAX */
		ck_assert_msg(ret == ((ssize_t)hdr_and_tlv_len),
		              "Should write size(Header)+size(TLV[%u]) bytes",
		              i);

		/* Verify copy TLV is a byte-per-byte copy of the original TLV */
		for (j = 0; j < tlv_orig_len; ++j)
			ck_assert_msg(tlv_orig[j] == tlv_copy[j],
			              "Expected tlv_orig[%u][%u] == tlv_copy[%u][%u]",
			              i, j, i, j);

		convert_free_opts(opts);
		free(tlv_orig);
	}
}
END_TEST

Suite *
convert_util_suite(void)
{
	Suite * s;
	TCase * tc_core;

	s = suite_create("convert_util");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_convert_parse_header);
	tcase_add_test(tc_core, test_convert_parse_tlvs_generic);
	tcase_add_test(tc_core, test_convert_parse_tlvs_connect);
	tcase_add_test(tc_core, test_convert_parse_tlvs_error);
	tcase_add_test(tc_core, test_convert_parse_tlvs_ext_tcp_hdr);
	tcase_add_test(tc_core, test_convert_parse_tlvs_cookie);
	tcase_add_test(tc_core, test_convert_parse_tlvs_multiple);
	tcase_add_test(tc_core, test_convert_write_tlvs);
	/* TODO:
	 *  - test Header part of convert_write()
	 *  - test convert_write() with multiple TLVs
	 */

	suite_add_tcase(s, tc_core);

	return s;
}

int
main(void)
{
	int		number_failed;
	Suite *		s;
	SRunner *	sr;

	s	= convert_util_suite();
	sr	= srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);

	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
