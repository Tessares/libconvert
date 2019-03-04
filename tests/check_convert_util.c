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
sample_convert_error(size_t *len)
{
	/* Error TLV is variable length. Value in this example is 1-byte long. */
	*len = sizeof(struct convert_error) + 1;
	struct convert_error *	error		= malloc(*len);
	struct convert_tlv *	error_tlv	= (struct convert_tlv *)error;

	error_tlv->length	= 1;    /* In 32-bit words */
	error_tlv->type		= CONVERT_ERROR;
	error->error_code	= 96;   /* Connection Reset */
	error->value[0]		= 0;

	return error;
}

struct convert_connect *
sample_convert_connect(size_t *len)
{
	*len = sizeof(struct convert_connect);
	struct convert_connect *connect		= malloc(*len);
	struct convert_tlv *	connect_tlv	= (struct convert_tlv *)connect;

	connect_tlv->length	= 5; /* In 32-bit words */
	connect_tlv->type	= CONVERT_CONNECT;
	connect->remote_port	= htons(12345);
	inet_pton(AF_INET6, "::1:5ee:bad:c0de", &(connect->remote_addr));

	return connect;
}

START_TEST(test_convert_parse_header){
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

START_TEST(test_convert_parse_tlvs_generic){
	struct convert_opts *	opts;
	uint8_t *		buff;
	size_t			buff_len;
	struct convert_tlv *	tlv;

	buff	= (uint8_t *)sample_convert_connect(&buff_len);
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

START_TEST(test_convert_parse_tlvs_connect){
	struct convert_opts *	opts;
	uint8_t *		buff;
	size_t			buff_len;
	struct convert_connect *connect;

	buff	= (uint8_t *)sample_convert_connect(&buff_len);
	connect = (struct convert_connect *)buff;

	opts = convert_parse_tlvs(buff, buff_len - 1);
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

START_TEST(test_convert_parse_tlvs_error){
	struct convert_opts *	opts;
	uint8_t *		buff;
	size_t			buff_len;
	struct convert_error *	error;

	buff	= (uint8_t *)sample_convert_error(&buff_len);
	error	= (struct convert_error *)buff;

	opts = convert_parse_tlvs(buff, buff_len - 1);
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

START_TEST(test_convert_parse_tlvs_multiple){
	struct convert_opts *	opts;
	uint8_t *		buff;
	size_t			buff_len, tlv1_len, tlv2_len;
	uint8_t *		tlv1, *tlv2;

	tlv1	= (uint8_t *)sample_convert_connect(&tlv1_len);
	tlv2	= (uint8_t *)sample_convert_error(&tlv2_len);

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

	free(tlv1);
	free(tlv2);
	free(buff);
}
END_TEST

START_TEST(test_convert_write){
	/* TODO */
	ck_assert(1);
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
	tcase_add_test(tc_core, test_convert_parse_tlvs_multiple);
	tcase_add_test(tc_core, test_convert_write);

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
