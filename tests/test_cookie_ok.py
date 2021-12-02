#!/usr/bin/env python3

from converter_mock import *
from test_lib import *


class TestCookieOK(TestInstance):
    def run(self):
        cookie = self.get_cookie()
        class MockConverterCookieOK(MockConverter):
            actions = [RecvSyn(), SendSynAckCheckCookie(Convert().build(), cookie), RecvHTTPGet(
            ), SendHTTPResp("HELLO, WORLD!"), SendPkt(flags='RA')]
        MockConverterCookieOK()

    def validate(self):
        self.assert_result("HELLO, WORLD!")


TestCookieOK()
