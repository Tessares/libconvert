#!/usr/bin/env python3

from converter_mock import *
from test_lib import *


class TestCookieError(TestInstance):
    def run(self):
        converter = Convert(tlvs=[ConvertTLV_Error(error_code=3)])
        print(converter.build())
        cookie = self.get_cookie()

        class MockConverterCookieError(MockConverter):
            actions = [RecvSyn(), SendSynAckCheckCookie(converter.build(), cookie), Wait(1), SendPkt(flags='R')]
        MockConverterCookieError()

    def validate(self):
        self.assert_log_contains("received TLV error: 3")


TestCookieError()
