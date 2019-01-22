#!/usr/bin/env python3

from converter_mock import *
from test_lib import *


class TestError(TestInstance):
    def run(self):
        converter = Convert(tlvs=[ConvertTLV_Error(error_code=1)])
        print(converter.build())

        class MockConverterError(MockConverter):
            actions = [RecvSyn(), SendSynAck(payload=converter.build())]
        MockConverterError()

    def validate(self):
        self.assert_result("Recv failure: Connection refused")
        self.assert_log_contains("received TLV error: 1")


TestError()
