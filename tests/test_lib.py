import sys
import os


class TestInstance:
    def run(self):
        raise NotImplemented()

    def validate(self):
        raise NotImplemented()

    def _get_result(self):
        with open(os.environ["TEST_OUTPUT_LOG"]) as f:
            return f.read()

    def _get_log(self):
        with open(os.environ["TEST_CONVERT_LOG"]) as f:
            return f.read()

    def assert_result(self, result):
        assert result in self._get_result(), "Couldn't find '{}' in output".format(result)

    def assert_log_contains(self, log):
        assert log in self._get_log(), "Couldn't find '{}' in log".format(log)

    def __init__(self):
        if len(sys.argv) < 2:
            raise Exception("don't run this manually")

        action = sys.argv[1]
        {
            'server': lambda: self.run(),
            'validate': lambda: self.validate(),
        }[action]()
