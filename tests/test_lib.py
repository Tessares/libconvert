import sys
import os


class curl:
    COMMAND = "curl -4 http://www.tessares.net/ -s -S -o -"
    ERROR_MATCH = "Connection reset by peer"


class wget:
    COMMAND = "wget -4 http://www.tessares.net/ -t1 -O -"
    ERROR_MATCH = "failed: Connection refused."


class TestInstance:
    def run(self):
        raise NotImplemented()

    def validate(self):
        raise NotImplemented()

    def _cmd(self):
        cmd = os.environ["TEST_CMD"]
        return eval(cmd)

    def run_cmd(self):
        klass = self._cmd()
        print(klass.COMMAND)

    def _get_result(self):
        with open(os.environ["TEST_OUTPUT_LOG"]) as f:
            return f.read()

    def _get_log(self):
        with open(os.environ["TEST_CONVERT_LOG"]) as f:
            return f.read()

    def get_cookie(self):
        return os.environ["TEST_CONVERT_COOKIE"]

    def assert_result(self, result):
        assert result in self._get_result(), "Couldn't find '{}' in output".format(result)

    def assert_error_result(self):
        klass = self._cmd()
        self.assert_result(klass.ERROR_MATCH)

    def assert_log_contains(self, log):
        assert log in self._get_log(), "Couldn't find '{}' in log".format(log)

    def __init__(self):
        if len(sys.argv) < 2:
            raise Exception("don't run this manually")

        action = sys.argv[1]
        {
            'server': lambda: self.run(),
            'validate': lambda: self.validate(),
            'run_cmd': lambda: self.run_cmd(),
        }[action]()
