import sys
import os


class curl:
    def print_cmd(ip_version):
        return "curl -%s http://www.tessares.net/ -s -S -o -" % ip_version

    ERROR_MATCH = "Connection reset by peer"


class wget:
    def print_cmd(ip_version):
        return "wget -%s http://www.tessares.net/ -t1 -O -" % ip_version

    ERROR_MATCH = "failed: Connection refused."


class TestInstance:
    def server(self):
        raise NotImplemented()

    def validate(self):
        raise NotImplemented()

    def _cmd(self):
        cmd = os.environ["TEST_CMD"]
        return eval(cmd)

    def run_cmd(self):
        klass = self._cmd()
        print(klass.print_cmd(self.ip_version))

    def _get_result(self):
        with open(os.environ["TEST_OUTPUT_LOG"]) as f:
            return f.read()

    def _get_log(self):
        with open(os.environ["TEST_CONVERT_LOG"]) as f:
            return f.read()

    def assert_result(self, result):
        assert result in self._get_result(), "Couldn't find '{}' in output".format(result)

    def assert_error_result(self):
        klass = self._cmd()
        self.assert_result(klass.ERROR_MATCH)

    def assert_log_contains(self, log):
        assert log in self._get_log(), "Couldn't find '{}' in log".format(log)

    def converter_adress(self):
        if self.ip_version == '6':
            return '::1/128'
        else:
            return '127.0.0.1'

    def __init__(self):
        if len(sys.argv) < 2:
            raise Exception("don't run this manually")

        action = sys.argv[1]
        self.ip_version = sys.argv[2]

        {
            'server': lambda: self.server(),
            'validate': lambda: self.validate(),
            'run_cmd': lambda: self.run_cmd(),
        }[action]()
