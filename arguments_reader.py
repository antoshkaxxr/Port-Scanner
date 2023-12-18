import argparse


class ArgumentsReader:
    def __init__(self):
        self.args = None
        self.read_from_cmd()

    def read_from_cmd(self):
        parser = argparse.ArgumentParser(description='Port-Scanner')
        parser.add_argument('--timeout', type=float, default=2.0,
                            help='how long to wait for a response')
        parser.add_argument('-j', '--num-threads', type=int, default=1,
                            help='number of threads')
        parser.add_argument('-v', '--verbose', action='store_true',
                            help='verbose mode')
        parser.add_argument('-g', '--guess', action='store_true',
                            help='protocol definition')
        parser.add_argument('ip', type=str,
                            help='target host IP')
        parser.add_argument('ports_list', type=str, nargs='+',
                            help='ports to scan (e.g.: tcp/80 udp/3000-3100)')

        self.args = parser.parse_args()
