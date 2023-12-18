import socket
import time
from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sr1
from protocol_definition import define_protocol


class Scanner:
    def __init__(self, args):
        self.args = args
        self.ports = {'tcp': set(), 'udp': set()}

    def read_ports_list(self):
        for port_info in self.args.ports_list:
            if '/' in port_info:
                port_connection, port_ranges = port_info.split('/')
                ranges = port_ranges.split(',')
                for _range in ranges:
                    if '-' in _range:
                        start, end = map(int, _range.split('-'))
                        for i in range(start, end + 1):
                            self.ports[port_connection].add(i)
                    else:
                        self.ports[port_connection].add(int(_range))
            else:
                if port_info == 'tcp' or port_info == 'udp':
                    self.ports[port_info] = set(i for i in range(65535 + 1))
                else:
                    return 'Incorrect input'
        return 'OK'

    def print_info(self, connection, port, done, time_in_ms):
        if not done:
            return

        _time = ''
        if self.args.verbose and connection == 'TCP':
            _time = f"[{round(time_in_ms, 2)} ms]"

        print(f"{connection} {port} {_time}"
              f"{define_protocol(port, connection) if self.args.guess else ''}")

    def scan_ports(self):
        response = self.read_ports_list()
        if response != "OK":
            print('Incorrect input. Please, try again! For example:')
            print('python portscan.py --timeout 2 --num-threads 8 '
                  '-v -g 1.1.1.1 tcp/80 udp/4320-4450')
            return

        for port in self.ports['tcp']:
            self.print_info('TCP', port, *self.scan_tcp(self.args.ip, port))

        for port in self.ports['udp']:
            self.print_info('UDP', port, *self.scan_udp(self.args.ip, port))

    def scan_tcp(self, ip, port):
        packet = IP(dst=ip) / TCP(dport=port, flags='S')
        response = sr1(packet, timeout=self.args.timeout, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            return True, response.time - packet.time
        return False, None

    def scan_udp(self, ip, port):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.settimeout(self.args.timeout)
        start_time = time.time()
        try:
            udp_socket.sendto(b'\xAB\xAB\x01\x00\x00\x01\x00\x00' + b'\x00\x00\x00\x00' + b'\x05'
                              + b'ya' + b'\x03' + b'ru' + b'\x00' + b'\x00\x01' + b'\x00\x01',
                              (ip, port))
            data, addr = udp_socket.recvfrom(1024)
            udp_socket.close()
            return True, (time.time() - start_time) * 1000
        except Exception:
            return False, None
