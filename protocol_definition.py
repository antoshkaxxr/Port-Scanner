import socket


def define_protocol(ip, port, connection):
    if is_http_protocol(ip, port, connection):
        return 'HTTP'
    if is_dns_protocol(ip, port, connection):
        return 'DNS'
    if is_echo_protocol(ip, port, connection):
        return 'ECHO'
    return '-'


def is_http_protocol(ip, port, connection):
    try:
        sock = socket.socket(socket.AF_INET,
                             socket.SOCK_STREAM if connection == 'TCP'
                             else socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.sendall(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
        response = sock.recv(1024)
        if response:
            return True
        return False
    except socket.error:
        return False
    finally:
        sock.close()


def is_dns_protocol(ip, port, connection):
    try:
        sock = socket.socket(socket.AF_INET,
                             socket.SOCK_STREAM if connection == 'TCP'
                             else socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
                + b"\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"
        sock.send(query)
        response = sock.recv(1024)
        if response:
            return True
        return False
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
        return False
    finally:
        sock.close()


def is_echo_protocol(ip, port, connection):
    try:
        sock = socket.socket(socket.AF_INET,
                             socket.SOCK_STREAM if connection == 'TCP'
                             else socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.sendall(b'Hello')
        response = sock.recv(1024)
        if response == b'Hello':
            return True
        return False
    except socket.error:
        return False
    finally:
        sock.close()
