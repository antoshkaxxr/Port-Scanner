from arguments_reader import ArgumentsReader
from scanner import Scanner


def main():
    args = ArgumentsReader().args
    scanner = Scanner(args)

    scanner.scan_ports()


main()
