from random import randint
from time import sleep

from scapy.all import IP, UDP, send


from argparse import ArgumentParser
parser = ArgumentParser()
parser.add_argument("--ip",
                    required=True,
                    dest="ip",
                    help="The destination IP packets will be send to")


def send_to_sniffer(ip):
    while True:
        port=randint(2000,3000)
        packet = IP(src=ip)/UDP(dport=port)
        print packet.summary()
        send(packet)
        sleep(1)

if __name__ == "__main__":
    args = parser.parse_args()
    send_to_sniffer(args.ip)
