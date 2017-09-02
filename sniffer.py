from scapy.all import sniff
from argparse import ArgumentParser
parser = ArgumentParser()
parser.add_argument("--ip",
                    required=True,
                    dest="ip",
                    help="The IP where the sniffer will detect UDP traffic from.")

def print_packet(packet):
    print packet.getlayer("IP").src, packet.getlayer("UDP").dport

def sniffedUDP(ip):
    print "snfifing from {0}".format(ip)
    sniff(filter="src {0} and udp".format(ip),
          prn=lambda p: print_packet(p))


if __name__ == "__main__":
    args = parser.parse_args()
    sniffedUDP(args.ip)
