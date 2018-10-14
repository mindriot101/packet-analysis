#!/usr/bin/env python


import sys
from scapy.all import IP, rdpcap, TCP
import argparse
import logging


logging.basicConfig(level=logging.INFO)


def analyse_raw_packet(packet):
    """ Parse a packet that does not have an IP layer """
    logging.debug("Parsing packet without IP layer: %r", packet)


def analyse_packet(packet):
    if not packet.haslayer(IP):
        analyse_raw_packet(packet)
        return

    logging.debug("Parsing packet with IP layer: %r", packet)

    ip_src = packet[IP].src
    ip_dest = packet[IP].dst


def main(args):
    pcap = rdpcap(args.filename)

    for packet in pcap:
        analyse_packet(packet)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    main(parser.parse_args())
