#!/usr/bin/env python


import sys
import os
from scapy.all import IP, rdpcap, TCP
import argparse
import logging
from functools import lru_cache
import geoip2.database
import geoip2.errors
from collections import namedtuple


logging.basicConfig(level=logging.INFO)


GEOLITE_DOWNLOAD_URL = (
    "http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz"
)


IpLookup = namedtuple("IpLookup", ["ip", "city", "country"])


class PacketAnalyser(object):
    def __init__(self, source_ip):
        self.source_ip = source_ip
        self.geoip = self.setup_geolite()
        self.results = set()
        self.failures = set()

    def analyse_packet(self, packet):
        if not packet.haslayer(IP):
            self.analyse_raw_packet(packet)
            return

        logging.debug("Parsing packet with IP layer: %r", packet)

        ip_src = packet[IP].src
        ip_dest = packet[IP].dst

        for ip in (ip_src, ip_dest):
            if ip != self.source_ip:
                if ip.startswith('192.168'):
                    continue
                response = self.lookup_ip(ip)
                if response:
                    self.results.add(
                        IpLookup(
                            **{
                                "ip": ip,
                                "city": response.city.name,
                                "country": response.country.name,
                            }
                        )
                    )

    def analyse_raw_packet(self, packet):
        """ Parse a packet that does not have an IP layer """
        logging.debug("Parsing packet without IP layer: %r", packet)

    @lru_cache()
    def lookup_ip(self, ip_address):
        try:
            return self.geoip.city(ip_address)
        except geoip2.errors.AddressNotFoundError:
            self.failures.add(ip_address)
            return None

    def setup_geolite(self):
        import tempfile
        import urllib.request
        import tarfile
        import shutil

        base_path = os.path.realpath(os.path.dirname(__file__))
        db_path = os.path.join(base_path, "db")
        if not os.path.isdir(db_path):
            logging.debug("Creating db path)")
            os.makedirs(db_path)

        file_path = os.path.join(db_path, "GeoLite2-City.mmdb")
        if not os.path.isfile(file_path):
            logging.debug("Creating geolite2-city file")
            download_dest = tempfile.NamedTemporaryFile()
            urllib.request.urlretrieve(GEOLITE_DOWNLOAD_URL, download_dest.name)
            download_dest.seek(0)
            with tarfile.open(download_dest.name) as tfile:
                members = tfile.getmembers()
                valid_files = [
                    member for member in members if member.name.endswith(".mmdb")
                ]
                if len(valid_files) != 1:
                    raise ValueError("Cannot find database file in download artifact")

                database_file = valid_files[0]
                database_file.name = os.path.basename(database_file.name)
                tfile.extract(database_file, db_path)

        return geoip2.database.Reader(file_path)


def main(args):
    analyser = PacketAnalyser(source_ip=args.src)
    for filename in args.filename:
        pcap = rdpcap(filename)
        for packet in pcap:
            analyser.analyse_packet(packet)

    for result in sorted(list(analyser.results)):
        print(result)
    print(analyser.failures)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", nargs="+")
    parser.add_argument(
        "-s", "--src", help="Source ip of device", type=str, required=True
    )
    main(parser.parse_args())
