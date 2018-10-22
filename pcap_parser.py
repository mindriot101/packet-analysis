#!/usr/bin/env python


import sys
import os
from scapy.all import IP, rdpcap, TCP
import argparse
import logging
from functools import lru_cache
import datetime
import geoip2.database
import geoip2.errors
import socket
import numpy as np
import matplotlib.pyplot as plt
from collections import namedtuple

plt.style.use(['ggplot', 'seaborn-paper'])


logging.basicConfig(level=logging.INFO)


GEOLITE_DOWNLOAD_URL = (
    "http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz"
)


IpLookupBase = namedtuple("IpLookupBase", ["ip", "city", "country",
    "hostname", "coordinates"])


class IpLookup(IpLookupBase):
    def __str__(self):
        return "IP address: {self.ip}, city: {self.city}, country: {self.country}, hostname: {hostname}".format(
            self=self, hostname=self.hostname if self.hostname else "unknown"
        )


class PacketAnalyser(object):
    def __init__(self, source_ip):
        self.source_ip = source_ip
        self.geoip = self.setup_geolite()
        self.results = set()
        self.failures = set()
        self.times = []
        self.packet_sizes = []

    def analyse_packet(self, packet):

        # Ensure to collect the packet data
        self.times.append(packet.time)
        self.packet_sizes.append(len(packet))

        if not packet.haslayer(IP):
            self.analyse_raw_packet(packet)
            return

        logging.debug("Parsing packet with IP layer: %r", packet)

        ip_src = packet[IP].src
        ip_dest = packet[IP].dst

        for ip in (ip_src, ip_dest):
            if ip != self.source_ip:
                if ip.startswith("192.168"):
                    continue
                response = self.lookup_ip(ip)
                hostnames = self.get_hostname(ip)
                if hostnames:
                    hostname = hostnames[0]
                else:
                    hostname = None
                if response:
                    self.results.add(
                        IpLookup(
                            **{
                                "ip": ip,
                                "city": response.city.name,
                                "country": response.country.name,
                                "hostname": hostname,
                                "coordinates": (
                                    response.location.latitude,
                                    response.location.longitude,
                                    ),
                            }
                        )
                    )

    def analyse_raw_packet(self, packet):
        """ Parse a packet that does not have an IP layer """
        logging.debug("Parsing packet without IP layer: %r", packet)

    def render_data_transferred(self, output_file):

        dates = [datetime.datetime.fromtimestamp(ts) for ts in
                self.times]

        fig, axes = plt.subplots(2, 1, sharex=True)
        axes[0].plot(dates, self.packet_sizes, ".")

        cumulative_packet_size = np.cumsum(self.packet_sizes)
        axes[1].plot(dates, cumulative_packet_size / 1024, "-")

        axes[0].set(ylabel="Packet size / B")
        axes[1].set(xlabel="Time", ylabel="Cumulative packet size / KB")

        fig.autofmt_xdate()

        fig.tight_layout()

        if output_file is None:
            plt.show()
        else:
            fig.savefig(output_file)
            plt.close(fig)

    @lru_cache()
    def lookup_ip(self, ip_address):
        try:
            return self.geoip.city(ip_address)
        except geoip2.errors.AddressNotFoundError:
            self.failures.add(ip_address)
            return None

    @lru_cache()
    def get_hostname(self, ip_address):
        try:
            return socket.gethostbyaddr(ip_address)
        except socket.herror:
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

    def render_locations_on_map(self):
        import folium
        import json

        m = folium.Map()
        for result in sorted(list(self.results)):
            lat, lng = result.coordinates
            folium.Marker([lat, lng], tooltip=result.city, popup=json.dumps(result._asdict())).add_to(m)
        return m


def main(args):
    analyser = PacketAnalyser(source_ip=args.src)
    for filename in args.filename:
        pcap = rdpcap(filename)
        for packet in pcap:
            analyser.analyse_packet(packet)

    for result in sorted(list(analyser.results)):
        print(result)
    print(analyser.failures)

    analyser.render_data_transferred(args.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", nargs="+")
    parser.add_argument("-o", "--output", required=False, help="Output image file")
    parser.add_argument(
        "-s", "--src", help="Source ip of device", type=str, required=True
    )
    main(parser.parse_args())
