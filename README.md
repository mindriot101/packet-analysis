# Packet analysis

Load a pcap file and list the countries and cities where requests are
made to/from.

## Requirements

- python3
- libpcap

## Installation

```sh
pip install -r requirements.txt
```

## Usage

The program ignores the _source_ ip of the device (passed in with
`-s/--src`.

```sh
./parser.py -s 192.168.1.60 captures/*.pcap
```

## Contributions

```sh
pip install -r requirements.txt
pip install -r dev_requirements.txt
```
