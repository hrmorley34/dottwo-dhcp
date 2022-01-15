#!/usr/bin/env python3
import argparse
import sys

parser = argparse.ArgumentParser(description="")
parser.add_argument("-l", "--leases",
                    type=str, dest="leases", default="/var/lib/dhcp/dhcpd.leases",
                    help="DHCP Leases file (default: /var/lib/dhcp/dhcpd.leases)")

parser.add_argument("-o", "--output",
                    type=argparse.FileType("w"), dest="csv", default=sys.stdout,
                    help="The CSV file to write to (defaults to stdout)")

pdebug = parser.add_mutually_exclusive_group()
pdebug.add_argument("-q", "--quiet",
                    action="store_const", const=-1, default=0, dest="debug",
                    help="Reduce console output")
pdebug.add_argument("-v", "--verbose",
                    action="count", dest="debug",
                    help="Increase console output")

ARGS = parser.parse_args()

import logging
config = {"format": "%(message)s", "level": 30 - 10*ARGS.debug}
if ARGS.csv == sys.stdout:
    config["stream"] = sys.stderr
logging.basicConfig(**config)
# No prefix;
#-1 -> 40 ERROR
# 0 -> 30 WARNING
# 1 -> 20 INFO
# 2 -> 10 DEBUG
logging.debug(ARGS)


from dhcp_leases import DhcpLeases
import csv

leasefile = DhcpLeases("/var/lib/dhcp/dhcpd.leases")

COLUMNS = ["IP", "Name", "MAC", "start", "end"]
def Row(lease):
    return lease.ip, lease.hostname, lease.ethernet, lease.start, lease.end


leases = leasefile.get()
rows = [Row(l) for l in leases]
rows.sort(key=lambda r:r[4], reverse=True)

logging.info("{} rows".format(len(rows)))
logging.debug(repr(rows))

writer = csv.writer(ARGS.csv)
writer.writerow(COLUMNS)
for r in rows:
    writer.writerow(r)

ARGS.csv.close()
