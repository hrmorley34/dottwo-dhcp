#!/usr/bin/env python3
import argparse
import csv
from datetime import datetime
from dhcp_leases import DhcpLeases, Lease
import logging
import sys
from typing import Any, Dict, TextIO


parser = argparse.ArgumentParser(description="")
parser.add_argument(
    "-l",
    "--leases",
    type=str,
    dest="leases",
    default="/var/lib/dhcp/dhcpd.leases",
    help="DHCP Leases file (default: /var/lib/dhcp/dhcpd.leases)",
)

parser.add_argument(
    "-o",
    "--output",
    type=argparse.FileType("w"),
    dest="csv",
    default=sys.stdout,
    help="The CSV file to write to (defaults to stdout)",
)

pdebug = parser.add_mutually_exclusive_group()
pdebug.add_argument(
    "-q",
    "--quiet",
    action="store_const",
    const=-1,
    default=0,
    dest="debug",
    help="Reduce console output",
)
pdebug.add_argument(
    "-v", "--verbose", action="count", dest="debug", help="Increase console output"
)


class Namespace(argparse.Namespace):
    leases: str
    csv: TextIO
    debug: int


ARGS = parser.parse_args(namespace=Namespace())


config: Dict[str, Any] = {"format": "%(message)s", "level": 30 - 10 * ARGS.debug}
if ARGS.csv == sys.stdout:
    config["stream"] = sys.stderr
logging.basicConfig(**config)
# No prefix;
# -1 -> 40 ERROR
# 0 -> 30 WARNING
# 1 -> 20 INFO
# 2 -> 10 DEBUG
logging.debug(ARGS)


leasefile = DhcpLeases(ARGS.leases)

COLUMNS = ["IP", "Name", "MAC", "start", "end"]


def lease_to_tuple(lease: Lease):
    return lease.ip, lease.hostname, lease.ethernet, lease.start, lease.end


leases = leasefile.get()
rows = [lease_to_tuple(lease) for lease in leases if isinstance(lease, Lease)]
rows.sort(key=lambda r: r[4] or datetime.now(), reverse=True)

logging.info("{} rows".format(len(rows)))
logging.debug(repr(rows))

with ARGS.csv as f:
    writer = csv.writer(f)
    writer.writerow(COLUMNS)
    for r in rows:
        writer.writerow(r)
