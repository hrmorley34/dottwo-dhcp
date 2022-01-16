#!/usr/bin/env python3
import argparse
import csv
import logging
import re
import string
import sys
from typing import Any, Dict, Optional, Set, TextIO

from lib import Device, Group, Range, StrRange


parser = argparse.ArgumentParser(
    description="Convert CSV data (using template) into a dhcpd.conf file"
)
parser.add_argument(
    "-s",
    "--csv",
    "--spreadsheet",
    type=argparse.FileType("r"),
    dest="csv",
    required=True,
    help="The CSV spreadsheet to parse data from",
)
parser.add_argument(
    "-t",
    "--template",
    type=argparse.FileType("r"),
    dest="template",
    required=True,
    help="The template to convert",
)

parser.add_argument(
    "-o",
    "--output",
    type=argparse.FileType("w"),
    dest="conf",
    default=sys.stdout,
    help="The location to write the complete configuration file (default: stdout)",
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
    csv: TextIO
    template: TextIO
    conf: TextIO
    debug: int


ARGS = parser.parse_args(namespace=Namespace())


config: Dict[str, Any] = {"format": "%(message)s", "level": 30 - 10 * ARGS.debug}
if ARGS.conf == sys.stdout:
    config["stream"] = sys.stderr
logging.basicConfig(**config)
# No prefix;
# -1 -> 40 ERROR
# 0 -> 30 WARNING
# 1 -> 20 INFO
# 2 -> 10 DEBUG
logging.debug(ARGS)


MAC_FMT = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
IP_FMT = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)  # don't worry about checking for .256. or .015.
IPV6_FMT = re.compile(r"^([0-9a-f]{1,4}::?){,7}[0-9a-f]{1,4}$", re.I)


def filter_name(name: str) -> str:
    filtername = ""
    for char in name:
        if char in string.ascii_letters + string.digits:
            filtername += char.lower()
        elif char in "_- .":
            filtername += "_"
    if filtername[0] not in string.ascii_letters:
        filtername = "d" + filtername
    return filtername


RANGE_NAME = re.compile(r"^(other|range).*$", re.I)
DENY_NAME = re.compile(r"^(block|refuse|stop|disallow|deny|no)([-_ ]ip)?.*$", re.I)
RANGEIP_FMT = re.compile(r"^'([0-9a-f]+)-([0-9a-f]+)$", re.I)
IGNORE_FMT = re.compile(
    r"^(\?*|none|(disallow|deny|no).*)$", re.I
)  # any number of "?"s (including ""), none or deny/no


groups: Dict[Optional[str], Group] = {}
cgroup = None
used_names: Set[str] = set()
main_range = Range((None, None), (None, None))

r = csv.reader(ARGS.csv)
headers = next(r)

for line in r:
    if not any(map(lambda s: s.strip(), line[0:4])):
        continue

    if (
        line[2].strip()
        and (
            RANGEIP_FMT.match(line[2].strip())
            or RANGEIP_FMT.match(line[3].strip())
            or DENY_NAME.match(line[2].strip())
        )
        and (not line[1].strip())
        and line[0].strip()
    ):
        cgroup = line[0].replace("\n", "\\n")
        if cgroup and RANGE_NAME.match(cgroup):
            continue  # use `main_range`
        groups[cgroup] = Group(
            range=tuple(line[2].strip()[1:].split("-"))
            if RANGEIP_FMT.match(line[2].strip())
            else (None, None),
            rangev6=tuple(line[3].strip()[1:].split("-"))
            if RANGEIP_FMT.match(line[3].strip())
            else (None, None),
        )
        continue

    if cgroup and RANGE_NAME.match(cgroup):
        name = line[0].strip()

        mac = line[1].strip()
        if not MAC_FMT.match(mac):
            mac = None
        else:
            mac = mac.replace("-", ":")

        ip = line[2].strip()
        if not IP_FMT.match(ip):
            ip = None
        ipv6 = line[3].strip()
        if not IPV6_FMT.match(ipv6):
            ipv6 = None

        if re.match(r"^min(imum)?.*$", name, re.I):
            main_range.range = StrRange(
                ip or main_range.range.min,
                main_range.range.max,
            )
            main_range.rangev6 = StrRange(
                ipv6 or main_range.rangev6.min,
                main_range.rangev6.max,
            )
            continue
        elif re.match(r"^max(imum)?.*$", name, re.I):
            main_range.range = StrRange(
                main_range.range.min,
                ip or main_range.range.max,
            )
            main_range.rangev6 = StrRange(
                main_range.rangev6.min,
                ipv6 or main_range.rangev6.max,
            )
            continue
        # else: go on to add hosts

    if line[0].strip():  # include partial data
        # if line[0].strip() and line[1].strip() and (line[2].strip() or line[3].strip()): # only with MAC and at least one IP
        human_name = line[0].strip()
        name = filter_name(human_name)
        if not name:
            name = "unnamed"
        if name in used_names:
            i = 2
            while f"{name}{i}" in used_names:
                i += 1
            name = f"{name}{i}"
        used_names.add(name)

        mac = line[1].strip()
        if not MAC_FMT.match(mac):
            if not IGNORE_FMT.match(mac):
                logging.warning(f"Invalid MAC: {mac}")
            mac = None
        else:
            mac = mac.replace("-", ":")

        ip = line[2].strip()
        if not IP_FMT.match(ip):
            if not IGNORE_FMT.match(ip):
                logging.warning(f"Invalid IP: {ip}")
            ip = None
        ipv6 = line[3].strip()
        if not IPV6_FMT.match(ipv6):
            if not IGNORE_FMT.match(ipv6):
                logging.warning(f"Invalid IPv6: {ipv6}")
            ipv6 = None

        groups[cgroup].devices.append(
            Device(
                human_name,
                name,
                mac,
                ip,
                ipv6,
                bool(DENY_NAME.match(cgroup)) if cgroup is not None else False,
            )
        )
ARGS.csv.close()


logging.debug(groups)
logging.debug(main_range)

groups_text: str = ""  # group { host { }; host { }; ... }; group { ... }; ...
groups6_text: str = ""  # ^^^ but with fixed-address6
range_text: str = ""  # range x.x.x.x y.y.y.y;
range6_text: str = ""  # range6 x:x::x:x y:y::y:y;

if main_range.range.min and main_range.range.max:
    range_text += f"range {main_range.range.min} {main_range.range.max};\n"
if main_range.rangev6.min and main_range.rangev6.max:
    range6_text += f"range6 {main_range.rangev6.min} {main_range.rangev6.max};\n"

for name, properties in groups.items():
    logging.info(f"Group {name}: {properties.range[0]}-{properties.range[1]}")
    groups_text += "group {\n"
    groups_text += f"\t# {name}"
    if any(properties.range):
        groups_text += f" ({properties.range[0]}-{properties.range[1]})"
    groups_text += "\n"
    groups6_text += "group {\n"
    groups6_text += f"\t# {name}"
    if any(properties.rangev6):
        groups6_text += f" ({properties.rangev6[0]}-{properties.rangev6[1]})"
    groups6_text += "\n"

    for dev in properties.devices:
        logging.debug(f"|- {dev.human_name}: {dev.mac} -> {dev.ip} / {dev.ipv6}")
        groups_text += f"\thost {dev.name} {{\n"
        groups_text += f"\t\t# {dev.human_name}\n"
        groups6_text += f"\thost {dev.name} {{\n"
        groups6_text += f"\t\t# {dev.human_name}\n"
        if dev.mac is not None:
            groups_text += f"\t\thardware ethernet {dev.mac};\n"
            groups6_text += f"\t\thardware ethernet {dev.mac};\n"
        if dev.ip is not None:
            groups_text += f"\t\tfixed-address {dev.ip};\n"
        if dev.ipv6 is not None:
            groups6_text += f"\t\tfixed-address6 {dev.ipv6};\n"
        if dev.deny:
            logging.debug("|  '- deny booting;")
            groups_text += "\t\tdeny booting;\n"
            groups6_text += "\t\tdeny booting;\n"
        groups_text += "\t}\n"
        groups6_text += "\t}\n"

    groups_text += "}\n\n"
    groups6_text += "}\n\n"

TAB_SIZE = 2
TAB_SPACES = " " * TAB_SIZE

groups_text = groups_text.replace("\t", TAB_SPACES).rstrip()
groups6_text = groups6_text.replace("\t", TAB_SPACES).rstrip()
range_text = range_text.replace("\t", TAB_SPACES).rstrip()
range6_text = range6_text.replace("\t", TAB_SPACES).rstrip()


with ARGS.template as f:
    template = f.read()


def replace_section(template: str, name: str, body: str) -> str:
    escaped_name = re.escape(name)
    repl_escaped_name = name.replace("\\", "\\\\")
    repl_escaped_body = body.replace("\\", "\\\\")
    return re.sub(
        r"^( +)# (={4,}) "
        + escaped_name
        + r" (={4,}).*^\1# \2/"
        + escaped_name
        + r" \3$",
        rf"\1# \2 {repl_escaped_name} \3\n\1"
        + r"\n\1".join(repl_escaped_body.splitlines(False))
        + rf"\n\1# \2/{repl_escaped_name} \3",
        template,
        1,
        re.MULTILINE | re.DOTALL,
    )


template = replace_section(template, "REPLACE_GROUPS", groups_text)
template = replace_section(template, "REPLACE_RANGE", range_text)
template = replace_section(template, "REPLACE_GROUPS6", groups6_text)
template = replace_section(template, "REPLACE_RANGE6", range6_text)

with ARGS.conf as f:
    f.write(template)
