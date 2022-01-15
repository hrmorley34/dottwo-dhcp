#!/usr/bin/env python3
import argparse
import sys

parser = argparse.ArgumentParser(description="Convert CSV data (using template) into a dhcpd.conf file")
parser.add_argument("-s", "--csv", "--spreadsheet",
                    type=argparse.FileType("r"), dest="csv", required=True,
                    help="The CSV spreadsheet to parse data from")
parser.add_argument("-t", "--template",
                    type=argparse.FileType("r"), dest="template", required=True,
                    help="The template to convert")

parser.add_argument("-o", "--output",
                    type=argparse.FileType("w"), dest="conf", default=sys.stdout,
                    help="The location to write the complete configuration file (default: stdout)")

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
if ARGS.conf == sys.stdout:
    config["stream"] = sys.stderr
logging.basicConfig(**config)
# No prefix;
#-1 -> 40 ERROR
# 0 -> 30 WARNING
# 1 -> 20 INFO
# 2 -> 10 DEBUG
logging.debug(ARGS)


import collections
import string
import json
import csv
import re


MAC_FMT = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
IP_FMT = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$") # don't worry about checking for .256. or .015.
IPV6_FMT = re.compile(r"^([0-9a-f]{1,4}::?){,7}[0-9a-f]{1,4}$", re.I)
def NAME_FILTER(name):
    filtername = ""
    for char in name:
        if char in string.ascii_letters+string.digits:
            filtername += char.lower()
        elif char in "_- .":
            filtername += "_"
    if filtername[0] not in string.ascii_letters:
        filtername = "d"+filtername
    return filtername
RANGE_NAME = re.compile(r"^(other|range).*$", re.I)
DENY_NAME = re.compile(r"^(block|refuse|stop|disallow|deny|no)([-_ ]ip)?.*$", re.I)
RANGEIP_FMT = re.compile(r"^'([0-9a-f]+)-([0-9a-f]+)$", re.I)
IGNORE_FMT = re.compile(r"^(\?*|none|(disallow|deny|no).*)$", re.I) # any number of "?"s (including ""), none or deny/no


groups = {}
cgroup = None
used_names = set()
main_range = {"min": (None, None), "max": (None, None)}

r = csv.reader(ARGS.csv)
headers = next(r)

for line in r:
    if not any(map(lambda s: s.strip(), line[0:4])):
        continue

    if line[2].strip() and (RANGEIP_FMT.match(line[2].strip()) or RANGEIP_FMT.match(line[3].strip()) \
                            or DENY_NAME.match(line[2].strip())) \
       and (not line[1].strip()) and line[0].strip():
        cgroup = line[0]
        if cgroup and RANGE_NAME.match(cgroup):
            continue # use `main_range`
        groups[cgroup] = {
            "range": tuple(map(int, line[2].strip()[1:].split("-"))) if RANGEIP_FMT.match(line[2].strip()) else (None, None),
            "rangev6": tuple(line[3].strip()[1:].split("-")) if RANGEIP_FMT.match(line[3].strip()) else (None, None),
            "devices": [],
        }
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
            main_range["min"] = (ip or main_range["min"][0], ipv6 or main_range["min"][1])
            continue
        elif re.match(r"^max(imum)?.*$", name, re.I):
            main_range["max"] = (ip or main_range["max"][0], ipv6 or main_range["max"][1])
            continue
        # else: go on to add hosts

    if line[0].strip(): # include partial data
    #if line[0].strip() and line[1].strip() and (line[2].strip() or line[3].strip()): # only with MAC and at least one IP
        human_name = line[0].strip()
        name = NAME_FILTER(human_name)
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

        groups[cgroup]["devices"].append({
            "human_name": human_name,
            "name": name,
            "mac": mac,
            "ip": ip,
            "ipv6": ipv6,
            "deny": bool(DENY_NAME.match(cgroup)),
        })
ARGS.csv.close()

logging.debug(json.dumps(groups))

groups_text = "" # group { host { }; host { }; ... }; group { ... }; ...
groups6_text = "" # ^^^ but with fixed-address6
range_text = "" # range x.x.x.x y.y.y.y;
range6_text = "" # range6 x:x::x:x y:y::y:y;

if main_range['min'][0] and main_range['max'][0]:
    range_text += f"range {main_range['min'][0]} {main_range['max'][0]};\n"
if main_range['min'][1] and main_range['max'][1]:
    range6_text += f"range6 {main_range['min'][1]} {main_range['max'][1]};\n"

for name, properties in groups.items():
    logging.info(f"Group {name}: {properties['range'][0]}-{properties['range'][1]}")
    groups_text += "group {\n"
    groups_text += f"\t# {name}"
    if properties['range']: groups_text += f" ({properties['range'][0]}-{properties['range'][1]})"
    groups_text += "\n"
    groups6_text += "group {\n"
    groups6_text += f"\t# {name}"
    if properties['rangev6']: groups6_text += f" ({properties['rangev6'][0]}-{properties['rangev6'][1]})"
    groups6_text += "\n"

    for dev in properties["devices"]:
        logging.debug(f"|- {dev['human_name']}: {dev['mac']} -> {dev['ip']} / {dev['ipv6']}")
        groups_text += "\thost "+dev['name']+" {\n"
        groups_text += f"\t\t# {dev['human_name']}\n"
        groups6_text += "\thost "+dev['name']+" {\n"
        groups6_text += f"\t\t# {dev['human_name']}\n"
        if dev.get('mac'):
            groups_text += f"\t\thardware ethernet {dev['mac']};\n"
            groups6_text += f"\t\thardware ethernet {dev['mac']};\n"
        if dev.get('ip'):
            groups_text += f"\t\tfixed-address {dev['ip']};\n"
        if dev.get('ipv6'):
            groups6_text += f"\t\tfixed-address6 {dev['ipv6']};\n"
        if dev.get('deny'):
            groups_text += "\t\tdeny booting;\n"
            groups6_text += "\t\tdeny booting;\n"
        groups_text += "\t}\n"
        groups6_text += "\t}\n"

    groups_text += "}\n\n"
    groups6_text += "}\n\n"

TAB_SIZE = 2

groups_text = groups_text.replace("\t", " "*TAB_SIZE).rstrip()
groups6_text = groups6_text.replace("\t", " "*TAB_SIZE).rstrip()
range_text = range_text.replace("\t", " "*TAB_SIZE).rstrip()
range6_text = range6_text.replace("\t", " "*TAB_SIZE).rstrip()


template = ARGS.template.read()
ARGS.template.close()

def replace_section(template, name, text):
    return re.sub(r"^( +)# (={4,}) "+name+r" (={4,}).*^\1# \2/"+name+r" \3$",
                  rf"\1# \2 {name} \3\n\1" \
                   + r"\n\1".join(text.replace("\\","\\\\").splitlines(False)) \
                   + rf"\n\1# \2/{name} \3",
                  template, 1, re.MULTILINE | re.DOTALL)

template = replace_section(template, "REPLACE_GROUPS", groups_text)
template = replace_section(template, "REPLACE_RANGE", range_text)
template = replace_section(template, "REPLACE_GROUPS6", groups6_text)
template = replace_section(template, "REPLACE_RANGE6", range6_text)

ARGS.conf.write(template)
ARGS.conf.close()
