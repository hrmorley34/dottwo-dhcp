#!/bin/bash
grep "dhcpd" /var/log/syslog | less +G
# find lines containing "dhcpd" in the system log
# '-> open in less, and immediately run G to go to end of file
