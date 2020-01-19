#! /bin/bash
# This script replays pcap related to cve-2020-0601 that has
# been generated or borrowed from the community
# Do not run in production!

# update to fit your environment
NWIP=""
NWUSER=""
NWPASS=""

echo y | cp curveball.lua /etc/netwitness/ng/parsers

NwConsole \
-c login $NWIP:50004 $NWUSER $NWPASS \
-c /decoder/parsers reload \
-c import badcurveballtest.pcap \
-c import goodcurveballtest.pcap \
-c import brocurveballtest.pcap \
-c logout \
-c exit
