# Overview
This is a Python script to provide find where an IP address might match in Tenable SecurityCenter's scan zones, repositories, and exclusion lists.   You can download Python for Unix, Windows, and Mac at https://www.python.org/


This script requires the following Python libraries:
*The pySecurityCenter project at https://github.com/SteveMcGrath/pySecurityCenter 
*The netaddr library at https://pypi.python.org/pypi/netaddr
*The ipaddr library at https://pypi.python.org/pypi/ipaddr

The last two libraries can be installed by running: **pip install netaddr ipaddr**


# Example Using With Security Center

SCHOST=192.168.1.1

SCUSERNAME=jamessmith

SCPASSWORD=***********

export SCHOST SCUSERNAME SCPASSWORD

./sc-ip-search.py 192.168.0.1
