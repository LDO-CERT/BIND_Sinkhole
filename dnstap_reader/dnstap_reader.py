#!/usr/bin/env python3

from __future__ import print_function
from dnstap_pb2 import *
import sys
import framestream
import ipaddress
import binascii
#from dnslib import *
import dns.message

if len(sys.argv) != 2:
    print("Usage:", sys.argv[0], "dnstap file")
    sys.exit(-1)

for frame in framestream.reader(open(sys.argv[1], "rb")):
    dnstap_data = Dnstap()
    dnstap_data.ParseFromString(frame)
#   https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto read here !
#    print(dnstap_data)
#    print(str('query_address: ')+str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port))
#    print(str('response_address: ')+str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port))
    print(str('DNS Message: '),end='')
    print(str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port),end='')
    print(str(' -> '),end='')
    print(str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port))

    if dnstap_data.message.type == 5:
        print('TYPE: CLIENT_QUERY')
        query =  dns.message.from_wire(dnstap_data.message.query_message)
        #query = DNSRecord.parse(dnstap_data.message.query_message)
        print(query)

    if dnstap_data.message.type == 6:
        print('TYPE: QUERY_RESPONSE')
        query = dns.message.from_wire(dnstap_data.message.response_message)
#        query = DNSRecord.parse(dnstap_data.message.response_message)
        print(query)
    print()
    print()

