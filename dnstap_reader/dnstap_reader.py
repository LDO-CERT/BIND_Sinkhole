#!/usr/bin/env python3
#
# dnstap_reader
# written by Luca Memini (LDO-CERT) - Luca.Memini@leonardocompany.com
# thx to Davide Arcuri
#

from __future__ import print_function
from dnstap_pb2 import *
from pprint import pprint
from var_dump import var_dump
import getopt, sys, datetime
import os, socket, io
import framestream
import ipaddress
import dns.message

def usage():
    print("")
    print("Usage:", sys.argv[0], "[-d][-v] -f dnstap_file | -s socket_file")
    print("")
    print("Default mode show only Client Query e Client Response, use -v for show all dns query")
    print("")
    print("Quiet text output format mnemonics:")
    print("  AQ: AUTH_QUERY (type: 1)")
    print("  AR: AUTH_RESPONSE (type: 2)")
    print("  RQ: RESOLVER_QUERY (type: 3)")
    print("  RR: RESOLVER_RESPONSE (type: 4)")
    print("  CQ: CLIENT_QUERY (type 5)")
    print("  CR: CLIENT_RESPONSE (type: 6)")
    print("  FQ: FORWARDER_QUERY (type: 7)")
    print("  FR: FORWARDER_RESPONSE (type: 8)")
    print("  SQ: STUB_QUERY (type: 9)")
    print("  SR: STUB_RESPONSE (type: 10)")
    print("  TQ: TOOL_QUERY (type: 11)")
    print("  TR: TOOL_RESPONSE (type: 12)")
    print("")
    print("Flags description:")
    print('  QR: Query Response')
    print('  AA: Authoritative Answer')
    print('  TT: Truncated Response')
    print('  RD: Recursion Desired')
    print('  RA: Recursion Avaible')
    print('  AD: Authentic Data')
    print('  CD: Checking Disabled')
    print("")


def print_dnsflag_fromhex(n):
    if n & int('0x8000',16):
        print('QR (Query Response)')
    if n & int('0x0400',16):
        print('AA (Authoritative Answer)')
    if n & int('0x0200',16):
        print('TT (Truncated Response)')
    if n & int('0x0100',16):
        print('RD (Recursion Desired)')
    if n & int('0x0080',16):
        print('RA (Recursion Avaible)')
    if n & int('0x0020',16):
        print('AD (Authentic Data)')
    if n & int('0x0010',16):
        print('CD (Checking Disabled)')

def get_query_type(type):
    switcher={
        1:'AQ',
        2:'AR',
        3:'RQ',
        4:'RR',
        5:'CQ',
        6:'CR',
        7:'FQ',
        8:'FR',
        9:'SQ',
        10:'SR',
        11:'TQ',
        12:'TR'
    }
    return switcher.get(type,"unknown")


def parse_frame(frame):
    dnstap_data = Dnstap()
    dnstap_data.ParseFromString(frame)
#   https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto read here !
#    print(dnstap_data)

    if dnstap_data.message.type == 5: ## CLIENT_QUERY
        query = dns.message.from_wire(dnstap_data.message.query_message)
#        var_dump(query)

        for question in query.question:
          print(str(datetime.datetime.fromtimestamp(dnstap_data.message.query_time_sec).strftime('%Y-%m-%d %H:%M:%S')),end='')
          print(str(' DNS ')+str(get_query_type(dnstap_data.message.type))+str(" "),end='')
          print(str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port),end='')
          print(str(' -> '),end='')
          print(str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port),end='')
          print(str(' Id: #')+str(query.id),end='')
          print(str(' Flags: '),end='')
          print(str(dns.flags.to_text(query.flags)),end='')
          print(' Question: '+question.to_text())

        if debug:
           print(print_dnsflag_fromhex(query.flags))
           print(query)
    elif dnstap_data.message.type == 6: ## CLIENT_RESPONSE
        query = dns.message.from_wire(dnstap_data.message.response_message)

        for question in query.question:
          print(str(datetime.datetime.fromtimestamp(dnstap_data.message.response_time_sec).strftime('%Y-%m-%d %H:%M:%S')),end='')
          print(str(' DNS ')+str(get_query_type(dnstap_data.message.type))+str(" "),end='')
          print(str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port),end='')
          print(str(' -> '),end='')
          print(str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port),end='')
          print(str(' Id: #')+str(query.id),end='')
          print(str(' Flags: '),end='')
          print(str(dns.flags.to_text(query.flags)),end='')
          print(' Question: '+question.to_text())
        for answer in query.answer:
          print(str(datetime.datetime.fromtimestamp(dnstap_data.message.response_time_sec).strftime('%Y-%m-%d %H:%M:%S')),end='')
          print(str(' DNS ')+str(get_query_type(dnstap_data.message.type))+str(" "),end='')
          print(str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port),end='')
          print(str(' -> '),end='')
          print(str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port),end='')
          print(str(' Id: #')+str(query.id),end='')
          print(str(' Flags: '),end='')
          print(str(dns.flags.to_text(query.flags)),end='')
          print(' Answer: '+str(answer).replace('\n',' | '))
        if debug:
           print(print_dnsflag_fromhex(query.flags))
           print(query)
#           var_dump(query)
    else:
        if verbose:
            print(str(datetime.datetime.fromtimestamp(dnstap_data.message.query_time_sec).strftime('%Y-%m-%d %H:%M:%S')),end='')
            print(str(' DNS ')+str(get_query_type(dnstap_data.message.type))+str(" "),end='')
            print(str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port),end='')
            print(str(' -> '),end='')
            print(str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port))
        if debug:
            query = dns.message.from_wire(dnstap_data.message.query_message)
            #print(dnstap_data)
            print(query)
#    print()
#    print()

try:
    opts, args = getopt.getopt(sys.argv[1:], "hdvf:s:", ["help","debug","verbose","file=","socket="])
    tapfile = False
    debug = False
    verbose = False
    socketfile = False
    for o, a in opts:
        if o == "-d":
            debug = True
            print(":::: Debug output enabled")
        elif o == "-v":
            verbose = True
            print(":::: Verbose output enabled")
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-f", "--file"):
            tapfile = a
            if not(tapfile):
               usage()
        elif o in ("-s", "--socket"):
            socketfile = a
            if not(socketfile):
               usage()
        else:
            assert False, "unhandled option"
except getopt.GetoptError as err:
    # print help information and exit:
    print(err) # will print something like "option -a not recognized"
    usage()


if socketfile:
    try:
       sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
       sock.bind(socketfile)
       sock.listen(1)
       while True:
          connection, client_address = sock.accept()
          print("New incoming connection...")
          try:
             # Ok, I need Frame Streams handshake code here.
             # https://www.nlnetlabs.nl/bugs-script/show_bug.cgi?id=741#c15
             print(">> Waiting READY FRAME")
             data = connection.recv(262144)
             if debug:
               var_dump(data)
             print("<< Sending ACCEPT FRAME")
             connection.sendall(b'\x00\x00\x00\x00\x00\x00\x00\x22\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x16\x70\x72\x6f\x74\x6f\x62\x75\x66\x3a\x64\x6e\x73\x74\x61\x70\x2e\x44\x6e\x73\x74\x61\x70')
             if debug:
               print(b'\x00\x00\x00\x00\x00\x00\x00\x22\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x16\x70\x72\x6f\x74\x6f\x62\x75\x66\x3a\x64\x6e\x73\x74\x61\x70\x2e\x44\x6e\x73\x74\x61\x70')
             print(">> Waiting START FRAME")
             data = connection.recv(262144)
             start = data
             if debug:
               var_dump(data)
             while True:
#                print("Reciving data:")
                data = connection.recv(262144)
                if data:
                    b = io.BytesIO(start+data)
                    if debug:
                       var_dump(b.read())
                    for frame in framestream.reader(b):
                       parse_frame(frame)
                else:
                    print('antani!!!')
#                    connection.close()
#                    break
          finally:
            # Clean up the connection
            #connection.close()
            print("connection lost?")
    finally:
      print("Closing socket")
      connection.close()
      sock.close()
      os.unlink(socketfile)

elif tapfile:
    for frame in framestream.reader(open(tapfile, "rb")):
        parse_frame(frame)
else:
    usage()
