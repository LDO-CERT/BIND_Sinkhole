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
from daemonize import Daemonize
import getopt, sys, datetime
import os, socket, io
import framestream
import ipaddress
import dns.message
import syslog

def log_message(tosyslog,message):
   if tosyslog:
      syslog.syslog(message)
   else:
     print(message)

def usage():
    print("Usage:", sys.argv[0], "[-d][-v][-l] -f dnstap_file | -s socket_file")
    print("")
    print("Options:")
    print(" -d\tDebug mode")
    print(" -v\tVerbose mode")
    print(" -l\tSend output to syslog (demonize) ** Only with socket")
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
    print("RCODE description:")
    print('   NOERROR = 0')
    print('   FORMERR = 1')
    print('   SERVFAIL = 2')
    print('   NXDOMAIN = 3')
    print('   NOTIMP = 4')
    print('   REFUSED = 5')
    print('   YXDOMAIN = 6')
    print('   YXRRSET = 7')
    print('   NXRRSET = 8')
    print('   NOTAUTH = 9')
    print('   NOTZONE = 10')
    print('   BADVERS = 16')

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

    ## CLIENT_QUERY
    if dnstap_data.message.type == 5: 
        query = dns.message.from_wire(dnstap_data.message.query_message)
        for question in query.question:
          msg = str(datetime.datetime.fromtimestamp(dnstap_data.message.query_time_sec).strftime('%Y-%m-%d %H:%M:%S'))
          #msg +=  str(' DNS')
          msg +=  ' '+str(get_query_type(dnstap_data.message.type))+str(" ")
          msg +=  str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port)
          msg +=  str(' -> ')
          msg +=  str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port)
          msg +=  str(' Id: #')+str(query.id)
          #msg +=  str(' Rcode: ')
          #msg +=  str(dns.rcode.to_text(dns.rcode.from_flags(query.flags,query.ednsflags)))
          #msg +=  str(' ')+str(dns.rcode.from_flags(query.flags,query.ednsflags))
          msg +=  str(' Flags: ')
          msg +=  str(dns.flags.to_text(query.flags))
          msg +=  ' Question: '+question.to_text()
          log_message(tosyslog,msg)

        if debug:
           print(print_dnsflag_fromhex(query.flags))
           print(query)

    ## RESOLVER_QUERY
    elif dnstap_data.message.type == 3: 
        if verbose:
          query = dns.message.from_wire(dnstap_data.message.query_message)
          for question in query.question:
            msg = str(datetime.datetime.fromtimestamp(dnstap_data.message.query_time_sec).strftime('%Y-%m-%d %H:%M:%S'))
            #msg +=  str(' DNS')
            msg +=  ' '+str(get_query_type(dnstap_data.message.type))+str(" ")
            msg +=  str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port)
            msg +=  str(' -> ')
            msg +=  str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port)
            msg +=  str(' Id: #')+str(query.id)
            #msg +=  str(' Rcode: ')
            #msg +=  str(dns.rcode.to_text(dns.rcode.from_flags(query.flags,query.ednsflags)))
            #msg +=  str(' ')+str(dns.rcode.from_flags(query.flags,query.ednsflags))
            msg +=  str(' Flags: ')
            msg +=  str(dns.flags.to_text(query.flags))
            msg +=  ' Question: '+question.to_text()
            log_message(tosyslog,msg)
            #print(dnstap_data)

    ## RESOLVER_RESPONSE
    elif dnstap_data.message.type == 4: 
        if verbose:
          query = dns.message.from_wire(dnstap_data.message.response_message)
          msg = str(datetime.datetime.fromtimestamp(dnstap_data.message.query_time_sec).strftime('%Y-%m-%d %H:%M:%S'))
          #msg +=  str(' DNS')
          msg +=  ' '+str(get_query_type(dnstap_data.message.type))+str(" ")
          msg +=  str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port)
          msg +=  str(' -> ')
          msg +=  str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port)
          msg +=  str(' Id: #')+str(query.id)
          msg +=  str(' Rcode: ')
          msg +=  str(dns.rcode.to_text(dns.rcode.from_flags(query.flags,query.ednsflags)))
          #msg +=  str(' ')+str(dns.rcode.from_flags(query.flags,query.ednsflags))
          msg +=  str(' Flags: ')
          msg +=  str(dns.flags.to_text(query.flags))

          for answer in query.answer:
            msg +=  ' Answer: '+str(answer).replace('\n',' | ')

          for auth in query.authority:
            msg +=  ' Authority: '+str(auth).replace('\n',' | ')


          log_message(tosyslog,msg)
            #print(dnstap_data)

    ## CLIENT_RESPONSE
    elif dnstap_data.message.type == 6: 
        query = dns.message.from_wire(dnstap_data.message.response_message)

#        for question in query.question:
#          msg = str(datetime.datetime.fromtimestamp(dnstap_data.message.response_time_sec).strftime('%Y-%m-%d %H:%M:%S'))
#          #msg +=  str(' DNS')
#          msg +=  ' '+str(get_query_type(dnstap_data.message.type))+str(" ")
#          msg +=  str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port)
#          msg +=  str(' -> ')
#          msg +=  str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port)
#          msg +=  str(' Id: #')+str(query.id)
#          msg +=  str(' Flags: ')
#          msg +=  str(dns.flags.to_text(query.flags))
#          msg +=  ' Question: '+question.to_text()
#          log_message(tosyslog,msg)

        msg = str(datetime.datetime.fromtimestamp(dnstap_data.message.response_time_sec).strftime('%Y-%m-%d %H:%M:%S'))
        #msg +=  str(' DNS')
        msg +=  ' '+str(get_query_type(dnstap_data.message.type))+str(" ")
        msg +=  str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port)
        msg +=  str(' -> ')
        msg +=  str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port)
        msg +=  str(' Id: #')+str(query.id)
        msg +=  str(' Rcode: ')
        msg +=  str(dns.rcode.to_text(dns.rcode.from_flags(query.flags,query.ednsflags)))
        #msg +=  str(' ')+str(dns.rcode.from_flags(query.flags,query.ednsflags))
        msg +=  str(' Flags: ')
        msg +=  str(dns.flags.to_text(query.flags))

        for answer in query.answer:
          msg +=  ' Answer: '+str(answer).replace('\n',' | ')

        for auth in query.authority:
          msg +=  ' Authority: '+str(auth).replace('\n',' | ')


        log_message(tosyslog,msg)

        if debug:
           print(print_dnsflag_fromhex(query.flags))
           print(query)
#           var_dump(query)

   ## OTHER QUERY
    else:
        if verbose:
            msg = str(datetime.datetime.fromtimestamp(dnstap_data.message.query_time_sec).strftime('%Y-%m-%d %H:%M:%S'))
            #msg +=  str(' DNS')
            msg +=  ' '+str(get_query_type(dnstap_data.message.type))+str(" ")
            msg +=  str(ipaddress.ip_address(dnstap_data.message.query_address))+str(':')+str(dnstap_data.message.query_port)
            msg +=  str(' -> ')
            msg +=  str(ipaddress.ip_address(dnstap_data.message.response_address))+str(':')+str(dnstap_data.message.response_port)
            msg +=  str(' Id: #')+str(query.id)
            log_message(tosyslog,msg)
            #print(dnstap_data)
        if debug:
            query = dns.message.from_wire(dnstap_data.message.query_message)
            #print(dnstap_data)
            log_message(tosyslog,query)

def main():

    if socketfile:
        if tosyslog:
          # Priority: LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG.
          # Facilities: LOG_KERN, LOG_USER, LOG_MAIL, LOG_DAEMON, LOG_AUTH, LOG_LPR, LOG_NEWS, LOG_UUCP, LOG_CRON, LOG_SYSLOG and LOG_LOCAL0 to LOG_LOCAL7.
          # Options: LOG_PID, LOG_CONS, LOG_NDELAY, LOG_NOWAIT and LOG_PERROR
          syslog.openlog('DNStap', logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)
    
        log_message(tosyslog,"Starting DNStap reader")

        try:
           sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
           sock.bind(socketfile)
           sock.listen(1)
           while True:
              connection, client_address = sock.accept()
              log_message(tosyslog,"New incoming connection...")
              try:
                 # Ok, I need Frame Streams handshake code here.
                 # https://www.nlnetlabs.nl/bugs-script/show_bug.cgi?id=741#c15
                 log_message(tosyslog,">> Waiting READY FRAME")
                 data = connection.recv(262144)
                 if debug:
                    var_dump(data)
                 log_message(tosyslog,"<< Sending ACCEPT FRAME")
                 connection.sendall(b'\x00\x00\x00\x00\x00\x00\x00\x22\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x16\x70\x72\x6f\x74\x6f\x62\x75\x66\x3a\x64\x6e\x73\x74\x61\x70\x2e\x44\x6e\x73\x74\x61\x70')
                 if debug:
                    print(b'\x00\x00\x00\x00\x00\x00\x00\x22\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x16\x70\x72\x6f\x74\x6f\x62\x75\x66\x3a\x64\x6e\x73\x74\x61\x70\x2e\x44\x6e\x73\x74\x61\x70')
                 log_message(tosyslog,">> Waiting START FRAME")
                 data = connection.recv(262144)
                 start = data
                 if debug:
                    var_dump(data)
                 while True:
                     data = connection.recv(262144)
                     if data:
                         b = io.BytesIO(start+data)
                     if debug:
                        var_dump(b.read())
                     for frame in framestream.reader(b):
                       parse_frame(frame)
                 else:
                     log_message(tosyslog,'antani!!!')
#                    connection.close()
#                    break
              finally:
                 # Clean up the connection
                 log_message(tosyslog,"connection lost")
                 connection.close()
        finally:
           log_message(tosyslog,"Closing socket")
           sock.close()
           os.unlink(socketfile)
           if tosyslog:
               syslog.closelog()

    elif tapfile:
        for frame in framestream.reader(open(tapfile, "rb")):
            parse_frame(frame)
    else:
       usage()


############################## 
tapfile = False
debug = False
verbose = False
socketfile = False
tosyslog = False

try:
  opts, args = getopt.getopt(sys.argv[1:], "hdvlf:s:", ["help","debug","verbose","to-syslog","file=","socket="])
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
    elif o in ("-l", "--to-syslog"):
       tosyslog = True
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
  print(err)
  print("")
  usage()
  sys.exit()

if tosyslog:
  # ok, going in to darkness
  # https://daemonize.readthedocs.io/en/latest/
  pid = "/var/run/dnstap.pid"
  daemon = Daemonize(app="dnstap", pid=pid, action=main,auto_close_fds=True)
  daemon.start()
else:
  main()

