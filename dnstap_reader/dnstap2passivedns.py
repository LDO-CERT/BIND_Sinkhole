#!/usr/bin/env python3
#
# dnstap_reader
# written by Luca Memini (LDO-CERT) - Luca.Memini@leonardocompany.com
# thx to Davide Arcuri
#
from __future__ import print_function
import io
import os
import sys
import socket
import argparse
import framestream
import ipaddress
import dns.message
import dns.rrset
#import dns.set
import shlex
#import dns.edns, dns.exception, dns.message, dns.name, dns.rdata, dns.rdataclass, dns.rdatatype, dns.rdtypes.ANY.NS, dns.rdtypes.IN.A, dns.rdtypes.IN.AAAA, dns.resolver, dns.rrset
import syslog
import logging
from dnstap_pb2 import Dnstap
from var_dump import var_dump
from daemonize import Daemonize
from datetime import datetime


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write("error: %s\n" % message)
        self.print_help()
        print(
            "Default mode parse only Client Response (CR),"
            " use -v for show all dns query\n",
            "\n",
        )
        sys.exit(2)

def print_mnemonics():
     print(
            "Quiet text output format mnemonics:\n",
            "  AQ: AUTH_QUERY (type: 1)\n",
            "  AR: AUTH_RESPONSE (type: 2)\n",
            "  RQ: RESOLVER_QUERY (type: 3)\n",
            "  RR: RESOLVER_RESPONSE (type: 4)\n",
            "  CQ: CLIENT_QUERY (type 5)\n",
            "  CR: CLIENT_RESPONSE (type: 6)\n",
            "  FQ: FORWARDER_QUERY (type: 7)\n",
            "  FR: FORWARDER_RESPONSE (type: 8)\n",
            "  SQ: STUB_QUERY (type: 9)\n",
            "  SR: STUB_RESPONSE (type: 10)\n",
            "  TQ: TOOL_QUERY (type: 11)\n",
            "  TR: TOOL_RESPONSE (type: 12)\n",
            "\n",
            "Flags description:\n",
            "  QR: Query Response\n",
            "  AA: Authoritative Answer\n",
            "  TT: Truncated Response\n",
            "  RD: Recursion Desired\n",
            "  RA: Recursion Avaible\n",
            "  AD: Authentic Data\n",
            "  CD: Checking Disabled\n",
            "\n",
            "RCODE description:\n",
            "   NOERROR = 0\n",
            "   FORMERR = 1\n",
            "   SERVFAIL = 2\n",
            "   NXDOMAIN = 3\n",
            "   NOTIMP = 4\n",
            "   REFUSED = 5\n",
            "   YXDOMAIN = 6\n",
            "   YXRRSET = 7\n",
            "   NXRRSET = 8\n",
            "   NOTAUTH = 9\n",
            "   NOTZONE = 10\n",
            "   BADVERS = 16",
            "\n",
        )
     sys.exit(2)


def log_message(tosyslog, message):
    if tosyslog:
        syslog.syslog(message)
    elif outfile:
        logging.info(message)
    else:
        print(message)


def dnsflag_fromhex(n):
    if n & int("0x8000", 16):
        return "QR (Query Response)"
    if n & int("0x0400", 16):
        return "AA (Authoritative Answer)"
    if n & int("0x0200", 16):
        return "TT (Truncated Response)"
    if n & int("0x0100", 16):
        return "RD (Recursion Desired)"
    if n & int("0x0080", 16):
        return "RA (Recursion Avaible)"
    if n & int("0x0020", 16):
        return "AD (Authentic Data)"
    if n & int("0x0010", 16):
        return "CD (Checking Disabled)"


def get_query_type(type):
    switcher = {
        1: "AQ",
        2: "AR",
        3: "RQ",
        4: "RR",
        5: "CQ",
        6: "CR",
        7: "FQ",
        8: "FR",
        9: "SQ",
        10: "SR",
        11: "TQ",
        12: "TR",
    }
    return switcher.get(type, "unknown")


def parse_frame(frame):
    dnstap_data = Dnstap()
    dnstap_data.ParseFromString(frame)
    # https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto read here!

    msg_type = dnstap_data.message.type

    if msg_type in [4, 6]:
        query = dns.message.from_wire(dnstap_data.message.response_message)
        if msg_type == 6 or (msg_type == 4 and verbose):
            tmp = {
                'timestamp': dnstap_data.message.response_time_sec,
                'query_type': get_query_type(msg_type),
                'query_address': ipaddress.ip_address(
                    dnstap_data.message.query_address
                ),
                'query_port': dnstap_data.message.query_port,
                'response_address': ipaddress.ip_address(
                    dnstap_data.message.response_address
                ),
                'response_port': dnstap_data.message.response_port,
                'query_id': query.id,
                'rcode': dns.rcode.to_text(
                    dns.rcode.from_flags(query.flags, query.ednsflags)
                ),
                'flags': dns.flags.to_text(query.flags),
		'question':[],
                'answers': [],
                'authorities':[],
            }
            for question in query.question:
               tmp['question'].append(str(question).replace("\n", " | "))
            for answer in query.answer:
               tmp['answers'].append(str(answer).replace("\n", " | "))
            for auth in query.authority:
               tmp['authorities'].append(str(auth).replace("\n", " | "))


            ##timestamp||dns-client ||dns-server||RR class||Query||Query Type||Answer||TTL||Count
            msg = "{timestamp}||{query_address}||{response_address}||".format(**tmp)

            if dns.rcode.from_flags(query.flags,query.ednsflags) == 0:
               for answer in query.answer:
                  list = answer.to_text().split("\n")
                  for row in list:
                    r=shlex.split(row)
                    #print(r) # ['hostupdate.vmware.com.', '14', 'IN', 'CNAME', 'shd-download.vmware.com.edgekey.net.']
                    if r[3] == 'SOA':
                       resp =r[2]+"||"+r[0]+"||"+r[3]+"||"+r[4]+"||"+r[-4]+"||"+dns.rcode.to_text(dns.rcode.from_flags(query.flags,query.ednsflags))
                    else:
                       resp =r[2]+"||"+r[0]+"||"+r[3]+"||"+r[-1]+"||"+r[1]+"||"+dns.rcode.to_text(dns.rcode.from_flags(query.flags,query.ednsflags))
                    log_message(tosyslog, msg+resp)
            else: # RCODE != 0
               for question in query.question:
                  list = question.to_text().split("\n")
                  for row in list:
                    r=shlex.split(row)
                    #print(r) #['shajhgajkghajkga.com.', 'IN', 'A']
                    resp =r[1]+"||"+r[0]+"||"+r[2]+"||""||""||"+dns.rcode.to_text(dns.rcode.from_flags(query.flags,query.ednsflags))
                    tmp['question'].append(str(question).replace("\n", " | "))
                    log_message(tosyslog, msg+resp)

            if msg_type == 6 and debug:
                logging.debug(dnsflag_fromhex(query.flags))
                logging.debug(query)

    # OTHER QUERY
    else:
        if verbose:
            query = dns.message.from_wire(dnstap_data.message.query_message)
            msg = "{} {} {}:{} -> {}:{} Id: #{}".format(
                dnstap_data.message.query_time_sec,
                get_query_type(msg_type),
                ipaddress.ip_address(dnstap_data.message.query_address),
                dnstap_data.message.query_port,
                ipaddress.ip_address(dnstap_data.message.response_address),
                dnstap_data.message.response_port,
                query.id,
            )
            log_message(tosyslog, msg)
        if debug:
            query = dns.message.from_wire(dnstap_data.message.query_message)
            log_message(tosyslog, query)

def main():
    if socketfile:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(socketfile)
            os.chmod(socketfile,666)
            sock.listen(1)
            while True:
                connection, client_address = sock.accept()
                log_message(tosyslog, "New incoming connection...")
                try:
                    # Ok, I need Frame Streams handshake code here.
                    # https://www.nlnetlabs.nl/bugs-script/show_bug.cgi?id=741#c15
                    log_message(tosyslog, ">> Waiting READY FRAME")
                    data = connection.recv(262144)
                    if debug:
                        var_dump(data)
                    log_message(tosyslog, "<< Sending ACCEPT FRAME")
                    connection.sendall(
                        b"\x00\x00\x00\x00\x00\x00\x00\x22\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x16\x70\x72\x6f\x74\x6f\x62\x75\x66\x3a\x64\x6e\x73\x74\x61\x70\x2e\x44\x6e\x73\x74\x61\x70"
                    )
                    if debug:
                        logging.debug(
                            b"\x00\x00\x00\x00\x00\x00\x00\x22\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x16\x70\x72\x6f\x74\x6f\x62\x75\x66\x3a\x64\x6e\x73\x74\x61\x70\x2e\x44\x6e\x73\x74\x61\x70"
                        )
                    log_message(tosyslog, ">> Waiting START FRAME")
                    data = connection.recv(262144)
                    start = data
                    if debug:
                        var_dump(data)
                    while True:
                        data = connection.recv(262144)
                        if data:
                            b = io.BytesIO(start + data)
                        if debug:
                            var_dump(b.read())
                        for frame in framestream.reader(b):
                            parse_frame(frame)
                    else:
                        log_message(tosyslog, "error error!!!")
                finally:
                    # Clean up the connection
                    log_message(tosyslog, "connection lost")
                    connection.close()
        finally:
            log_message(tosyslog, "Closing socket")
            sock.close()
            os.unlink(socketfile)
            if tosyslog:
                syslog.closelog()

    elif tapfile:
        log_message(tosyslog, "Reading data from "+tapfile)
        for frame in framestream.reader(open(tapfile, "rb")):
            parse_frame(frame)

if __name__ == "__main__":
    parser = MyParser(description="DNSTAP reader to passivedns log format")
    parser.add_argument("-m", "--mnemonics",
                        action="store_true", help="Mnemonics datatype (help)")
    parser.add_argument("-d", "--debug",
                        action="store_true", help="Debug mode")
    parser.add_argument("-v", "--verbose",
                        action="store_true", help="Verbose mode")

    logdest = parser.add_mutually_exclusive_group(required=False)
    logdest.add_argument(
        "-l",
        "--to-syslog",
        action="store_true",
        help="Send output to syslog (demonize)",
    )
    logdest.add_argument(
        "-o",
        "--outfile",
        action="store_true",
        help="Send output to file (demonize)",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="file")
    group.add_argument("-s", "--socket", help="socket")

    args = parser.parse_args()

    tapfile = args.file
    debug = args.debug
    verbose = args.verbose
    socketfile = args.socket
    tosyslog = args.to_syslog
    outfile = args.outfile

    mnemonics = args.mnemonics ## non funziona --todo

    if mnemonics:
       print_mnemonics()

    if outfile:
       logging.basicConfig(format='%(message)s', filename="dnstap.log", level=logging.INFO)

    if tosyslog:
        # Priority: LOG_EMERG, LOG_ALERT, LOG_CRIT,
        #           LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG.
        # Facilities: LOG_KERN, LOG_USER, LOG_MAIL, LOG_DAEMON, LOG_AUTH,
        #             LOG_LPR, LOG_NEWS, LOG_UUCP, LOG_CRON, LOG_SYSLOG
        #             and LOG_LOCAL0 to LOG_LOCAL7.
        # Options: LOG_PID, LOG_CONS, LOG_NDELAY, LOG_NOWAIT and LOG_PERROR
        syslog.openlog(
          "DNStap", logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON
        )
        pid = "/var/run/dnstap.pid"
        daemon = Daemonize(app="DNStap", pid=pid,
                           action=main, auto_close_fds=True)
        # ok, going in to darkness
        # https://daemonize.readthedocs.io/en/latest/
        daemon.start()
    else:
        main()
