#!/usr/bin/env python
#
# ipytraf.py
#
# (c) Franck LABADILLE  ; franck {at} kernlog [dot] net
# IRC : Franck @ irc.oftc.net
#       
# Version 0.4  ; 2012-01-04
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS 0AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# ipytraf stocks iptables_logs in database while displaying them by osd
# and offer you a frontend to look at them
#
#
###############################################################################
###############################################################################
###########                            CHANGELOG                     ##########
###############################################################################
###############################################################################
#
##############
## Changelog 0.1
##############
#
#
#
###############################################################################
###############################################################################
############                             TODO                        ##########
###############################################################################
###############################################################################
#
#
#
#
#
#
#                                    ~~~~~~~~~
#                                    ~ FIXED ~
#                                    ~~~~~~~~~
#
###############################################################################
###############################################################################
#########                   BEGINNING  OF  ipytraf.py                 #########
###############################################################################
###############################################################################

import time
import re
import os
import sys
import socket
from datetime import datetime
import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Table, Column, Integer, String, DateTime
from sqlalchemy.orm import relationship, backref, sessionmaker
import subprocess
import pyosd

import pdb

logfile = "/var/log/iptables.log"
database = os.path.join(os.path.expanduser("~"), ".ipytraf-dev.db")
errorfile = os.path.join(os.path.expanduser("~"), ".ipytraf-dev_errors")
IpytrafBase = declarative_base()
osdconf = {
    "ip_pingi": {
        "position": "top",
        "align": "right",
        "colour": "white",
        "timeout": 3,
        "h_offset": 0,
        "v_offset": 20,
        "font": "-*-helvetica-*-*-*-*-16-*-*-*-*-*-*-*"
        },
    "ip_pingo": {
        "position": "top",
        "align": "right",
        "colour": "white",
        "timeout": 1,
        "h_offset": 0,
        "v_offset": 20,
        "font": "-*-helvetica-*-*-*-*-16-*-*-*-*-*-*-*"
        },
    "ip_2": {
        "position": "top",
        "align": "right",
        "colour": "blue",
        "timeout": 2,
        "h_offset": 0,
        "v_offset": 20,
        "font": "-*-helvetica-*-*-*-*-16-*-*-*-*-*-*-*"
        },
    "ip_intruder": {
        "position": "top",
        "align": "right",
        "colour": "cyan",
        "timeout": 5,
        "h_offset": 0,
        "v_offset": 20,
        "font": "-*-helvetica-*-*-*-*-16-*-*-*-*-*-*-*"
        },
    "ip_server": {
        "position": "top",
        "align": "right",
        "colour": "green",
        "timeout": 5,
        "h_offset": 0,
        "v_offset": 20,
        "font": "-*-helvetica-*-*-*-*-16-*-*-*-*-*-*-*"
        },
    "ip_reject": {
        "position": "top",
        "align": "right",
        "colour": "black",
        "timeout": 3,
        "h_offset": 0,
        "v_offset": 20,
        "font": "-*-helvetica-*-*-*-*-16-*-*-*-*-*-*-*"
        },
    "ip_newport": {
        "position": "top",
        "align": "right",
        "colour": "red",
        "timeout": 5,
        "h_offset": 0,
        "v_offset": 20,
        "font": "-*-helvetica-*-*-*-*-16-*-*-*-*-*-*-*"
        },
    "ip_strange": {
        "position": "middle",
        "align": "center",
        "colour": "red",
        "timeout": 5,
        "h_offset": 0,
        "v_offset": 20,
        "font": "-*-helvetica-*-*-*-*-16-*-*-*-*-*-*-*"
        },
    "ip_invalid": {
        "position": "middle",
        "align": "center",
        "colour": "cyan",
        "timeout": 5,
        "h_offset": 0,
        "v_offset": 20,
        "font": "-*-helvetica-*-*-*-*-16-*-*-*-*-*-*-*"
        }
}

class LogParser:
    """ """
    def __init__(self, lines2parse):
        """ """
        self.lines2parse = lines2parse
        self.keeped_data = []
        self._clearlog()

    def _clearlog(self):
        self.log = {}
        self.log["year"] = ""
        self.log["month"] = ""
        self.log["day"] = ""
        self.log["time"] = ""
        self.log["tz"] = ""
        self.log["timestamp"] = ""
        self.log["hostname"] = ""
        self.log["uptime"] = ""
        self.log["logname"] = ""
        self.log["inetin"] = ""
        self.log["inetout"] = ""
        self.log["mac"] = ""
        self.log["srcip"] = ""
        self.log["dstip"] = ""
        self.log["leng"] = ""
        self.log["tos"] = ""
        self.log["prec"] = ""
        self.log["ttl"] = ""
        self.log["iden"] = ""
        self.log["protocole"] = ""
        self.log["sport"] = ""
        self.log["dport"] = ""
        self.log["window"] = ""
        self.log["res"] = ""
        self.log["flag"] = ""
        self.log["urgp"] = ""
        self.log["lenudp"] = ""
        self.log["icmptype"] = ""
        self.log["icmpcode"] = ""
        self.log["icmpiden"] = ""
        self.log["icmpseq"] = ""

    def _iptablebase(self, line):
        base = re.match(r"""
            (\d{4})-                           # 1 year
            (\d{2})-                           # 2 month
            (\d{2})T                           # 3 day
            (\d{2}:\d{2}:\d{2}.\d{6})          # 4 time
            (.\d{2}:\d{2})\s                   # 5 tz
            (\w+)\s                            # 6 hostname
            kernel:\s
            \[\s?(\d+\.\d+)\]\s                   # 7 uptime
            \[(ip_.+)\]                        # 8 iptable log-prefix
            IN=(\w*)\s                         # 9 interface in
            OUT=(\w*)\s                        # 10 inet out
            (MAC=((\w:)+)\s)?                  # 11 mac adre
            .+
            """, line, re.VERBOSE)

        if base:
            self.log["year"] = int(base.group(1))
            self.log["month"] = int(base.group(2))
            self.log["day"] = int(base.group(3))
            self.log["time"] = base.group(4)
            self.log["hour"] = int(self.log["time"].split(":")[0])
            self.log["minute"] = int(self.log["time"].split(":")[1])
            self.log["secondes"] = self.log["time"].split(":")[2]
            self.log["seconde"] = int(self.log["secondes"].split(".")[0])
            self.log["useconde"] = int(self.log["secondes"].split(".")[1])
#            self.log["tz"] = base.group(5)
            self.log["tz"] = 0
            self.log["timestamp"] = datetime(self.log["year"], \
                        self.log["month"], self.log["day"], self.log["hour"],\
                        self.log["minute"], self.log["seconde"], \
                        self.log["useconde"] + self.log["tz"])
            self.log["hostname"] = base.group(6)
            self.log["uptime"] = base.group(7)
            self.log["logname"] = base.group(8)
            self.log["inetin"] = base.group(9)
            self.log["inetout"] = base.group(10)
            if base.group(11):
                self.log["mac"] = base.group(11)
        else:
            with open(errorfile, "a") as fp:
                fp.write(line)
            print("Need to config regex base in iptraffic.py {}\
                                        ".format(self.log["timestamp"]))
       
    def _iptableip(self, line):
        packet = re.match(r"""
                .+
                SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s # 1 ip address
                DST=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s # 2 ip address
                LEN=(\d+)\s                                # 3 len
                TOS=(\wx\w\w)\s                            # 4 tos
                PREC=(\wx\w\w)\s                           # 5 prec
                TTL=(\d+)\s                                # 6 TTL
                ID=(\d+)\s                                 # 7
                .+
                """, line, re.VERBOSE)
        if packet:
                self.log["srcip"] = packet.group(1)
                self.log["dstip"] = packet.group(2)
                self.log["leng"] = packet.group(3)
                self.log["tos"] = packet.group(4)
                self.log["prec"] = packet.group(5)
                self.log["ttl"] = packet.group(6)
                self.log["iden"] = packet.group(7)
        else:
            with open(errorfile, "a") as fp:
                fp.write(line)
            print("Need to conf regex packet in ipytraf.py {}\
                                        ".format(self.log["timestamp"]))

    def _iptabletcp(self, line):
        ptcp = re.match(r"""
            .+
            D?F?\s?PROTO=TCP\s                  #  TCP
            SPT=(\d{1,5})\s                    # 1 source port   
            DPT=(\d{1,5})\s                    # 2 dest port     
            WINDOW=(\d+)\s                     # 3 window              
            RES=(\wx\w\w)\s                    # 4 
            ([A-Z]{3})\s                       # 5 SYN ACK flags
            URGP=(\d+)                         # 6 urgp
            """, line, re.VERBOSE)
        if ptcp:
            self.log["protocole"] = "tcp"
            self.log["sport"] = ptcp.group(1)
            self.log["dport"] = ptcp.group(2)
            self.log["window"] = ptcp.group(3)
            self.log["res"] = ptcp.group(4)
            self.log["flag"] = ptcp.group(5)
            self.log["urgp"] = ptcp.group(6)

    def _iptableudp(self, line):
        pudp = re.match(r"""
            .+
            PROTO=UDP\s                      #  UDP
            SPT=(\d{1,5})\s                    # 1 source port   
            DPT=(\d{1,5})\s                    # 2 dest port     
            LEN=(\d+)                          # 3 len
            """, line, re.VERBOSE)
        if pudp:
            self.log["protocole"] = "udp"
            self.log["sport"] = pudp.group(1)
            self.log["dport"] = pudp.group(2)
            self.log["lenudp"] = pudp.group(3)

    def _iptableicmp(self, line):
        picmp = re.match(r"""
            .+
            DF\sPROTO=ICMP\s                 #  ICMP
            TYPE=(\d{1,3})\s                   # 1 type
            CODE=(\d{1,2})+\s                  # 2 code
            ID=(\d)+\s                         # 3 id
            SEQ=(\d+)                          # 4 seq
            """, line, re.VERBOSE)
        if picmp:
            self.log["protocole"] = "icmp"
            self.log["icmptype"] = picmp.group(1)
            self.log["icmpcode"] = picmp.group(2)
            self.log["icmpiden"] = picmp.group(3)
            self.log["icmpseq"] = picmp.group(4)

    def _iptableproto2(self, line):
        pproto2 = re.match(r"""
            .+
            DF\sPROTO=2
            """,line, re.VERBOSE)
        if pproto2:
            self.log["protocole"] = "2"

    def iptablelog(self):
        """ return list of log_dict """
        raw_logs = re.findall(r".+\[ip_.+\].+", self.lines2parse)
        for raw in raw_logs:
            lines = raw.splitlines()
            for line in lines:
                self._iptablebase(line)
                self._iptableip(line)
                self._iptabletcp(line)
                self._iptableudp(line)
                self._iptableicmp(line)
                self._iptableproto2(line)
                self.keeped_data.append(self.log)
                self._clearlog()
        return self.keeped_data

class IptableLog(IpytrafBase):
    """ """
    __tablename__ = 'ipytraf'
    timestamp = Column(DateTime, primary_key=True)
    hostname = Column(String, nullable=False)
    uptime = Column(String, nullable=False)
    logname = Column(String, nullable=False)
    inetin = Column(String)
    inetout = Column(String)
    mac = Column(String)
    srcip = Column(String)
    dstip = Column(String)
    leng = Column(Integer)
    tos = Column(String)
    prec = Column(String)
    ttl = Column(Integer)
    iden = Column(Integer)
    protocole = Column(String)
    sport = Column(String)
    dport = Column(String)
    window = Column(Integer)
    res = Column(String)
    flag = Column(String)
    urgp = Column(String)
    lenudp = Column(Integer)
    icmptype = Column(Integer)
    icmpcode = Column(Integer)
    icmpiden = Column(Integer)
    icmpseq = Column(Integer)

    def __init__(self, data):
        """ data is a dictionnary of logs"""
        self.timestamp = data["timestamp"]
        self.hostname = data["hostname"]
        self.uptime = data["uptime"]
        self.logname = data["logname"]
        self.inetin = data["inetin"]
        self.inetout = data["inetout"]
        self.mac = data["mac"]
        self.srcip = data["srcip"]
        self.dstip = data["dstip"]
        self.leng = data["leng"]
        self.tos = data["tos"]
        self.prec = data["prec"]
        self.ttl = data["ttl"]
        self.iden = data["iden"]
        self.protocole = data["protocole"]
        self.sport = data["sport"]
        self.dport = data["dport"]
        self.window = data["window"]
        self.res = data["res"]
        self.flag = data["flag"]
        self.urgp = data["urgp"]
        self.lenudp = data["lenudp"]
        self.icmptype = data["icmptype"]
        self.icmpcode = data["icmpcode"]
        self.icmpiden = data["icmpiden"]
        self.icmpseq = data["icmpseq"]

    def __repr__(self):
        return """<IptableLog('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}',
                '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', 
                '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')>
                """.format(self.timestamp, self.hostname, self.uptime,
                self.logname, self.inetin, self.inetout, self.mac, self.srcip,
                self.dstip, self.leng, self.tos, self.prec, self.ttl, 
                self.iden, self.protocole, self.sport, self.dport, self.window,
                self.res, self.flag, self.urgp, self.lenudp, self.icmptype, 
                self.icmpcode, self.icmpiden, self.icmpseq)
    
class DbHandler:
    def __init__(self, database):
        #from sqlalchemy import create_engine
        self.eng = create_engine("sqlite:///{}".format(database))
        #from sqlachemy.ext.declarative import declarative_base
        IpytrafBase.metadata.create_all(self.eng)
        #fromsqlalchemy.orm import sessionmaker
        Session = sessionmaker(bind=self.eng)
        self.session = Session()

    def addnewlog(self, d):
        """ """
        try:
            u = IptableLog(d)
            self.session.add(u)
            self.session.commit()
            return True
        except sqlalchemy.exc.IntegrityError:
            return False

    def checktimestamp(self, d):
        existing_log = (
            self.session.query(IptableLog)
                .filter_by(timestamp=d["timestamp"])
                ).count()
        if existing_log:
            return False
        else:
            return True
           
class OsdDisplay:
    """ """
    def __init__(self, data, conf):
        """ """
        self.data = data
        self.conf = conf
        self.p = pyosd.osd()

    def _makeosdmsg(self):
        """ """
        def pinghandler():
            if self.data["srcip"] == socket.gethostbyname (\
                                                socket.gethostname())\
                and self.data["icmptype"] == "8":
                msg = "ICMP probe to {}".format(self.data["dstip"])
                osdconf = self.conf["ip_pingo"]
            elif self.data["dstip"] == socket.gethostbyname(\
                                                socket.gethostname())\
                and self.data["icmptype"] == "0":
                msg = "ICMP SCAN from {}".format(self.data["srcip"])
                osdconf = self.conf["ip_pingi"]
            else:
                msg = "ICMP from {} to {}, type {}".format(self.data["srcip"],\
                    self.data["dstip"], self.data["icmptype"])
                osdconf = self.conf["ip_pingi"]
            return (msg, osdconf)

        def tcpudphandler():
            if self.data["protocole"] == "tcp":
                msg = "tcp out to {}:{}".format(self.data["dstip"],\
                                                        self.data["dport"])
                osdconf = self.conf["ip_newport"]

            elif self.data["protocole"] == "udp":
                mgg = "udp out to {}:{}".format(self.data["dstip"],\
                                                        self.data["dport"])
                osdconf = self.conf["ip_newport"]
            else:
                with open(errorfile, "a") as fp:
                    fp.write(self.data)
                msg = "tcp/udp log handling curiously, see {}\
                                                        ".format(errorfile)
                print(msg)
                osdconf = self.conf["ip_strange"]
            return (msg, osdconf)
                
        if self.data["protocole"] == "2":
            msg = "packet protocole 2 sent to {}".format(self.data["dstip"])
            osdconf = self.conf["ip_2"]
        elif self.data["logname"] == "ip_ping":
            (msg, osdconf) = pinghandler()
        elif self.data["logname"] == "ip_intruder":
            msg = "{} attack from {}:{} on port {}\
                ".format(self.data["protocole"], self.data["srcip"], \
                self.data["sport"], self.data["dport"])
            osdconf = self.conf["ip_intruder"]
        elif self.data["logname"] == "ip_server":
            msg = "{} {} connects to port {}".format(self.data["srcip"],\
                self.data["protocole"], self.data["dport"])
            osdconf = self.conf["ip_server"]
        elif self.data["logname"] == "ip_reject":
            msg = "rejects {} on {}".format(self.data["srcip"],\
                self.data["dstip"])
            osdconf = self.conf["ip_reject"]
        elif self.data["logname"] == "ip_newport":
            (msg, osdconf) = tcpudphandler()
        elif self.data["logname"] == "ip_invalid":
            msg = "invalid from {}:{} to {}:{} dropped\
                ".format(self.data["srcip"], self.data["sport"],\
                self.data["dstip"], self.data["dport"])
            osdconf = self.conf["ip_invalid"]
        elif self.data["logname"] == "ip_strange":
            msg = "Special configuration from {}:{} to {}{}"\
                .format(self.data["srcip"], self.data["sport"],\
                        self.data["dstip"], self.data["dport"])
            osdconf = self.conf["ip_strange"]
        else:
            msg = "unexpected iptable log which does'nt match any filter"
            with open(errorfile, "a") as fp:
                fp.write(self.data)
            print("unexpected iptable log which does'nt match any filter")
            osdconf = self.conf["ip_strange"]
        return (msg, osdconf)

    def _osddisplay(self, message, osdconf):
        """Method to o.s.d. with pyosd"""
        ###
        ### Change self.__dict__ dans __init__
        ###
        self.msg = message
        self.p.set_font(osdconf["font"])
        self.p.set_colour(osdconf["colour"])
        self.p.set_timeout(osdconf["timeout"])
        if osdconf["position"] == "top":
            self.p.set_pos(0)
        elif osdconf["position"] == "middle":
            self.p.set_pos(2)
        elif osdconf["position"] == "bottom":
            self.p.set_pos(1)
        else:
            self.p.set_pos(2)

        if osdconf["align"] == "left":
            self.p.set_align(0)
        elif osdconf["align"] == "center":
            self.p.set_align(1)
        elif osdconf["align"] == "right":
            self.p.set_align(2)
        else:
            self.p.set_align(1)

        self.p.set_horizontal_offset(osdconf["h_offset"])
        self.p.set_vertical_offset(osdconf["v_offset"])
        self.p.display(self.msg)
        self.p.wait_until_no_display()

    def show(self):
        (msg, osdconf) = self._makeosdmsg()
        try:
            pid = subprocess.Popen(self._osddisplay(msg, osdconf)).pid
        except TypeError:
            pass

class PreciseDisplay():
    def __init__(self, data):
        self.data = data

    def _tcpdata(self):
        msg = "{} : {} connect from {}:{} to {}:{}\
            ".format(self.data["timestamp"], self.data["protocole"],\
            self.data["srcip"], self.data["sport"], self.data["dstip"],\
                                                        self.data["dport"])
        return msg
    def _udpdisplay(self):
        msg = "{} : {} connect from {}:{} to {}:{}\
            ".format(self.data["timestamp"], self.data["protocole"],\
            self.data["srcip"], self.data["sport"], self.data["dstip"],\
                                                        self.data["dport"])
        return msg
    def _icmpdisplay(self):
        msg = "{} : {} from {} type {} to {}\
            ".format(self.data["timestamp"], self.data["protocole"],\
            self.data["srcip"], self.data["icmptype"], self.data["dstip"])
        return msg
    def _proto2display(self):
        msg = "{} : protocole 2 connect from {} to {}\
            ".format(self.data["timestamp"], self.data["srcip"],\
                                                        self.data["dstip"])
        return msg

    def showlog(self):
        if self.data["protocole"] == "tcp":
            msg = self._tcpdata()
        elif self.data["protocole"] == "udp":
            msg = self._udpdata()
        elif self.data["protocole"] == "icmp":
            msg = self._icmpdisplay()
        elif self.data["protocole"] == "2":
            msg = self._proto2display()
        else:
            msg = "protocole inconnu, voir fichier d'erreurs"
        print(msg)

if __name__ == "__main__":

    archive = DbHandler(database)
    def analyselog(data):
        p = LogParser(data)
        logs_of_interest = p.iptablelog()
        if logs_of_interest:
            for d in logs_of_interest:
                try:
                    if d["timestamp"]:
                        newdata = ""
                        newdata = archive.checktimestamp(d)
                        if newdata:
                            archive.addnewlog(d)
                            more = PreciseDisplay(d)
                            more.showlog()
                            osd = OsdDisplay(d, osdconf)
                            osd.show()
                except KeyError:
                    pass

    while True:  # turn it into check stats on logfile, for rotation
        try:
            with open(logfile, "r") as fp:
                logpipe = fp.read()
                
                while True:
                    if logpipe:
                        analyselog(logpipe)
                    else:
                        time.sleep(3)
                    logpipe = fp.readline()
        except KeyboardInterrupt:
            print("Keyboard interrupt")
            sys.exit(0)
