#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import re

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:

    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        f = open(config['rule'])
        self.rules = []
        self.geoipdb = []
        while True:
            line = f.readline()
            if line == "":
                break
            elif line[0] == "%" or line[0] == "\n":
                continue
            else:
                line = self.parse_rule(line)
                if line[2] == 'dns' and line[3] != 'any':
                    line[3] = re.compile(self.regex_transform(line[3]))
                self.rules.append(line)
        f.close()
        db = open("geoipdb.txt")
        while True:
            line = db.readline()
            if line == "":
                break
            line = line.split()
            country = line[2]
            base = struct.unpack('!L', socket.inet_aton(line[0]))
            bound = struct.unpack('!L', socket.inet_aton(line[1]))
            self.geoipdb.append((country, base, bound))
        db.close()

    def regex_transform(self, domain):
        if domain[0] == "*":
            return "\w*" + regex_transform(domain[1:])
        elif domain[0] == ".":
            return "\." + regex_transform(domain[1:])
        return domain[0] + regex_transform(domain[1:])

    def bin_search(self, arr, v):
        if len(arr) == 0:
            return
        m = int(len(arr)/2)
        if v < arr[m][1]:
            return self.bin_search(arr[:m], v)
        elif v > arr[m][2]:
            return self.bin_search(arr[m:], v)
        else:
            return arr[m][0]

    def parse_rule(self, rule):
        rule = rule.split()
        verdict = rule[0]
        if rule[1] == 'udp':
            protocol_or_dns = 17
        elif rule[1] == 'tcp':
            protocol_or_dns = 6
        elif rule[1] == 'icmp':
            protocol_or_dns = 1
        else:
            protocol_or_dns = 'dns'
        try:
            ip = struct.unpack('!L', socket.inet_aton(rule[2]))
        except socket.error:
            ip = rule[2]
        port = None if len(rule) < 5 else int(rule[3])
        return (verdict, protocol_or_dns, ip, port)

    # unpack dns needs domain at the end of tuple
    def unpack_packet(self, pkt, pkt_dir):
        head_length = ord(pkt[:1]) & 0b00001111
        if head_length < 5:
            return None
        protocol = struct.unpack('!B', pkt[9:10])[0]
        if pkt_dir == PKT_DIR_INCOMING:
            ip = struct.unpack('L', pkt[12:16])[0]
            port = struct.unpack('!L', pkt[head_length:(head_length + 4)])[0]
        else:
            ip = struct.unpack('!L', pkt[16:20])[0]
            port = struct.unpack('!L', pkt[(head_length + 4):(head_length + 8)])[0]
        if port == 53 and protocol == 17:
            qdcount = struct.unpack('!H', pkt[(head_length + 12):(head_length + 14)])
            if qdcount == 1:
                i = 20
                char = pkt[(head_length + i)]
                domain = ""
                while char != "":
                    i += 1
                    domain += char
                    char = pkt[(head_length + i)]
                return (head_length, protocol, ip, port, domain)
            return None
        return (head_length, protocol, ip, port)

    def ip_match(self, rule_ip, pkt_ip):
        if len(rule_ip) == 2:
            return self.bin_search(self.geoipdb, pkt_ip) == rule_ip
        return rule_ip == 'any' or rule_ip == pkt_ip
    def protocol_match(self, rule_prot, pkt_prot):
        print rule_prot, pkt_prot
        return rule_prot == pkt_prot
    def rule_matches(self, rule, pkt, pkt_dir, verdict):
        if rule[1] == 'dns' and len(pkt) == 5 and rule[2].match(pkt[4]) is not None:
            return rule[0]
        match = (self.protocol_match(rule[1], pkt[1])
                 and rule[2] == pkt[2]
                 and rule[3] == pkt[3])
        return rule[0] if match else verdict

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        unpacked_pkt = self.unpack_packet(pkt, pkt_dir)
        verdict = 'pass'
        if unpacked_pkt is not None:
            for rule in self.rules:
                verdict = self.rule_matches(rule, pkt, pkt_dir, verdict)
            if verdict == 'pass':
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_int.send_ip_packet(pkt)
                else:
                    self.iface_ext.send_ip_packet(pkt)
