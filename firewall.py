#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct
import re
import ast

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
                self.rules.append(self.parse_rule(line))
        f.close()
        db = open("geoipdb.txt")
        while True:
            line = db.readline()
            if line == "":
                break
            line = line.split()
            country = line[2]
            base = struct.unpack('!L', socket.inet_aton(line[0]))[0]
            bound = struct.unpack('!L', socket.inet_aton(line[1]))[0]
            self.geoipdb.append((country, base, bound))
        db.close()

    def regex_transform(self, domain):
        if len(domain) == 1:
            return domain
        elif domain[0] == "*":
            return ".*" + self.regex_transform(domain[1:])
        elif domain[0] == ".":
            return "\." + self.regex_transform(domain[1:])
        return domain[0] + self.regex_transform(domain[1:])

    def bin_search(self, arr, v):
        if len(arr) == 1:
            return arr[0][0]
        m = len(arr)/2
        if v < arr[m][1]:
            return self.bin_search(arr[:m], v)
        elif v > arr[m][2]:
            return self.bin_search(arr[m+1:], v)
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
            protocol_or_dns = rule[1]
        if protocol_or_dns == 'dns':
            ip = re.compile(self.regex_transform(rule[2]))
        else:
            try:
                ip = struct.unpack('!L', socket.inet_aton(rule[2]))
            except socket.error:
                try:
                    addr, prefix = rule[2].split('/')
                    ip = (struct.unpack('!L', socket.inet_aton(addr))[0], int(prefix))
                except:
                    ip = rule[2]
        if len(rule) < 4:
            port = None
        elif rule[3] == 'any':
            port = 'any'
        else:
            try:
                port = int(rule[3])
            except ValueError:
                port = ast.literal_eval(re.sub("-", ",", rule[3]))
        return (verdict, protocol_or_dns, ip, port)

    def unpack_pkt(self, pkt, pkt_dir):
        head_length = 4 * (ord(pkt[:1]) & 0b00001111)
        if head_length < 20:
            return None
        protocol = struct.unpack('!B', pkt[9:10])[0]
        if pkt_dir == PKT_DIR_INCOMING:
            ip = struct.unpack('!L', pkt[12:16])[0]
            port = struct.unpack('!H', pkt[head_length:(head_length + 2)])[0]
        else:
            ip = struct.unpack('!L', pkt[16:20])[0]
            port = struct.unpack('!H', pkt[(head_length + 2):(head_length + 4)])[0]
        if port == 53 and protocol == 17:
            qdcount = struct.unpack('!H', pkt[(head_length + 12):(head_length + 14)])[0]
            if qdcount == 1:
                ext_length = ord(pkt[head_length + 20])
                base = head_length + 21
                i = 0
                domain = ""
                while pkt[base + i] != '\x00':
                    if i == ext_length:
                        ext_length, base = ord(pkt[base + i]), base + ext_length + 1
                        domain += "."
                        i = 0
                    else:
                        domain += pkt[base + i]
                        i += 1
                i += 1
                q_type = struct.unpack('!H', pkt[base + i: base + i + 2])[0]
                q_class = struct.unpack('!H', pkt[base + i + 2:base + i + 4])[0]
                if (q_type == 1 or q_type == 28) and q_class == 1:
                    return (head_length, protocol, ip, port, domain)
            return None
        port = ord(pkt[head_length]) if protocol == 1 else port
        return (head_length, protocol, ip, port)

    def port_match(self, rule_port, pkt_port):
        if isinstance(rule_port, tuple):
            return pkt_port >= rule_port[0] and pkt_port <= rule_port[1]
        return rule_port == 'any' or rule_port == pkt_port

    def ip_match(self, rule_ip, pkt_ip):
        if isinstance(rule_ip, str) == 2:
            return self.bin_search(self.geoipdb, pkt_ip) == rule_ip
        if isinstance(rule_ip, tuple):
            rule_ip = rule_ip[0] & (4294967295 >> (32 - rule_ip[1]) << (32 - rule_ip[1]))
            return (pkt_ip & rule_ip) == rule_ip
        return rule_ip == 'any' or rule_ip == pkt_ip

    def rule_matches(self, rule, pkt, pkt_dir, verdict):
        if rule[1] == 'dns' and len(pkt) == 5 and rule[2].match(pkt[4]) is not None:
            return rule[0]
        match = ((rule[1] == 'any' or rule[1] == pkt[1])
                 and self.ip_match(rule[2], pkt[2])
                 and self.port_match(rule[3], pkt[3]))
        return rule[0] if match else verdict

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        unpacked_pkt = self.unpack_pkt(pkt, pkt_dir)
        verdict = 'pass'
        if unpacked_pkt is not None:
            for rule in self.rules:
                verdict = self.rule_matches(rule, unpacked_pkt, pkt_dir, verdict)
            if verdict == 'pass':
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_int.send_ip_packet(pkt)
                else:
                    self.iface_ext.send_ip_packet(pkt)
