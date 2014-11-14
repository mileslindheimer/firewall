#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:

    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        f = open(config['rule'])
        self.rules = []
        while True:
            line = f.readline()
            if line == "":
                break
            elif line[0] == "%" or line[0] == "\n":
                continue
            else:
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
        ip = rule[2]
        port = None if len(rule) < 5 else int(rule[3])
        return verdict, protocol_or_dns, ip, port

    def ip_match(self, rule_ip, pkt_ip):
        # check if rule_ip is a country or just a regular address
        # if it's a country, do binary search on pkt_ip (country, base, bound) record
            # if the country matches that of the search record, the ip matches
        # else check if the rule_ip matches the pkt_ip

    def port_match(self, rule_port, pkt_port):
        return rule_port is None or rule_port == pkt_port

    def prot_type_match(self, prot_type, pkt_prot):
        return prot_type == 'dns' or prot_type == pkt_prot

    def rule_matches(self, rule, pkt):
        _, prot_type, rule_ip, rule_port = self.parse_rule(rule)
        pkt_prot = socket.htons(struct.unpack('!B', pkt[9:10]))
        src_ip = socket.htonl(struct.unpack('!L', pkt[12:16]))
        dst_ip = socket.htonl(struct.unpack('!L', pkt[16:20]))
        head_length = socket.htonl(ord(pkt[:1])) # need to get 4 bits from 8 here
        src_port = socket.htonl(struct.unpack('!L', pkt[head_length:(head_length + 2)]))
        dst_port = socket.htonl(struct.unpack('!L', pkt[(head_length + 2):(head_length + 4)])
        return (self.ip_match(prot_type, rule_ip, src_ip)
                and self.ip_match(prot_type, rule_ip, dst_ip)
                and self.prot_type_match(prot_type, pkt_prot)
                and self.port_match(rule_port, pkt_port))

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            send = self.iface_int.send_ip_packet
        else: 
            send = self.iface_ext.send_ip_packet
        for rule in self.rules:
            verdict = rule[0]
            if self.rule_matches_packet(rule, pkt) and verdict == 'drop':
                continue
            send(pkt)
