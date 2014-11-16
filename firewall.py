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
        self.geoipdb = []
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
        if rule[2] == 'any':
            ip = 'any'
        else:
            print rule[2]
            ip = struct.unpack('!L', socket.inet_aton(rule[2]))
        port = None if len(rule) < 5 else int(rule[3])
        return verdict, protocol_or_dns, ip, port

    def bin_search(self, arr, v):
        if len(arr) == 0:
            return
        m = int(len(arr)/2)
        if v < arr[m][1]:
            # v is less than base -> search left
            return self.bin_search(arr[:m], v)
        elif v > arr[m][2]:
            # v is greater than bound -> search right
            return self.bin_search(arr[m:], v)
        else:
            # v matches -> return country
            return arr[m][0]

    def ip_match(self, rule_prot, rule_ip, pkt_ip):
        # check if rule_ip is a country or just a regular address
        if rule_ip == 'any':
            return True
        if len(rule_ip) == 2:
            return self.bin_search(self.geoipd, pkt_ip) == rule_ip
        elif rule_prot == 'dns':
            # need to check pkt_ip is part of domain
            return self.dns_match(pkt_ip, rule_ip)
        return rule_ip == pkt_ip

    def port_match(self, rule_port, pkt_port):
        return rule_port is None or rule_port == pkt_port

    def prot_type_match(self, prot_type, pkt_prot):
        return prot_type == 'dns' or prot_type == pkt_prot

    def rule_matches(self, rule, pkt):
        _, prot_type, rule_ip, rule_port = self.parse_rule(rule)
        print struct.unpack('!L', pkt[12:16])[0]
        pkt_prot = socket.htons(struct.unpack('!B', pkt[9:10])[0])
        src_ip = socket.htonl(struct.unpack('!L', pkt[12:16])[0])
        dst_ip = socket.htonl(struct.unpack('!L', pkt[16:20])[0])
        head_length = ord(pkt[:1]) & 0b00001111
        src_port = socket.htonl(struct.unpack('!L', pkt[head_length:(head_length + 4)])[0])
        dst_port = socket.htonl(struct.unpack('!L', pkt[(head_length + 4):(head_length + 8)])[0])
        return (self.ip_match(prot_type, rule_ip, src_ip) and self.ip_match(prot_type, rule_ip, dst_ip) and self.prot_type_match(prot_type, pkt_prot) and self.port_match(rule_port, src_port))

    def dns_match(self, ip_addr, rule_ip):
        # still need to handle wildcards
        return domain == self.query_dns(ip_addr)

    def query_dns(self, ip_addr):
        # may need to return all aliases, not just hostname
        hostname, aliases, ipaddrs = socket.gethostbyaddr(ip_addr)
        return socket.getfqdn(hostname)

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        if pkt_dir == PKT_DIR_INCOMING:
            send = self.iface_int.send_ip_packet
        else: 
            send = self.iface_ext.send_ip_packet
        for rule in self.rules:
            verdict = rule[0]
            head_length = ord(pkt[:1]) & 0b00001111
            if head_length < 5 or self.rule_matches(rule, pkt) and verdict == 'drop':
                continue
            send(pkt)
