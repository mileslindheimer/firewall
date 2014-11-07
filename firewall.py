#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

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


        # TODO: Load the firewall rules (from rule_filename) here.
        #print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
                #config['rule']

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        send = self.iface_int.send_ip_packet if pkt_dir == PKT_DIR_INCOMING else self.iface_ext.send_ip_packet
        for rule in self.rules:
            verdict, rule_type, ip, port = self.parse_rule(rule)
            #if not self.ip_okay(packet_ip):
            #    continue
            #if is_protocol(rule_type) and not self.port_ok(packet_port):
            #    continue
        send(pkt)
            #break

    def parse_rule(self, rule):
        rule = rule.split()
        verdict = rule[0]
        rule_type = rule[1]
        ip = rule[2]
        port = None if len(rule) < 5 else rule[3]
        return verdict, rule_type, ip, port

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
