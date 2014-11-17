import socket
import struct

geoipdb = []
db = open("geoipdb.txt")
while True:
    line = db.readline()
    if line == "":
        break
    line = line.split()
    country = line[2]
    base = struct.unpack('!L', socket.inet_aton(line[0]))[0]
    bound = struct.unpack('!L', socket.inet_aton(line[1]))[0]
    geoipdb.append((country, base, bound))
db.close()

def bin_search(arr, v):
    if len(arr) == 1:
        return arr[0][0]
    m = len(arr)/2
    if v < arr[m][1]:
        return bin_search(arr[:m], v)
    elif v > arr[m][2]:
        return bin_search(arr[m+1:], v)
    else:
        return arr[m][0]

if bin_search(geoipdb, struct.unpack("!L", socket.inet_aton('1.0.64.0'))[0]) == 'JP':
    print "pass"
else:
    print "fail"
if bin_search(geoipdb, struct.unpack("!L", socket.inet_aton('1.0.255.255'))[0]) == 'TH':
    print "pass"
else:
    print "fail"
if bin_search(geoipdb, struct.unpack("!L", socket.inet_aton('1.2.5.6'))[0]) == 'CN':
    print "pass"
else:
    print "fail"
if bin_search(geoipdb, struct.unpack("!L", socket.inet_aton('1.4.0.81'))[0]) == 'AU':
    print "pass"
else:
    print "fail"
if bin_search(geoipdb, struct.unpack("!L", socket.inet_aton('1.97.212.200'))[0]) == 'KR':
    print "pass"
else:
    print "fail"
if bin_search(geoipdb, struct.unpack("!L", socket.inet_aton('5.10.77.112'))[0]) == 'NL':
    print "pass"
else:
    print "fail"
