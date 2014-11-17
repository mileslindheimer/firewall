import socket

'''UDP Tests'''
print 'testing dns rules'

print 'testing gethostbyname'
domains = ['google.com', 'stanford.edu', 'github.com', 'australia.gov.au']
for domain in domains:
    try:
        socket.gethostbyname(domain)
        print 'packet to/from %s passed' % domain
    except socket.gaierror:
        print 'packet to/from %s dropped' % domain

print 'end of tests'
