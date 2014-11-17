import socket

'''UDP Tests'''
print 'testing dns rules'

print 'testing gethostbyname'
domains = ['google.com', 'stanford.edu', 'gibhub.com', 'australia.gov.au']
for domain in domains:
    try:
        socket.gethostbyname(domain)
        print 'packet from %s passed' % domain
    except socket.gaierror:
        print 'packet from %s dropped' % domain

print 'Passed tests!'
