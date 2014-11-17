# if doesn't run with just sudo ./curltest.sh,
# run chmod +x curltest.sh and then sudo ./curltest.sh
echo testing google.com
curl http://www.google.com/

echo testing facebook.com
curl http://www.facebook.com/

echo testing *.gov
curl http://www.usa.gov/
curl http://www.ca.gov/

echo testing au
curl http://www.australia.gov.au/

echo testing de
curl http://www.spiegel.de/international/

echo testing *.org
curl http://www.kiva.org/
curl http://www.yosemite.org/
