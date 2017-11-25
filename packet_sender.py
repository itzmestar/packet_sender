#!/usr/bin/python2
import sys, random
from scapy.all import *

#----global variables---#
dest_IP=""
intf=""
type=0
message=""

#-----function definition----#

#prints program usage on screen 
def usage():
	print 'Usage : ./packet_sender <ip_address> <interface> <type> <message>'
	print 'Where :' 
	print '\tip_address : Destination IP address'
	print '\tinterface  : Source ethernet interface'
	print '\ttype       : 0 -> ICMP Echo Request Message Or 1 -> TCP SYN packet to port 80'
	print '\tmessage    : message to be sent in packet' 
	
#prints error message on screen & exits program
#arg1 -> 1st value in error message
#arg2 -> 2nd value in error message
def print_error(arg, value):
	print 'Error: Invalid argument "%s" value: "%s" provided! Exiting...' % (arg, value)
	usage()
	sys.exit()

#prints sending info 
def print_send_info(proto):
	print "\nSending %s packet:" % (proto)
	
#creates raw IP packet with default values
# sets the identification field in packet
# sets DO NOT FRAGMENT flag
# sets FRAGMENTATION OFFSET value
# arg1 -> identification 
# arg2 -> character to be sent in identification field
# arg3 -> fragmentation offset value
# return -> IP packet
def create_ip_packet(id, char, n):
	try:
		pkt=IP(dst=dest_IP)
		msg=ord(char)
		iden = id | (msg << 8)
		#print hex(id) , hex((msg << 8))
		pkt.id = iden
		#print hex(pkt.id)
		pkt.flags = 0b010 #set DO NOT FRAGMENT flag
		#print pkt.flags
		pkt.frag = n
	except socket.gaierror as e:
		(error, string) = e
		if error == -2:
			print 'Error: Invalid IP address: "%s" provided. Exiting...' % (dest_IP)
			sys.exit() 
		else:
			print '%s' % (e)
	except:
		print 'Some Exception occured'
	return pkt

#sends n number of ICMP packets where n is the length of message
# arg1 -> message	
def send_icmp(msg):
	global intf
	id=generate_id()
	#send n number of packets
	for i in range(0,len(msg)):
		pkt=create_ip_packet(id, msg[i], i)/ICMP(id=id, seq=i+1)
		print_send_info('IPv4/ICMP')
		pkt.show()
		#print hex(pkt.frag)
		send_packet(pkt,intf)
		
	#send last packet with message length
	pkt=create_ip_packet(id, '\0', len(msg))/ICMP(id=id, seq=len(msg)+1)
	#put the last bit high of frag offset
	pkt.frag = pkt.frag | (1<<12)
	#print hex(pkt.frag)
	print_send_info('IPv4/ICMP')
	pkt.show()
	send_packet(pkt,intf)

#sends n number of TCP SYN packets to port 80 where n is the length of message
# arg1 -> message
def send_tcp(msg):
	global intf
	id=generate_id()
	#send n number of packets
	for i in range(0,len(msg)):
		pkt=create_ip_packet(id, msg[i], i)/TCP()
		print_send_info('IPv4/TCP')
		pkt.show()
		#print hex(pkt.frag)
		send_packet(pkt,intf)
		
	#send last packet with message length
	pkt=create_ip_packet(id, '\0', len(msg))/TCP()
	#put the last bit high of frag offset
	pkt.frag = pkt.frag | (1<<12)
	#print hex(pkt.frag)
	print_send_info('IPv4/TCP')
	pkt.show()
	send_packet(pkt,intf)

#gererate a random number between 1 & 0xfe 
# return -> random number
def generate_id():
	n = random.randint(1,0xfe)
	return n

#sends the packet over the provided interface
# arg1 -> packet to be sent
# arg2 -> interface on which packet will be sent
def send_packet(pkt,interface):
	try:
		send(pkt)
		#sr(pkt, iface=interface, timeout=2)
	except socket.error as e:
		(error, string) = e
		if error == 19:
			print 'Error: Invalid Interface %s provided. Exiting...' % (interface)
			sys.exit()
		else:
			print '%s' % (e)
	except:
		print 'Some Exception occured'
		

#-----main starts here----#

#check for arguments
if len(sys.argv) != 5:
	usage()
	sys.exit()
	
dest_IP=sys.argv[1]
intf=str(sys.argv[2])
type=int(sys.argv[3])
message=str(sys.argv[4])

if len(message) >= (1<<8):
	print "Error: cannot send message with len > %d. Provided message len: %d" % ((1<<8)-1, len(message))

#send ICMP packet if type is 0	
if type == 0:
	send_icmp(message)
	pass
#send TCP packet if type is 1	
elif type == 1:
	send_tcp(message)
#else print error & exit
else:
	print_error("type", str(type))