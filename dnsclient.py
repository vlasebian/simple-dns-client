#!/usr/bin/python

"""
    This is a simple dnsclient that supports A, AAAA, MX, SOA, NS and CNAME
    queries written in python.

"""

import sys
import socket
import binascii

import src.serverconf as serverconf
import src.queryfactory as queryfactory
import src.queryhandler as queryhandler


def main():
    """ Main function of the DNS client
    """

    usage()

    query_elem = sys.argv[1]
    query_type = sys.argv[2]

    ### Create packet according to the requested query
    packet = ""
    query = queryfactory.get_dns_query(query_elem, query_type)

    # query[0] is the packet
    packet = query[0]

    raw_reply = query_dns_server(packet)
    # query[1] is qname length
    reply = queryhandler.parse_answer(raw_reply, query[1])
    queryhandler.print_reply(reply)

    return 0

def query_dns_server(packet):
    """ Function used to create a UDP socket, to send the DNS query to the server
        and to receive the DNS reply.

    Args:
        packet = the DNS query message
    
    Returns:
        The reply of the server

    If none of the servers in the dns_servers.conf sends a reply, the program
    exits showing an error message.

    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print "[Error]: Faild to create socket. Exiting..."
        exit(1)

    # get DNS server IPs from dns_servers.conf file
    dns_servers = serverconf.read_file()
    # default port for DNS
    server_port = 53

    for server_ip in dns_servers:
        got_response = False

        # send message to server
        sock.sendto(packet, (server_ip, server_port))
        # receive answer
        recv = sock.recvfrom(1024)

        # if no answer is received, try another server
        if recv:
            got_response = True
            break

    # output error message if no server could respond
    if not got_response:
        print "[Error]: No response received from server. Exiting..."
        exit(0)

    return recv[0]

def usage():
    """ Function that checks if the required arguments are given 
    """

    if len(sys.argv) != 3:
        print "Usage: ./dnsclient.py <DNS name/IP> <query type>"
        exit(0)

if __name__ == "__main__":
    main()
