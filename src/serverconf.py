"""
    This module is used for reading DNS servers IPs used for querying.
"""

# from socket import inet_aton
import os

def read_file():
    dns_servers = []

    # Read the file
    try:

        # Open dns_servers.conf which is in another directory
        crt_dir = os.path.dirname(__file__)
        file_path = os.path.join(crt_dir, '../conf/dns_servers.conf')

        input_file = open(file_path, "r")
        dns_servers = input_file.readlines()

        input_file.close()
    except IOError:
        print "Error: dns_servers.conf cannot be opened. Exiting..."
        exit(1)


    # Erase comments from the lines read and convert strings to ip form
    ips = []
    for line in dns_servers:
        if not line.startswith("#") and not line.startswith("\n"):
            #ips.append(inet_aton(line))
            ips.append(line)

    return ips
