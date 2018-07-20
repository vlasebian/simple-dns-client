"""
    Module used for creating DNS queries.
"""

from struct import pack
from os import getpid

# Opcodes
QUERY = 0
IQUERY = 1
STATUS = 2

def create_header(opcode):
    """ Function used to create a DNS query header.
    
    Args:
        opcode = opcode of the query. It can take the following values:
            QUERY = 0, IQUERY = 1, STATUS = 2

    Returns:
        The header

    """

    header = ''
    flags = ''

    # Message ID
    header += pack(">H", getpid())

    # Flags (QR, opcode, AA, TC, RD, RA, Z, RCODE)
    if opcode == QUERY:
        # Standard DNS query
        flags = 0b0000000100000000
    elif opcode == IQUERY:
        flags = 0b0000100100000000
    elif opcode == STATUS:
        flags = 0b0001000100000000

    header += pack(">H", flags)

    # QDCOUNT
    header += pack(">H", 1)
    # ANCOUNT
    header += pack(">H", 0)
    # NSCOUNT
    header += pack(">H", 0)
    # ARCOUNT
    header += pack(">H", 0)

    return header

def get_dns_query(domain_name, query_type):
    """ Function used to create a DNS query question section.
    
    Args:
        domain_name = the domain name that needs to be resolved
        query_type = the query type of the DNS message

    Returns:
        The DNS query question section and the length of the qname in a tuple
        form: (question, qname_len)

    """

    # QNAME
    qname = create_qname(domain_name)

    code = 0
    # QTYPE - query for A record
    if query_type == "A":
        # host address
        code = 1
    elif query_type == "NS":
        # authoritative name server
        code = 2
    elif query_type == "CNAME":
        # the canonical name for an alias
        code = 5
    elif query_type == "SOA":
        # start of a zone of authority
        code = 6
    elif query_type == "MX":
        # mail exchange
        code = 15
    elif query_type == "TXT":
        # text strings
        print "[Error]: Not implemented. Exiting..."
        exit(1)
        code = 16
    elif query_type == "PTR":
        # domain name pointer
        code = 12
        print "[Error]: Not implemented. Exiting..."
        exit(1)
    elif query_type == "AAAA":
        # AAAA record
        code = 28
    else:
        print "[Error]: Invalid query. Exiting..."
        exit(1)

    qtype = pack(">H", code)

    # QCLASS - internet
    qclass = pack(">H", 1)

    # whole question section
    question = create_header(QUERY) + qname + qtype + qclass

    return (question, len(qname))

def create_qname(domain_name):
    """ Function used to transfrom URL from normal form to DNS form.

    Args:
        domain_name = URL that needs to be converted

    Returns:
        The URL in DNS form

    Example:
        3www7example3com0 to www.example.com

    """

    qname = ''

    split_name = domain_name.split(".")
    for atom in split_name:
        qname += pack(">B", len(atom))
        for byte in bytes(atom):
            qname += byte
    qname += '\x00'

    return qname
