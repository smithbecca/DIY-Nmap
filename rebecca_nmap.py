'''
    Rebecca's DIY Nmap
        July 2024
          Enjoy!
'''

import argparse
from datetime import datetime
import ipaddress
import pyfiglet
import nmap
import re
import scapy.all as scapy 
import sys
import socket

# Print out sick banner
ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)


# Define a dictionary with port numbers and their associated protocol names
port_protocols = {
    20: 'FTP Data Transfer',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP Server',
    68: 'DHCP Client',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    119: 'NNTP',
    123: 'NTP',
    135: 'Microsoft RPC',
    137: 'NetBIOS Name Service',
    138: 'NetBIOS Datagram Service',
    139: 'NetBIOS Session Service',
    143: 'IMAP',
    161: 'SNMP',
    162: 'SNMP Trap',
    179: 'BGP',
    194: 'IRC',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'Microsoft-DS (SMB)',
    465: 'SMTPS',
    514: 'Syslog',
    520: 'RIP',
    587: 'SMTP (submission)',
    631: 'IPP (Internet Printing Protocol)',
    636: 'LDAPS',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'Microsoft SQL Server',
    1434: 'Microsoft SQL Monitor',
    1521: 'Oracle Database',
    2049: 'NFS',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    5985: 'WinRM (HTTP)',
    5986: 'WinRM (HTTPS)',
    6379: 'Redis',
    8080: 'HTTP Proxy',
    8443: 'HTTPS Alternate',
    9000: 'SonarQube',
    9092: 'Kafka',
    9200: 'Elasticsearch',
    27017: 'MongoDB',
}

# Define regular expressions pattern to validate the port number input
port_range_pattern = re.compile("([0-9]+)-([0-9]+)") 

# Function to take in port range and validate
def check_port_range(port_range):
    try:
        port_range_valid = port_range_pattern.search(port_range.replace(" ","")) # allows the user to use spaces in cml
        if not port_range_valid:
            raise ValueError("Invalid port range format. ")
        else:
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            return port_min, port_max
    except ValueError as ve:    # print out why they need to start over
        print(f"Error: {ve} Enter in the criteria again.\n")
        sys.exit(1)

# Organizing command line aurguments
parser = argparse.ArgumentParser(description="This tool will scan for specified ports on a given IP address or subnet. You can also choose to perform additional scans on discovered devices.")
subnet_group = parser.add_mutually_exclusive_group(required=True)
subnet_group.add_argument("-sN", dest="target_subnet", type=str, help="Subnet scan (e.g., 192.168.1.0/24)")
subnet_group.add_argument("-t", dest="target_ipaddr", type=str, help="The target IP address (e.g., 192.168.1.1)")

# Port range argument
parser.add_argument("port_range", type=str, help="The target range of ports (e.g., 1-1000)")

# Optional arguments
parser.add_argument("-sT", dest="TCP_scan", action="store_true", help="Full TCP connect scan")
parser.add_argument("-O", dest="OS_scan", action="store_true", help="OS scan")

# Parse arguments
args = parser.parse_args()

# Validate IP addresses and call port validation function
try:
    if args.target_ipaddr:
        ipaddress.ip_address(args.target_ipaddr)
    if args.target_subnet:
        ipaddress.ip_network(args.target_subnet, strict=False)
    
    if args.port_range:
        port_min, port_max = check_port_range(args.port_range)
except ValueError as ve:
    print(f"Error: {ve} Enter in the criteria again.\n")
    sys.exit(1)

# Based on code stored in result, print out port state
def print_results(results):
    print("\nPORT\t STATE\t \tSERVICE\n")

    for port, protocol, state in results:
        if state != 'closed' and not (state == 'filtered' and protocol == 'Unknown Protocol'):
            print(f"{port}\t {state}\t {protocol}")

# Function to perform a full TCP connect scan
def tcp_connect_scan(target_ip, port_min, port_max):
    # Update banner to display the address currently being scanned
    print("_" * 50)
    print(f"Scanning Target: {target_ip}")
    print("Scan started at: " + str(datetime.now()))
    print("_" * 50)
    
    results = [] 
    # Create a TCP connect for every port in port range
    for port in range(port_min, port_max + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(.5)
        return_code = s.connect_ex((target_ip, port))

        # Default protocol name in case it's not included in library
        protocol = port_protocols.get(port, 'Unknown Protocol')

        # Uses both Linux and Windows return codes
        if return_code == 0:
            state = 'open'
        elif return_code == 10060 or 110:
            state = 'filtered'
        elif return_code == 10061 or 111:
            state = 'closed'
        elif return_code == 10013 or 13:
            state = 'permission denied'
        else:
            state = 'unknown'
        
        print(".", end="", flush=True) # the illusion of progress
        if ((port % 50) == 0 and port != 0):  # keeps it in line with other banners
            print("\n")
        
        results.append((port, protocol, state))
        s.close()
    
    print_results(results)

# Scan IP addresses for OS information
def os_nmap_scan(target_ip):
    # Update banner to display the address currently being scanned
    print("_" * 50)
    print("Scanning OS for: " + target_ip)
    print("Scan started at: " + str(datetime.now()))
    print("_" * 50)

    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-O')  # -O enables OS detection
    
    # Check the scan results
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        
        if 'osclass' in nm[host]:
            for osclass in nm[host]['osclass']:
                print(f"OS Type: {osclass['type']}")
                print(f"Vendor: {osclass['vendor']}")
                print(f"OS Family: {osclass['osfamily']}")
                print(f"OS Generation: {osclass['osgen']}")
                print(f"Accuracy: {osclass['accuracy']}")
        else:
            print("OS detection not available")

# Function to discover devices within a subnet
def network_device_scan(target_subnet):
    # Create request
    request = scapy.ARP(pdst=target_subnet)

    # Create an ethernet frame with broadcast address
    broadcast = scapy.Ether()
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'

    # Combine ethernet frame and arp request
    request_broadcast = broadcast / request
    # Send packet and get responses
    clients = scapy.srp(request_broadcast, timeout=10, verbose=1)[0]
    
    # Print findings
    for client in clients:
        print(client[1].psrc + "      " + client[1].hwsrc)

    if args.TCP_scan:
        for client in clients:
            ip_address = str(client[1].psrc)  # Extract IP address as a string so function can accept it
            tcp_connect_scan(ip_address, port_min, port_max)
    
    if args.OS_scan:
        for client in clients:
            ip_address = str(client[1].psrc)  # Extract IP address as a string so function can accept it
            os_nmap_scan(ip_address)


# Perform scans! 
try:
    if args.target_subnet:
        network_device_scan(args.target_subnet)
    if not args.target_subnet and args.TCP_scan:
        tcp_connect_scan(args.target_ipaddr, port_min, port_max)
    if not args.target_subnet and args.OS_scan:
        os_nmap_scan(args.target_ipaddr)
    else:
        print("\nThanks for using my scanner!\n")
except KeyboardInterrupt:
   print("\nExiting Program.")
   sys.exit()