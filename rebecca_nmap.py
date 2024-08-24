"""
Rebecca's DIY Nmap
July 2024

A tool for scanning IP addresses and subnets for open ports and OS information.
"""

import argparse
from datetime import datetime
import ipaddress
import logging
import pyfiglet
import nmap
import re
import scapy.all as scapy 
import sys
import socket

def configure_logging():
    '''
    Configures logging for scans.
    '''
    log_filename = f"logfile_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename=log_filename)

def display_starting_banner() -> None:
    '''
    Displays the ASCII banner at the start of the program.
    '''
    ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
    print(ascii_banner)

# Define a dictionary with port numbers and their associated protocol names
PORT_PROTOCOLS = {
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

def arg_parser() -> argparse.Namespace:
    '''
    Parses command line arguments for use throughout the program.

    Returns:
        argparse.Namespace: Parsed aurguments
    '''
    # Organizing command line aurguments
    parser = argparse.ArgumentParser(description="This tool will scan for specified ports on a given IP address or subnet. You can also choose to perform additional scans on discovered devices.")
    subnet_group = parser.add_mutually_exclusive_group(required=True)
    subnet_group.add_argument("-sN", dest="target_subnet", type=str, help="Subnet scan (e.g., 192.168.1.0/24)")
    subnet_group.add_argument("-t", dest="target_ipaddr", type=str, help="The target IP address (e.g., 192.168.1.1)")

    # Port range argument
    parser.add_argument("-p", dest="port_range", type=str, help="The target range of ports (e.g., 1-1000)")

    # Optional arguments
    parser.add_argument("-sT", dest="TCP_scan", action="store_true", help="Full TCP connect scan")
    parser.add_argument("-O", dest="OS_scan", action="store_true", help="OS scan")

    return parser.parse_args()

def validate_port_range(port_range: str) -> tuple[int, int] | None:
    '''
    Validates the user given port ranges and returns the maximum and minimum of the range.

    Args: 
        port_range (str): Port range as a string.

    Returns:
        tuple[int, int]: Tuple containing maximum and minimum ports.

    Raises:
        ValueError: If the port range is invalid
    '''

    # Define regular expressions pattern to validate the port number input
    port_range_pattern = re.compile(r"(\d+)-(\d+)")
    match = port_range_pattern.fullmatch(port_range.replace(" ", ""))
    if not match:
        logging.error(f"Invalid port range format: {port_range}")
        raise ValueError("Invalid port range format.")
    
    logging.info("Port range has been validated.")
    return int(match.group(1)), int(match.group(2))

def validation_ip_or_subnet(args: argparse.Namespace) -> None:
    '''
    Validates the user given IP address or subnet.

    Arguments:
        args (args.Namespace): Parsed command line arguments.
    
    Raises:
        ValueError: If the IP address or subnet is invalid.
    '''
    try: 
        if args.target_ipaddr:
            ipaddress.ip_address(args.target_ipaddr)
            logging.info("IP address has been validated.")
        if args.target_subnet:
            ipaddress.ip_network(args.target_subnet, strict=False) 
            logging.info("Subnet has been validated.")
    except ValueError as ve:
        logging.error(f"Validation error: {ve}")
        sys.exit(1)

def print_scan_results(results: list[tuple[int, str, str]], save_results: bool) -> None:
    '''
    Prints the result of a port scan on a target IP address.
    Optionally saves the results to a file that saves in the user's current directory.

    Arguments:
        results (list[tuple[int, str, str]]): List of tuples containing port number, state of port, and protocol.
        save_results (bool): Indicates whether or not the user wants the results saved in an output file.
    '''
    if save_results:
        results_file_name = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        with open(results_file_name, 'w') as f:
            logging.info("Starting to write scan results to file.")
            f.write("PORT\t STATE\t \tSERVICE\n")
            print("\nPORT\t STATE\t \tSERVICE\n") # Print to console as well
            for port, protocol, state in results:
                if state != 'closed' and not (state == 'filtered' and protocol == 'Unknown Protocol'):
                    f.write(f"{port}\t {state}\t {protocol}\n")
                    print(f"{port}\t {state}\t {protocol}")  # Print to console as well

            logging.info(f"Done writing scan results to file.")
    else:
        logging.info("Starting to print scan results.")
        print("\nPORT\t STATE\t \tSERVICE\n")
        for port, protocol, state in results:
            if state != 'closed' and not (state == 'filtered' and protocol == 'Unknown Protocol'):
                print(f"{port}\t {state}\t {protocol}")
        
        logging.info("Done printing scan results.")
    
    print(f"Results saved in file: {results_file_name}")

def print_banner_for_scans(target_ip: str) -> None:
    '''
    Prints the banner for scans.

    Arguments:
        target_ip (str): target IP address.
    '''
    print("_" * 50)
    print(f"Scanning Target: {target_ip}")
    print("Scan started at: " + str(datetime.now()))
    print("_" * 50)

def tcp_connect_scan(target_ip: str, port_min: int, port_max: int) -> None:
    '''
    Performs a TCP connection to each port between the range of the minimum and maximum ports.

    Arguments:
        target_ip (str): Target IP address.
        port_min (int): Minimum port number.
        port_max (int): Maximum port number.
    '''
    print_banner_for_scans(target_ip)
    logging.info(f"Starting TCP connect scan to {target_ip}.")
    results = [] 

    for port in range(port_min, port_max + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(.5)
            return_code = s.connect_ex((target_ip, port))
            protocol = PORT_PROTOCOLS.get(port, 'Unknown Protocol') # Default protocol name in case it's not included in library
            state = interpret_socket_return_code(return_code)

            print(".", end="", flush=True)
            if ((port % 50) == 0 and port != 0):  # Keeps the dots in line with other banners
                print("\n")
            
            results.append((port, protocol, state))
            s.close()
        except socket.error as e:
            logging.error(f"Socket error: {e}")
            continue
    
    logging.info(f"Done with TCP connect scan to {target_ip}.")
    print_scan_results(results, True)

def interpret_socket_return_code(return_code: int) -> str:
    '''
    Interprets the socket return code into a port state. Uses both Linux and Windows return codes

    Arguments: 
        return_code (int): Socket return code.

    Returns:
        str: Port state.
    '''
    if return_code == 0:
        return 'open'
    if return_code == 10060 or 110:
        return 'filtered'
    if return_code == 10061 or 111:
        return 'closed'
    if return_code == 10013 or 13:
        return 'permission denied'
    return 'unknown'

def os_nmap_scan(target_ip: str) -> None:
    '''
    Performs an operating system scan on target IP address.

    Arguments:
        target_ip (str): Target IP address.
    '''
    print_banner_for_scans(target_ip)

    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments='-O')  # -O enables OS detection
    
    for host in nm.all_hosts():
        logging.info(f"Starting OS scan on {host}.")
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
            logging.error(f"OS detection not available on {host}.")
    
        logging.info(f"Done with OS scan on {host}")
    

def network_device_scan(target_subnet: str, args: argparse.Namespace, port_min: int, port_max: int) -> None:
    '''
    Discovers devices within a given subnet.

    Arguments:
        target_subnet (str): Target IP address.
        args (argparse.Namespace): Parsed command line arguments.
        port_min (int): Minimum port number.
        port_max (int): Maximum port number.
    '''
    request = scapy.ARP(pdst=target_subnet)
    broadcast = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff') # Create an ethernet frame with broadcast address
    request_broadcast = broadcast / request
    clients = scapy.srp(request_broadcast, timeout=10, verbose=1)[0]
    logging.info(f"Starting network scan on subnet {target_subnet}.")
    
    for client in clients:
        print(client[1].psrc + "      " + client[1].hwsrc)
        logging.info(f"Found device at {client}.")

    # For every IP address found, if the TCP_scan flag is set, then run the scan on each addr
    if args.TCP_scan:
        for client in clients:
            #ip_address = str(client[1].psrc)  # Extract IP address as a string so function can accept it
            tcp_connect_scan(client[1].psrc, port_min, port_max)
    
    # For every IP address found, if the OS_scan flag is set, then run the scan on each addr
    if args.OS_scan:
        for client in clients:
            #ip_address = str(client[1].psrc)  # Extract IP address as a string so function can accept it
            os_nmap_scan(client[1].psrc)

def main():
    '''
    Main function to run all the scripts.
    '''
    configure_logging()
    display_starting_banner()
    args = arg_parser()
    validation_ip_or_subnet(args)
    port_min, port_max = validate_port_range(args.port_range)

    # Based on the flag set from command line, run those scans here
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

if __name__ == "__main__":
    main()