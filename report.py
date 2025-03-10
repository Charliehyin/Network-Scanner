#!/usr/bin/env python3

import sys
import json
from texttable import Texttable
from collections import Counter

def load_scan_results(input_file):
    """Load scan results from JSON file."""
    try:
        with open(input_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in file '{input_file}'.")
        sys.exit(1)

def print_domain_details(domain, data, output):
    """Print detailed information for a single domain."""
    output.write(f"\n{'=' * 80}\n")
    output.write(f"DOMAIN: {domain}\n")
    output.write(f"{'=' * 80}\n\n")
    
    # Basic scan info
    output.write(f"Scan time: {data.get('scan_time')}\n")
    
    # IPv4 addresses
    ipv4_addresses = data.get('ipv4_addresses', [])
    output.write(f"IPv4 addresses ({len(ipv4_addresses)}):\n")
    for ip in ipv4_addresses:
        output.write(f"  - {ip}\n")
    
    # IPv6 addresses
    ipv6_addresses = data.get('ipv6_addresses', [])
    output.write(f"IPv6 addresses ({len(ipv6_addresses)}):\n")
    for ip in ipv6_addresses:
        output.write(f"  - {ip}\n")
    
    # Server information
    output.write(f"HTTP server: {data.get('http_server', 'None')}\n")
    
    # Security features
    output.write(f"Insecure HTTP: {data.get('insecure_http', False)}\n")
    output.write(f"Redirects to HTTPS: {data.get('redirect_to_https', False)}\n")
    output.write(f"HSTS enabled: {data.get('hsts', False)}\n")
    
    # TLS versions
    tls_versions = data.get('tls_versions', [])
    output.write(f"Supported TLS versions ({len(tls_versions)}):\n")
    for version in tls_versions:
        output.write(f"  - {version}\n")
    
    # Root CA
    output.write(f"Root CA: {data.get('root_ca', 'None')}\n")
    
    # Reverse DNS names
    rdns_names = data.get('rdns_names', [])
    output.write(f"Reverse DNS names ({len(rdns_names)}):\n")
    for name in rdns_names:
        output.write(f"  - {name}\n")
    
    # RTT range
    rtt_range = data.get('rtt_range')
    if rtt_range:
        output.write(f"RTT range: {rtt_range[0]:.2f}ms - {rtt_range[1]:.2f}ms\n")
    else:
        output.write("RTT range: Not available\n")
    
    # Geographic locations
    geo_locations = data.get('geo_locations', [])
    output.write(f"Geographic locations ({len(geo_locations)}):\n")
    for location in geo_locations:
        output.write(f"  - {location}\n")
    
    output.write("\n")

def create_rtt_table(scan_results):
    """Create a table of RTT ranges sorted by minimum RTT."""
    rtt_data = []
    
    for domain, data in scan_results.items():
        rtt_range = data.get('rtt_range')
        if rtt_range:
            rtt_data.append((domain, rtt_range[0], rtt_range[1]))
    
    # Sort by minimum RTT (fastest to slowest)
    rtt_data.sort(key=lambda x: x[1])
    
    # Create table
    table = Texttable(max_width=80)
    table.set_deco(Texttable.HEADER | Texttable.VLINES)
    table.set_cols_align(["l", "r", "r"])
    table.set_cols_dtype(['t', 'f', 'f'])
    table.set_cols_width([40, 15, 15])
    table.add_rows([["Domain", "Min RTT (ms)", "Max RTT (ms)"]])
    
    for domain, min_rtt, max_rtt in rtt_data:
        table.add_row([domain, min_rtt, max_rtt])
    
    return table.draw()

def create_ca_table(scan_results):
    """Create a table of root CA occurrences."""
    ca_counter = Counter()
    
    for data in scan_results.values():
        root_ca = data.get('root_ca')
        if root_ca:
            ca_counter[root_ca] += 1
    
    # Sort by occurrence count (most to least)
    ca_counts = ca_counter.most_common()
    
    # Create table
    table = Texttable(max_width=80)
    table.set_deco(Texttable.HEADER | Texttable.VLINES)
    table.set_cols_align(["l", "r", "r"])
    table.set_cols_dtype(['t', 'i', 'f'])
    table.set_cols_width([50, 15, 15])
    table.add_rows([["Root Certificate Authority", "Count", "Percentage (%)"]])
    
    total_domains = len(scan_results)
    for ca, count in ca_counts:
        percentage = (count / total_domains) * 100
        table.add_row([ca, count, percentage])
    
    return table.draw()

def create_server_table(scan_results):
    """Create a table of web server occurrences."""
    server_counter = Counter()
    
    for data in scan_results.values():
        http_server = data.get('http_server')
        if http_server:
            server_counter[http_server] += 1
    
    # Sort by occurrence count (most to least)
    server_counts = server_counter.most_common()
    
    # Create table
    table = Texttable(max_width=80)
    table.set_deco(Texttable.HEADER | Texttable.VLINES)
    table.set_cols_align(["l", "r", "r"])
    table.set_cols_dtype(['t', 'i', 'f'])
    table.set_cols_width([50, 15, 15])
    table.add_rows([["Web Server", "Count", "Percentage (%)"]])
    
    total_domains = len(scan_results)
    for server, count in server_counts:
        percentage = (count / total_domains) * 100
        table.add_row([server, count, percentage])
    
    return table.draw()

def create_feature_table(scan_results):
    """Create a table of feature support percentages."""
    total_domains = len(scan_results)
    if total_domains == 0:
        return "No domains scanned"
    
    # Count features
    features = {
        "SSLv2": 0,
        "SSLv3": 0,
        "TLSv1.0": 0,
        "TLSv1.1": 0,
        "TLSv1.2": 0,
        "TLSv1.3": 0,
        "Plain HTTP": 0,
        "HTTPS Redirect": 0,
        "HSTS": 0,
        "IPv6": 0
    }
    
    for data in scan_results.values():
        # TLS versions
        tls_versions = data.get('tls_versions', [])
        for version in tls_versions:
            if version in features:
                features[version] += 1
        
        # HTTP features
        if data.get('insecure_http', False):
            features["Plain HTTP"] += 1
        
        if data.get('redirect_to_https', False):
            features["HTTPS Redirect"] += 1
        
        if data.get('hsts', False):
            features["HSTS"] += 1
        
        # IPv6 support
        if data.get('ipv6_addresses', []):
            features["IPv6"] += 1
    
    # Create table
    table = Texttable(max_width=80)
    table.set_deco(Texttable.HEADER | Texttable.VLINES)
    table.set_cols_align(["l", "r", "r"])
    table.set_cols_dtype(['t', 'i', 'f'])
    table.set_cols_width([40, 15, 15])
    table.add_rows([["Feature", "Count", "Percentage (%)"]])
    
    for feature, count in features.items():
        percentage = (count / total_domains) * 100
        table.add_row([feature, count, percentage])
    
    return table.draw()

def generate_report(scan_results, output_file):
    """Generate a comprehensive report from scan results."""
    try:
        with open(output_file, 'w') as f:
            # Title
            f.write("\n")
            f.write("=" * 80 + "\n")
            f.write("DOMAIN SCAN REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Total domains scanned: {len(scan_results)}\n\n")
            
            # Per-domain details
            f.write("DETAILED DOMAIN INFORMATION\n")
            f.write("-" * 80 + "\n")
            for domain, data in scan_results.items():
                print_domain_details(domain, data, f)
            
            # RTT table
            f.write("\nRTT RANGES (FASTEST TO SLOWEST)\n")
            f.write("-" * 80 + "\n")
            f.write(create_rtt_table(scan_results) + "\n\n")
            
            # Root CA table
            f.write("\nROOT CERTIFICATE AUTHORITIES\n")
            f.write("-" * 80 + "\n")
            f.write(create_ca_table(scan_results) + "\n\n")
            
            # Web server table
            f.write("\nWEB SERVERS\n")
            f.write("-" * 80 + "\n")
            f.write(create_server_table(scan_results) + "\n\n")
            
            # Feature support table
            f.write("\nFEATURE SUPPORT\n")
            f.write("-" * 80 + "\n")
            f.write(create_feature_table(scan_results) + "\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
            
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        sys.exit(1)

def main():
    # Check if correct number of arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python3 report.py [input_file.json] [output_file.txt]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Load scan results
    scan_results = load_scan_results(input_file)
    
    # Generate report
    print(f"Generating report from {input_file}...")
    generate_report(scan_results, output_file)
    print(f"Report generated and saved to {output_file}")

if __name__ == "__main__":
    main()
