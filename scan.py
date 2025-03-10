#!/usr/bin/env python3

import sys
import json
import time
import socket
import subprocess
import requests
import ipaddress
import os
import dns.resolver
from urllib.parse import urlparse

# List of public DNS resolvers to use for lookups
PUBLIC_DNS_RESOLVERS = [
    "8.8.8.8",      # Google
    "1.1.1.1",      # Cloudflare
    "9.9.9.9",      # Quad9
    "208.67.222.222" # OpenDNS
]

def get_scan_time():
    """Get the current time in Unix epoch seconds."""
    return time.time()

def get_ipv4_addresses(domain):
    """Get IPv4 addresses for a domain using nslookup with multiple DNS resolvers."""
    ipv4_addresses = set()
    
    # Try DNS resolution with multiple public resolvers
    for resolver in PUBLIC_DNS_RESOLVERS:
        try:
            output = subprocess.check_output(
                ["nslookup", domain, resolver],
                timeout=2,
                stderr=subprocess.STDOUT
            ).decode("utf-8")
            
            # Parse the nslookup output to extract IPv4 addresses
            lines = output.split("\n")
            for line in lines:
                if "Address:" in line and not line.startswith("Server:"):
                    ip = line.split("Address:")[1].strip()
                    try:
                        # Validate that this is a valid IPv4 address
                        ipaddress.IPv4Address(ip)
                        ipv4_addresses.add(ip)
                    except ValueError:
                        # Not a valid IPv4 address, skip it
                        pass
                        
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            # If this resolver fails, just continue with the next one
            continue
    
    # Also try with dnspython for completeness
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for answer in answers:
            ipv4_addresses.add(answer.to_text())
    except Exception:
        pass
        
    return list(ipv4_addresses)

def get_ipv6_addresses(domain):
    """Get IPv6 addresses for a domain using nslookup with multiple DNS resolvers."""
    ipv6_addresses = set()
    
    # Try DNS resolution with multiple public resolvers
    for resolver in PUBLIC_DNS_RESOLVERS:
        try:
            output = subprocess.check_output(
                ["nslookup", "-type=AAAA", domain, resolver],
                timeout=2,
                stderr=subprocess.STDOUT
            ).decode("utf-8")
            
            # Parse the nslookup output to extract IPv6 addresses
            lines = output.split("\n")
            for line in lines:
                if "Address:" in line and not line.startswith("Server:"):
                    ip = line.split("Address:")[1].strip()
                    try:
                        # Validate that this is a valid IPv6 address
                        ipaddress.IPv6Address(ip)
                        ipv6_addresses.add(ip)
                    except ValueError:
                        # Not a valid IPv6 address, skip it
                        pass
                        
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            # If this resolver fails, just continue with the next one
            continue
    
    # Also try with dnspython for completeness
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        for answer in answers:
            ipv6_addresses.add(answer.to_text())
    except Exception:
        pass
        
    return list(ipv6_addresses)

def get_http_server(domain):
    """Get the HTTP server header from the domain."""
    server_header = None
    
    # Try HTTP first
    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
        server_header = response.headers.get("Server")
    except Exception:
        pass
    
    # If HTTP failed or didn't provide a Server header, try HTTPS
    if not server_header:
        try:
            response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
            server_header = response.headers.get("Server")
        except Exception:
            pass
    
    return server_header  # Will be None (null in JSON) if not found

def check_insecure_http(domain):
    """Check if the website listens for unencrypted HTTP requests on port 80."""
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(2)
        conn.connect((domain, 80))
        conn.close()
        return True
    except Exception:
        return False

def check_redirect_to_https(domain):
    """Check if HTTP requests are redirected to HTTPS."""
    if not check_insecure_http(domain):
        return False
        
    try:
        # Allow up to 10 redirects
        response = requests.get(
            f"http://{domain}", 
            timeout=5,
            allow_redirects=False  # Don't follow redirects automatically
        )
        
        redirect_count = 0
        current_url = f"http://{domain}"
        
        # Follow redirects manually to track the chain
        while redirect_count < 10 and 300 <= response.status_code < 400:
            redirect_url = response.headers.get('Location')
            if not redirect_url:
                break
                
            # Handle relative URLs
            if redirect_url.startswith('/'):
                parsed_url = urlparse(current_url)
                redirect_url = f"{parsed_url.scheme}://{parsed_url.netloc}{redirect_url}"
                
            current_url = redirect_url
            redirect_count += 1
            
            # Check if we've reached HTTPS
            if current_url.startswith('https://'):
                return True
                
            # Get the next response
            response = requests.get(redirect_url, timeout=5, allow_redirects=False)
            
        return False
    except Exception:
        return False

def check_hsts(domain):
    """Check if the website has HTTP Strict Transport Security enabled."""
    try:
        # Try directly with HTTPS
        response = requests.get(f"https://{domain}", timeout=5)
        
        # Check for HSTS header
        hsts_header = response.headers.get('Strict-Transport-Security')
        return hsts_header is not None
    except Exception:
        return False

def get_tls_versions(domain):
    """Check which TLS versions are supported by the server."""
    tls_versions = []
    versions = [
        ("SSLv2", "-ssl2"),
        ("SSLv3", "-ssl3"),
        ("TLSv1.0", "-tls1"),
        ("TLSv1.1", "-tls1_1"),
        ("TLSv1.2", "-tls1_2"),
        ("TLSv1.3", "-tls1_3")
    ]
    
    for version_name, version_flag in versions:
        try:
            process = subprocess.run(
                ["openssl", "s_client", version_flag, "-connect", f"{domain}:443"],
                input=b'',
                capture_output=True,
                timeout=3
            )
            
            output = process.stdout.decode('utf-8', errors='ignore')
            
            # Check if the connection was successful
            if "CONNECTED" in output and "Secure Renegotiation IS supported" in output:
                tls_versions.append(version_name)
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            # If this TLS version check fails, just continue with the next one
            continue
    
    return tls_versions

def get_root_ca(domain):
    """Get the root certificate authority (CA) organization name."""
    try:
        output = subprocess.check_output(
            ["openssl", "s_client", "-connect", f"{domain}:443"],
            input=b'',
            timeout=3,
            stderr=subprocess.STDOUT
        ).decode('utf-8', errors='ignore')
        
        # Look for certificate chain information
        cert_section = False
        ca_org = None
        
        for line in output.split('\n'):
            if '---' in line and 'BEGIN CERTIFICATE' in line:
                cert_section = True
            elif '---' in line and 'END CERTIFICATE' in line:
                cert_section = False
            elif cert_section and 'O = ' in line:
                # Extract organization name
                parts = line.split('O = ')
                if len(parts) > 1:
                    ca_org = parts[1].split(',')[0].strip()
                    
        return ca_org
    except Exception:
        return None

def get_rdns_names(ipv4_addresses):
    """Get reverse DNS names for IPv4 addresses."""
    rdns_names = []
    
    for ip in ipv4_addresses:
        try:
            # Reverse the IP address for PTR query
            reversed_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
            
            # Try using subprocess with nslookup for PTR record
            output = subprocess.check_output(
                ["nslookup", "-type=PTR", reversed_ip],
                timeout=2,
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            
            # Parse the output to find PTR records
            for line in output.split('\n'):
                if 'name = ' in line.lower():
                    name = line.split('name = ')[1].strip()
                    if name.endswith('.'):
                        name = name[:-1]  # Remove trailing dot
                    rdns_names.append(name)
        except Exception:
            # Try using dnspython as a fallback
            try:
                answers = dns.resolver.resolve(reversed_ip, 'PTR')
                for answer in answers:
                    name = answer.to_text()
                    if name.endswith('.'):
                        name = name[:-1]  # Remove trailing dot
                    rdns_names.append(name)
            except Exception:
                # If both methods fail, just continue
                continue
    
    return rdns_names

def get_rtt_range(ipv4_addresses):
    """Get the min and max round trip time to the IP addresses."""
    rtts = []
    
    for ip in ipv4_addresses:
        for port in [443, 80, 22]:  # Try common ports
            try:
                # Use socket to measure RTT
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                sock.close()
                end_time = time.time()
                
                # Calculate RTT in milliseconds
                rtt = (end_time - start_time) * 1000
                rtts.append(rtt)
                
                # We only need one successful connection per IP
                break
            except Exception:
                continue
    
    if not rtts:
        return None
    
    return [min(rtts), max(rtts)]

def get_geo_locations(ipv4_addresses):
    """Get geographic locations for IP addresses using MaxMind database."""
    locations = set()
    
    try:
        import maxminddb
        
        # Check if the database file exists
        if not os.path.exists('GeoLite2-City.mmdb'):
            sys.stderr.write("Error: GeoLite2-City.mmdb not found in the current directory.\n")
            return []
        
        # Open the database
        with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
            for ip in ipv4_addresses:
                try:
                    # Look up the IP address
                    result = reader.get(ip)
                    
                    if result and 'city' in result and 'subdivisions' in result and 'country' in result:
                        city = result['city']['names']['en'] if 'names' in result['city'] and 'en' in result['city']['names'] else ''
                        region = result['subdivisions'][0]['names']['en'] if result['subdivisions'] and 'names' in result['subdivisions'][0] and 'en' in result['subdivisions'][0]['names'] else ''
                        country = result['country']['names']['en'] if 'names' in result['country'] and 'en' in result['country']['names'] else ''
                        
                        location = f"{city}, {region}, {country}".strip()
                        if location.startswith(', '):
                            location = location[2:]
                        if location.endswith(', '):
                            location = location[:-2]
                            
                        locations.add(location)
                except Exception:
                    continue
    except ImportError:
        sys.stderr.write("Error: maxminddb module not installed. Run 'pip install maxminddb'.\n")
    except Exception as e:
        sys.stderr.write(f"Error accessing GeoLite2 database: {str(e)}\n")
    
    return list(locations)

def scan_domain(domain):
    """Scan a domain and return a dictionary of results."""
    results = {}
    
    # a) scan_time - Record when the scan started
    results["scan_time"] = get_scan_time()
    
    # b) ipv4_addresses - Get IPv4 addresses
    ipv4_addresses = get_ipv4_addresses(domain)
    results["ipv4_addresses"] = ipv4_addresses
    
    # c) ipv6_addresses - Get IPv6 addresses
    results["ipv6_addresses"] = get_ipv6_addresses(domain)
    
    # d) http_server - Get HTTP server header
    http_server = get_http_server(domain)
    if http_server:
        results["http_server"] = http_server
    else:
        results["http_server"] = None
    
    # e) insecure_http - Check if the website supports unencrypted HTTP
    results["insecure_http"] = check_insecure_http(domain)
    
    # f) redirect_to_https - Check if HTTP redirects to HTTPS
    results["redirect_to_https"] = check_redirect_to_https(domain)
    
    # g) hsts - Check for HTTP Strict Transport Security
    results["hsts"] = check_hsts(domain)
    
    # h) tls_versions - Check supported TLS versions
    tls_versions = get_tls_versions(domain)
    if tls_versions:
        results["tls_versions"] = tls_versions
    
    # i) root_ca - Get root certificate authority
    root_ca = get_root_ca(domain)
    if root_ca:
        results["root_ca"] = root_ca
    else:
        results["root_ca"] = None
    
    # j) rdns_names - Get reverse DNS names
    if ipv4_addresses:
        rdns_names = get_rdns_names(ipv4_addresses)
        results["rdns_names"] = rdns_names
    
    # k) rtt_range - Get RTT range
    if ipv4_addresses:
        rtt_range = get_rtt_range(ipv4_addresses)
        if rtt_range:
            results["rtt_range"] = rtt_range
        else:
            results["rtt_range"] = None
    
    # l) geo_locations - Get geographic locations
    if ipv4_addresses:
        geo_locations = get_geo_locations(ipv4_addresses)
        if geo_locations:
            results["geo_locations"] = geo_locations
    
    return results

def main():
    # Check if correct number of arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py [input_file.txt] [output_file.json]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Read domains from the input file
    try:
        with open(input_file, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    
    # Scan each domain
    scan_results = {}
    for domain in domains:
        print(f"Scanning {domain}...")
        scan_results[domain] = scan_domain(domain)
    
    # Write results to the output file with nice formatting
    with open(output_file, "w") as f:
        json.dump(scan_results, f, sort_keys=True, indent=4)
    
    print(f"Scan completed. Results saved to {output_file}")

if __name__ == "__main__":
    main()
