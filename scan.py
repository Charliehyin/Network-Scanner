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
    "208.67.222.222",
    "1.1.1.1",       
    "8.8.8.8",       
    "8.26.56.26",    
    "9.9.9.9",       
    "94.140.14.14",  
    "185.228.168.9", 
    "76.76.2.0",     
    "76.76.19.19",    
    "129.105.49.1",  
    "74.82.42.42",    
    "205.171.3.65",  
    "193.110.81.0",  
    "147.93.130.20", 
    "51.158.108.203" 
]

def get_scan_time():
    """Get the current time in Unix epoch seconds."""
    return time.time()

def get_ipv4_addresses(domain):
    """Get IPv4 addresses for a domain using nslookup with multiple DNS resolvers."""
    ipv4_addresses = set()
    resolver_ips = set(PUBLIC_DNS_RESOLVERS)  # Create a set of resolver IPs to filter them out
    
    # Try DNS resolution with multiple public resolvers
    for resolver in PUBLIC_DNS_RESOLVERS:
        try:
            output = subprocess.check_output(
                ["nslookup", domain, resolver],
                timeout=2,
                stderr=subprocess.STDOUT
            ).decode("utf-8")
            
            # Parse the nslookup output to extract IPv4 addresses
            in_answer_section = False
            lines = output.split("\n")
            
            for line in lines:
                # Check if we've entered the answer section
                if "Non-authoritative answer:" in line:
                    in_answer_section = True
                    continue
                
                # Skip resolver address
                if "Address:" in line and not in_answer_section:
                    continue
                    
                # If in answer section, look for both "Address:" and "Addresses:"
                if in_answer_section:
                    # Extract from "Addresses:" line (could be IPv4 or IPv6)
                    if "Addresses:" in line:
                        parts = line.split("Addresses:")[1].strip().split()
                        for part in parts:
                            try:
                                ipv4 = ipaddress.IPv4Address(part)
                                if str(ipv4) not in resolver_ips:
                                    ipv4_addresses.add(str(ipv4))
                            except ValueError:
                                # Not a valid IPv4 address, skip it
                                pass
                    # Extract from "Address:" line
                    elif "Address:" in line:
                        ip = line.split("Address:")[1].strip()
                        try:
                            ipv4 = ipaddress.IPv4Address(ip)
                            if str(ipv4) not in resolver_ips:
                                ipv4_addresses.add(str(ipv4))
                        except ValueError:
                            # Not a valid IPv4 address, skip it
                            pass
                    # Check indented lines that might contain just an IP
                    elif line.strip() and line[0].isspace():
                        ip = line.strip()
                        try:
                            ipv4 = ipaddress.IPv4Address(ip)
                            if str(ipv4) not in resolver_ips:
                                ipv4_addresses.add(str(ipv4))
                        except ValueError:
                            # Not a valid IPv4 address, skip it
                            pass
                    
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            # If this resolver fails, just continue with the next one
            continue
            
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
    except Exception as e:
        print(f"HTTP request failed: {str(e)}")
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

import socket
import requests
import json
import sys
from urllib.parse import urlparse

import socket
import requests
import json
import sys
from urllib.parse import urlparse, urljoin

def check_http_redirect(hostname, max_redirects=10):
    """
    Check if HTTP requests on port 80 are redirected to HTTPS on port 443.
    
    Args:
        hostname (str): The hostname to check
        max_redirects (int): Maximum number of redirects to follow
        
    Returns:
        dict: A dictionary with 'redirect_to_https' boolean key
    """
    result = {"redirect_to_https": False}
    
    # First check if the site even listens on port 80
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((hostname, 80))
        sock.close()
    except (socket.timeout, socket.error):
        # Website doesn't listen on port 80, so it can't redirect
        return result
    
    # Construct the initial HTTP URL
    http_url = f"http://{hostname}/"
    
    try:
        # Make request with manual redirect handling
        current_url = http_url
        redirect_count = 0
        
        while redirect_count < max_redirects:
            # Use a short timeout and set proper headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
            
            response = requests.get(current_url, 
                                   headers=headers,
                                   allow_redirects=False, 
                                   timeout=10)
            
            # Check for redirect status codes (300-399)
            if 300 <= response.status_code < 400:
                if 'Location' in response.headers:
                    next_url = response.headers['Location']
                    
                    # Handle relative URLs properly
                    if not (next_url.startswith('http://') or next_url.startswith('https://')):
                        next_url = urljoin(current_url, next_url)
                    
                    # Check if we've been redirected to HTTPS
                    if next_url.startswith('https://'):
                        result["redirect_to_https"] = True
                        break
                    
                    # Continue following redirect chain
                    current_url = next_url
                    redirect_count += 1
                else:
                    # Redirect with no Location header
                    break
            else:
                # Check the final URL even if no explicit redirect
                # Some sites use JavaScript or other means to redirect
                final_url = response.url
                if final_url.startswith('https://'):
                    result["redirect_to_https"] = True
                break
        
        # Check if we reached maximum redirects but last URL was HTTPS
        if redirect_count == max_redirects and current_url.startswith('https://'):
            result["redirect_to_https"] = True
    
    except requests.exceptions.RequestException as e:
        # Log the error for debugging
        print(f"Error: {str(e)}", file=sys.stderr)
        
        # If there was a connection error but the URL changed to HTTPS, it might
        # still be a valid redirect
        if 'current_url' in locals() and current_url.startswith('https://'):
            result["redirect_to_https"] = True
    
    return result



def check_hsts(domain):
    """Check if the website has HTTP Strict Transport Security enabled."""
    try:
        # First check if the domain is in the HSTS preload list
        try:
            preload_check = requests.get(f"https://hstspreload.org/api/v2/status?domain={domain}", timeout=5)
            if preload_check.status_code == 200:
                preload_data = preload_check.json()
                if preload_data.get("status") == "preloaded":
                    return True
        except Exception:
            pass  # Continue with direct checks if preload check fails
        
        # Try multiple paths with redirects enabled
        paths = ["", "/", "/index.html", "/home", "/search", "/about"]
        for path in paths:
            try:
                response = requests.get(f"https://{domain}{path}", timeout=5, allow_redirects=True)
                
                # Check for HSTS header
                hsts_header = response.headers.get('Strict-Transport-Security')
                if hsts_header is not None:
                    return True
                    
                # Also check for HSTS in response history (redirects)
                for r in response.history:
                    hsts_header = r.headers.get('Strict-Transport-Security')
                    if hsts_header is not None:
                        return True
            except Exception:
                continue
                
        # If still not found, try www subdomain
        if not domain.startswith('www.'):
            try:
                response = requests.get(f"https://www.{domain}", timeout=5, allow_redirects=True)
                
                # Check for HSTS header
                hsts_header = response.headers.get('Strict-Transport-Security')
                if hsts_header is not None:
                    return True
                    
                # Also check for HSTS in response history
                for r in response.history:
                    hsts_header = r.headers.get('Strict-Transport-Security')
                    if hsts_header is not None:
                        return True
            except Exception:
                pass
                
        return False
    except Exception:
        return False

def get_tls_versions(domain):
    """Check which TLS versions are supported by the server."""
    tls_versions = []
    
    # Use nmap to check for SSLv2, SSLv3, TLSv1.0, TLSv1.1, and TLSv1.2
    try:
        # Run nmap with ssl-enum-ciphers script
        process = subprocess.run(
            ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", domain],
            capture_output=True,
            timeout=30  # nmap can take longer
        )
        
        output = process.stdout.decode('utf-8', errors='ignore')
        
        # Parse nmap output to find supported TLS versions
        version_indicators = {
            "SSLv2": ["SSLv2", "SSL2"],
            "SSLv3": ["SSLv3", "SSL3"],
            "TLSv1.0": ["TLSv1.0", "TLS1.0", "TLSv1"],
            "TLSv1.1": ["TLSv1.1", "TLS1.1"],
            "TLSv1.2": ["TLSv1.2", "TLS1.2"]
        }
        
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            
            # Check each version
            for version, indicators in version_indicators.items():
                if any(indicator in line for indicator in indicators):
                    # Check if this line indicates the version is not offered
                    not_offered = any(phrase in line.lower() for phrase in 
                                      ["not offered", "no supported ciphers", "disabled"])
                    
                    if not not_offered and version not in tls_versions:
                        tls_versions.append(version)
            
    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        # If nmap fails, fall back to our previous method for all versions
        versions = [
            ("SSLv2", "-ssl2"),
            ("SSLv3", "-ssl3"),
            ("TLSv1.0", "-tls1"),
            ("TLSv1.1", "-tls1_1"),
            ("TLSv1.2", "-tls1_2")
        ]
        
        for version_name, version_flag in versions:
            try:
                process = subprocess.run(
                    ["openssl", "s_client", version_flag, "-connect", f"{domain}:443"],
                    input=b'\n',
                    capture_output=True,
                    timeout=5
                )
                
                stdout = process.stdout.decode('utf-8', errors='ignore')
                stderr = process.stderr.decode('utf-8', errors='ignore')
                
                if "Verify return code:" in stdout and process.returncode == 0:
                    if not any(err in stderr.lower() for err in ["handshake failure", "no protocols available"]):
                        tls_versions.append(version_name)
            except Exception:
                continue
    
    # Use openssl to check for TLSv1.3 (which nmap doesn't support)
    try:
        process = subprocess.run(
            ["openssl", "s_client", "-tls1_3", "-connect", f"{domain}:443"],
            input=b'\n',
            capture_output=True,
            timeout=5
        )
        
        stdout = process.stdout.decode('utf-8', errors='ignore')
        stderr = process.stderr.decode('utf-8', errors='ignore')
        
        if "Verify return code:" in stdout and process.returncode == 0:
            if not any(err in stderr.lower() for err in ["handshake failure", "no protocols available"]):
                tls_versions.append("TLSv1.3")
    except Exception:
        pass
    
    return tls_versions

def get_root_ca(domain):
    """Get the root certificate authority (CA) organization name."""
    try:
        # Use -showcerts to get the full certificate chain
        output = subprocess.check_output(
            ["openssl", "s_client", "-connect", f"{domain}:443", "-showcerts"],
            input=b'',
            timeout=3,
            stderr=subprocess.STDOUT
        ).decode('utf-8', errors='ignore')
        
        # Find all certificates in the chain
        cert_blocks = []
        current_block = []
        in_cert = False
        
        for line in output.split('\n'):
            if '-----BEGIN CERTIFICATE-----' in line:
                in_cert = True
                current_block = [line]
            elif '-----END CERTIFICATE-----' in line:
                current_block.append(line)
                cert_blocks.append('\n'.join(current_block))
                in_cert = False
            elif in_cert:
                current_block.append(line)
        
        # The last certificate in the chain should be the root CA
        if cert_blocks:
            # Write the last certificate to a temporary file
            with open('temp_cert.pem', 'w') as f:
                f.write(cert_blocks[-1])
            
            # Use openssl x509 to extract the subject
            subj_output = subprocess.check_output(
                ["openssl", "x509", "-in", "temp_cert.pem", "-noout", "-subject"],
                timeout=2
            ).decode('utf-8')
            
            # Extract the organization
            if 'O = ' in subj_output:
                org_part = subj_output.split('O = ')[1].split(',')[0].strip()
                return org_part
            
            # Clean up the temporary file
            os.remove('temp_cert.pem')
            
        return None
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
                # One successful connection is enough for this IP/port combination
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
                    
                    if result:
                        # Extract location components with defaults if missing
                        city = ""
                        region = ""
                        country = ""
                        
                        # Get city if available
                        if 'city' in result and 'names' in result['city'] and 'en' in result['city']['names']:
                            city = result['city']['names']['en']
                        
                        # Get region/subdivision if available
                        if 'subdivisions' in result and result['subdivisions'] and 'names' in result['subdivisions'][0] and 'en' in result['subdivisions'][0]['names']:
                            region = result['subdivisions'][0]['names']['en']
                        
                        # Get country if available
                        if 'country' in result and 'names' in result['country'] and 'en' in result['country']['names']:
                            country = result['country']['names']['en']
                        
                        # Construct location string, handling missing parts
                        location_parts = []
                        if city:
                            location_parts.append(city)
                        if region:
                            location_parts.append(region)
                        if country:
                            location_parts.append(country)
                        
                        location = ", ".join(location_parts)
                        
                        if location:  # Only add non-empty locations
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
    print("Done with scan_time")
    
    # b) ipv4_addresses - Get IPv4 addresses
    ipv4_addresses = get_ipv4_addresses(domain)
    results["ipv4_addresses"] = ipv4_addresses
    print("Done with ipv4_addresses")
    
    # c) ipv6_addresses - Get IPv6 addresses
    results["ipv6_addresses"] = get_ipv6_addresses(domain)
    print("Done with ipv6 addresses")
    
    # d) http_server - Get HTTP server header
    http_server = get_http_server(domain)
    if http_server:
        results["http_server"] = http_server
    else:
        results["http_server"] = None
    
    # e) insecure_http - Check if the website supports unencrypted HTTP
    results["insecure_http"] = check_insecure_http(domain)
    print("Done with insecure_http")
    
    # f) redirect_to_https - Check if HTTP redirects to HTTPS
    results["redirect_to_https"] = check_http_redirect(domain)
    print("Done with redirect_to_https")
    
    # g) hsts - Check for HTTP Strict Transport Security
    results["hsts"] = check_hsts(domain)
    print("Done with hsts")
    
    # h) tls_versions - Check supported TLS versions
    tls_versions = get_tls_versions(domain)
    if tls_versions:
        results["tls_versions"] = tls_versions
    print("Done with tls_versions")
    # i) root_ca - Get root certificate authority
    root_ca = get_root_ca(domain)
    if root_ca:
        results["root_ca"] = root_ca
    else:
        results["root_ca"] = None
    print("Done with root_ca")

    # j) rdns_names - Get reverse DNS names
    if ipv4_addresses:
        rdns_names = get_rdns_names(ipv4_addresses)
        results["rdns_names"] = rdns_names
    print("Done with rdns_names")

    # k) rtt_range - Get RTT range
    if ipv4_addresses:
        rtt_range = get_rtt_range(ipv4_addresses)
        if rtt_range:
            results["rtt_range"] = rtt_range
        else:
            results["rtt_range"] = None
    print("Done with rtt_range")
    # l) geo_locations - Get geographic locations
    if ipv4_addresses:
        geo_locations = get_geo_locations(ipv4_addresses)
        if geo_locations:
            results["geo_locations"] = geo_locations
    print("Done with geo_locations")
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
