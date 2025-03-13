#!/usr/bin/env python3

import sys
import json
import time
import socket
import subprocess
import requests
import ipaddress
import os
import re
import tempfile
import dns.resolver
from urllib.parse import urlparse, urljoin

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
    return time.time()

def get_ipv4_addresses(domain):
    """Get IPv4 addresses for a domain using nslookup with multiple DNS resolvers."""
    ipv4_addresses = set()
    resolver_ips = set(PUBLIC_DNS_RESOLVERS) 
    
    # Try DNS resolution with multiple public resolvers
    for resolver in PUBLIC_DNS_RESOLVERS:
        try:
            output = subprocess.check_output(
                ["nslookup", domain, resolver],
                timeout=2,
                stderr=subprocess.STDOUT
            ).decode("utf-8")
            in_answer_section = False
            lines = output.split("\n")
            
            for line in lines:
                if "Non-authoritative answer:" in line:
                    in_answer_section = True
                    continue
                
                if "Address:" in line and not in_answer_section:
                    continue
                if in_answer_section:
                    if "Addresses:" in line:
                        parts = line.split("Addresses:")[1].strip().split()
                        for part in parts:
                            try:
                                ipv4 = ipaddress.IPv4Address(part)
                                if str(ipv4) not in resolver_ips:
                                    ipv4_addresses.add(str(ipv4))
                            except ValueError:
                                pass
                    elif "Address:" in line:
                        ip = line.split("Address:")[1].strip()
                        try:
                            ipv4 = ipaddress.IPv4Address(ip)
                            if str(ipv4) not in resolver_ips:
                                ipv4_addresses.add(str(ipv4))
                        except ValueError:
                            pass
                    elif line.strip() and line[0].isspace():
                        ip = line.strip()
                        try:
                            ipv4 = ipaddress.IPv4Address(ip)
                            if str(ipv4) not in resolver_ips:
                                ipv4_addresses.add(str(ipv4))
                        except ValueError:
                            pass
                    
        except:
            continue
            
    return list(ipv4_addresses)

def get_ipv6_addresses(domain):
    ipv6_addresses = set()
    
    for resolver in PUBLIC_DNS_RESOLVERS:
        try:
            output = subprocess.check_output(
                ["nslookup", "-type=AAAA", domain, resolver],
                timeout=2,
                stderr=subprocess.STDOUT
            ).decode("utf-8")
            
            #parse output
            lines = output.split("\n")
            for line in lines:
                if "Address:" in line and not line.startswith("Server:"):
                    ip = line.split("Address:")[1].strip()
                    try:
                        #validate
                        ipaddress.IPv6Address(ip)
                        ipv6_addresses.add(ip)
                    except ValueError:
                        pass
                        
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            continue
    
    #try with dns
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        for answer in answers:
            ipv6_addresses.add(answer.to_text())
    except Exception:
        pass
        
    return list(ipv6_addresses)

def get_http_server(domain):
    server_header = None
    
    # http
    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
        server_header = response.headers.get("Server")
    except Exception as e:
        print(f"HTTP request failed: {str(e)}")
        pass
    
    #try https
    if not server_header:
        try:
            response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
            server_header = response.headers.get("Server")
        except Exception:
            pass
    
    return server_header 

def check_insecure_http(domain):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(2)
        conn.connect((domain, 80))
        conn.close()
        return True
    except Exception:
        return False

def check_http_redirect(hostname, max_redirects=10):
    result = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((hostname, 80))
        sock.close()
    except (socket.timeout, socket.error):
        return result
    
    http_url = f"http://{hostname}/"
    
    try:
        #make request
        current_url = http_url
        redirect_count = 0
        
        while redirect_count < max_redirects:
            #headers for request 
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
            
            response = requests.get(current_url, 
                                   headers=headers,
                                   allow_redirects=False, 
                                   timeout=10)
            
            # 300 = redirect
            if 300 <= response.status_code < 400:
                if 'Location' in response.headers:
                    next_url = response.headers['Location']
                    
                    if not (next_url.startswith('http://') or next_url.startswith('https://')):
                        next_url = urljoin(current_url, next_url)
                    
                    #check for https
                    if next_url.startswith('https://'):
                        result = True
                        break
                    
                    #go on chain
                    current_url = next_url
                    redirect_count += 1
                else:
                    break
            else:
                # safety check last
                final_url = response.url
                if final_url.startswith('https://'):
                    result = True
                break
        
        # safetycheck last (again)
        if redirect_count == max_redirects and current_url.startswith('https://'):
            result = True
    
    except requests.exceptions.RequestException as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        
    return result



def check_hsts(domain):
    try:
        try:
            preload_check = requests.get(f"https://hstspreload.org/api/v2/status?domain={domain}", timeout=5)
            if preload_check.status_code == 200:
                preload_data = preload_check.json()
                if preload_data.get("status") == "preloaded":
                    return True
        except Exception:
            pass 
        
        # Try multiple paths with redirects enabled
        paths = ["", "/"]
        for path in paths:
            try:
                response = requests.get(f"https://{domain}{path}", timeout=5, allow_redirects=True)
                
                # check header
                hsts_header = response.headers.get('Strict-Transport-Security')
                if hsts_header is not None:
                    return True
                    
                for r in response.history:
                    hsts_header = r.headers.get('Strict-Transport-Security')
                    if hsts_header is not None:
                        return True
            except Exception:
                continue
                
        # try with subdomain
        if not domain.startswith('www.'):
            try:
                response = requests.get(f"https://www.{domain}", timeout=5, allow_redirects=True)
                
                hsts_header = response.headers.get('Strict-Transport-Security')
                if hsts_header is not None:
                    return True
                    
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
    
    try:
        # nmap with ssl-enum-ciphers script
        process = subprocess.run(
            ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30 
        )
        
        output = process.stdout.decode('utf-8', errors='ignore')
        
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
            
            for version, indicators in version_indicators.items():
                if any(indicator in line for indicator in indicators):
                    #check if the version is not offered
                    not_offered = any(phrase in line.lower() for phrase in 
                                      ["not offered", "no supported ciphers", "disabled"])
                    
                    if not not_offered and version not in tls_versions:
                        tls_versions.append(version)
            
    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        #backup in case
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
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=5
                )
                
                stdout = process.stdout.decode('utf-8', errors='ignore')
                stderr = process.stderr.decode('utf-8', errors='ignore')
                
                if "Verify return code:" in stdout and process.returncode == 0:
                    if not any(err in stderr.lower() for err in ["handshake failure", "no protocols available"]):
                        tls_versions.append(version_name)
            except Exception:
                continue
    
    try:
        process = subprocess.run(
            ["openssl", "s_client", "-tls1_3", "-connect", f"{domain}:443"],
            input=b'\n',
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
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
    """Get the root certificate authority (CA) organization name using regex on depth lines."""
    try:
        output = subprocess.check_output(
            ["openssl", "s_client", "-connect", f"{domain}:443", "-showcerts"],
            input=b'',
            timeout=3,
            stderr=subprocess.STDOUT
        ).decode('utf-8', errors='ignore')
        
        pattern = r"depth=(\d+).*?O\s*=\s*([^,/\n]+)"
        matches = re.finditer(pattern, output)
        
        max_depth = -1
        org_name = None
        
        for match in matches:
            depth = int(match.group(1))
            org = match.group(2).strip()
            if depth > max_depth:
                max_depth = depth
                org_name = org
        
        return org_name
    except Exception:
        return None


def get_rdns_names(ipv4_addresses):
    rdns_names = []
    
    for ip in ipv4_addresses:
        try:
            reversed_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
            
            output = subprocess.check_output(
                ["nslookup", "-type=PTR", reversed_ip],
                timeout=2,
                stderr=subprocess.STDOUT
            ).decode('utf-8')
            
            for line in output.split('\n'):
                if 'name = ' in line.lower():
                    name = line.split('name = ')[1].strip()
                    if name.endswith('.'):
                        name = name[:-1] 
                    rdns_names.append(name)
        except Exception:
            #try again with dnspy
            try:
                answers = dns.resolver.resolve(reversed_ip, 'PTR')
                for answer in answers:
                    name = answer.to_text()
                    if name.endswith('.'):
                        name = name[:-1]  
                    rdns_names.append(name)
            except Exception:
                continue
    
    return rdns_names

def get_rtt_range(ipv4_addresses):
    rtts = []
    
    for ip in ipv4_addresses:
        for port in [443, 80, 22]: #multiple common ports
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                sock.close()
                end_time = time.time()
                
                rtt = (end_time - start_time) * 1000
                rtts.append(rtt)
                break
            except Exception:
                continue
    
    if not rtts:
        return None
    
    return [min(rtts), max(rtts)]

def get_geo_locations(ipv4_addresses):
    locations = set()
    
    try:
        import maxminddb
        import os
        import sys
        
        if not os.path.exists('GeoLite2-City.mmdb'):
            sys.stderr.write("Error: GeoLite2-City.mmdb not found in the current directory.\n")
            return []
        with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
            for ip in ipv4_addresses:
                try:
                    result = reader.get(ip)
                    
                    if result:
                        city = ""
                        region = ""
                        country = ""
                        
                        #city
                        if 'city' in result and 'names' in result['city'] and 'en' in result['city']['names']:
                            city = result['city']['names']['en']
                        
                        # region
                        if ('subdivisions' in result and result['subdivisions'] and 
                            'names' in result['subdivisions'][0] and 'en' in result['subdivisions'][0]['names']):
                            region = result['subdivisions'][0]['names']['en']
                        
                        #country
                        if 'country' in result and 'names' in result['country'] and 'en' in result['country']['names']:
                            country = result['country']['names']['en']
                        
                        #only add the location if all three components are present
                        if city and region and country:
                            location = ", ".join([city, region, country])
                            locations.add(location)
                except Exception:
                    continue
    except Exception as e:
        sys.stderr.write(f"Error accessing GeoLite2 database: {str(e)}\n")
        return []
    
    return list(locations)


def scan_domain(domain):
    """Scan a domain and return a dictionary of results."""
    results = {}
    
    #a) scan_time
    results["scan_time"] = get_scan_time()
    print("Done with scan_time")
    
    # b) ipv4_addresses 
    ipv4_addresses = get_ipv4_addresses(domain)
    results["ipv4_addresses"] = ipv4_addresses
    print("Done with ipv4_addresses")
    
    # c) ipv6_addresses
    results["ipv6_addresses"] = get_ipv6_addresses(domain)
    print("Done with ipv6 addresses")
    
    # d) http_server
    http_server = get_http_server(domain)
    if http_server:
        results["http_server"] = http_server
    else:
        results["http_server"] = None
    
    # e) insecure_http 
    results["insecure_http"] = check_insecure_http(domain)
    print("Done with insecure_http")
    
    # f) redirect_to_https 
    results["redirect_to_https"] = check_http_redirect(domain)
    print("Done with redirect_to_https")
    
    # g) hsts 
    results["hsts"] = check_hsts(domain)
    print("Done with hsts")
    
    # h) tls_versions 
    tls_versions = get_tls_versions(domain)
    if tls_versions:
        results["tls_versions"] = tls_versions
    print("Done with tls_versions")
    # i) root_ca 
    root_ca = get_root_ca(domain)
    if root_ca:
        results["root_ca"] = root_ca
    else:
        results["root_ca"] = None
    print("Done with root_ca")

    # j) rdns_names 
    if ipv4_addresses:
        rdns_names = get_rdns_names(ipv4_addresses)
        results["rdns_names"] = rdns_names
    print("Done with rdns_names")

    # k) rtt_range
    if ipv4_addresses:
        rtt_range = get_rtt_range(ipv4_addresses)
        if rtt_range:
            results["rtt_range"] = rtt_range
        else:
            results["rtt_range"] = None
    print("Done with rtt_range")
    # l) geo_locations
    if ipv4_addresses:
        geo_locations = get_geo_locations(ipv4_addresses)
        if geo_locations:
            results["geo_locations"] = geo_locations
        else:
            results["geo_locations"] = []
    print("Done with geo_locations")
    return results

def main():
    # Check if correct number of arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py [input_file.txt] [output_file.json]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        with open(input_file, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    
    scan_results = {}
    for domain in domains:
        print(f"Scanning {domain}...")
        scan_results[domain] = scan_domain(domain)
    
    # write results
    with open(output_file, "w") as f:
        json.dump(scan_results, f, sort_keys=True, indent=4)
    
    print(f"Scan completed. Results saved to {output_file}")

if __name__ == "__main__":
    main()
