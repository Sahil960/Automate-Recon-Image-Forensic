# app.py
import os
import socket
import requests
import requests.exceptions
import json
import threading
import queue
from flask import Flask, render_template, request, jsonify, flash
from bs4 import BeautifulSoup
import nmap
import dns.resolver
import dns.zone
import dns.exception
import whois
from urllib.parse import urljoin, urlparse, quote
import warnings
import subprocess # For running external commands
import tempfile   # For temporary files
import shutil     # For finding executables (which) and file operations
import logging    # Better logging

# --- Lib Imports ---
from dotenv import load_dotenv
from serpapi import GoogleSearch
import webtech
from github import Github, GithubException
import waybackpy
# --- Pillow (Optional Fallback - currently unused in main flow) ---
try:
    from PIL import Image
    from PIL.ExifTags import TAGS as PILLOW_TAGS, GPSTAGS as PILLOW_GPSTAGS
    pillow_available = True
except ImportError:
    pillow_available = False
# --- End Lib Imports ---

# --- Configuration ---
load_dotenv()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # Limit upload size
app.secret_key = os.urandom(24) # For flash messages
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


WORDLIST_FILE = os.path.join(os.path.dirname(__file__), 'common_dirs.txt')
DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"

# --- API Keys and Tokens ---
SERPAPI_API_KEY = os.getenv('SERPAPI_API_KEY')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
# --- End API Keys ---

# --- Global variable for ExifTool path ---
EXIFTOOL_PATH = None

# --- Helper Functions (Recon - Keep Existing) ---
# ... (is_valid_target, format_url, safe_get_request remain the same) ...
def is_valid_target(target):
    """ Basic check if target is an IP or resolvable hostname """
    try:
        socket.inet_aton(target)
        return True # It's a valid IP address format
    except socket.error:
        # Not an IP, try resolving as hostname
        try:
            socket.gethostbyname(target)
            return True # It's a resolvable hostname
        except socket.gaierror:
            return False # Cannot resolve hostname

def format_url(target):
    """ Ensure target has a scheme (http/https) """
    if not target.startswith(('http://', 'https://')):
        return 'http://' + target
    return target

def safe_get_request(url, timeout=10, headers={'User-Agent': 'ReconTool/1.1'}):
    """ Wrapper for requests.get with SSL verification fallback """
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers, verify=True)
        response.raise_for_status()
        return response
    except requests.exceptions.SSLError as e:
        logging.warning(f"SSL Error for {url}. Cert verification failed ({e}). Trying without verify...")
        try:
             response = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers, verify=False)
             response.raise_for_status()
             logging.info(f"Success: Fetched {url} without SSL verification.")
             return response
        except requests.exceptions.RequestException as e_no_verify:
             logging.error(f"Error fetching {url} (even without SSL verify): {e_no_verify}")
             return f"Error fetching {url} (even without SSL verify): {e_no_verify}" # Return error string
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return f"Error fetching {url}: {e}" # Return error string

# --- Passive Recon Functions (Keep Existing) ---
# ... (get_whois_info, get_dns_records, find_subdomains_crtsh, ...)
# ... (search_google_dorks_serpapi, detect_technologies, ...)
# ... (search_github_repos, get_wayback_snapshots remain the same) ...
def get_whois_info(domain):
    """ Performs WHOIS lookup """
    logging.info(f"Starting WHOIS lookup for {domain}")
    try:
        w = whois.whois(domain)
        result = {}
        if not hasattr(w, 'domain_name') or not w.domain_name:
             logging.warning(f"Could not retrieve valid WHOIS data for {domain}")
             return {"error": f"Could not retrieve valid WHOIS data for {domain} (domain might not exist or is private)."}
        valid_items = {k: v for k, v in w.items() if v is not None}
        for key, value in valid_items.items():
            if isinstance(value, list):
                result[key] = [str(item) if not isinstance(item, (str, int, float, bool)) else item for item in value]
            else:
                result[key] = str(value) if not isinstance(value, (str, int, float, bool)) else value
        logging.info(f"WHOIS lookup finished for {domain}.")
        return result if result else {"info": f"Minimal or no WHOIS data found for {domain}."}
    except whois.parser.PywhoisError as e:
         logging.error(f"WHOIS lookup failed for {domain}: {e}")
         return {"error": f"WHOIS lookup failed for {domain}: {e}"}
    except Exception as e:
        logging.exception(f"WHOIS lookup failed unexpectedly for {domain}")
        return {"error": f"WHOIS lookup failed for {domain}: {type(e).__name__}"}

def get_dns_records(domain):
    """ Retrieves common DNS records """
    logging.info(f"Starting DNS record query for {domain}")
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    nxdomain_found = False

    for r_type in record_types:
        if nxdomain_found:
            records[r_type] = ["NXDOMAIN"]
            continue
        try:
            answers = resolver.resolve(domain, r_type)
            records[r_type] = sorted([str(rdata).rstrip('.') for rdata in answers])
        except dns.resolver.NoAnswer: records[r_type] = ["No record found"]
        except dns.resolver.NXDOMAIN:
            logging.info(f"NXDOMAIN encountered for {domain} querying {r_type}")
            records[r_type] = ["NXDOMAIN"]; nxdomain_found = True
        except dns.exception.Timeout: records[r_type] = ["DNS query timed out"]
        except dns.resolver.NoNameservers:
             logging.warning(f"No nameservers found for {domain} querying {r_type}")
             records[r_type] = ["No nameservers found"]; nxdomain_found = True
        except Exception as e:
            logging.error(f"Error querying {r_type} for {domain}: {type(e).__name__}")
            records[r_type] = [f"Error querying {r_type}: {type(e).__name__}"]
    logging.info(f"DNS query finished for {domain}.")
    return records

def find_subdomains_crtsh(domain):
    """ Finds subdomains using crt.sh """
    logging.info(f"Starting crt.sh subdomain search for {domain}")
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    response = safe_get_request(url, timeout=25)

    if isinstance(response, str): # Check if safe_get_request returned an error string
        logging.error(f"Error fetching crt.sh data: {response}")
        return {"error": f"Error fetching from crt.sh: {response}"} # Return error dict

    try:
        content = response.json()
        if not isinstance(content, list):
            logging.error(f"Unexpected response format from crt.sh for {domain}")
            return {"error": "Unexpected response format from crt.sh"}
        for entry in content:
             if 'name_value' in entry and isinstance(entry['name_value'], str):
                names = entry['name_value'].split('\n')
                for name in names:
                    clean_name = name.strip().lower()
                    if domain in clean_name and clean_name != domain and '.' in clean_name and not clean_name.startswith('*'):
                         subdomains.add(clean_name)

        logging.info(f"crt.sh search finished. Found {len(subdomains)} potential subdomains.")
        subdomain_list = sorted(list(subdomains))
        return {"data": subdomain_list, "source": "crt.sh"} if subdomains else {"info": "No subdomains found via crt.sh"}

    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from crt.sh for {domain}")
        return {"error": "Could not decode JSON response from crt.sh"}
    except Exception as e:
        logging.exception(f"Error processing crt.sh data for {domain}")
        return {"error": f"An unexpected error occurred processing crt.sh data: {type(e).__name__}"}

def search_google_dorks_serpapi(domain, max_results_per_dork=5):
    """ Performs Google Dork searches using SerpApi """
    if not SERPAPI_API_KEY:
        logging.error("SerpApi API key not configured.")
        return {"error": "SerpApi API key (SERPAPI_API_KEY) not configured."}

    logging.info(f"Starting SerpApi Google Dork searches for {domain}")
    results = {"info": f"SerpApi Results (Max {max_results_per_dork} per dork)", "dorks": {}}
    dorks_to_try = [ f"site:{domain}", f"site:{domain} filetype:pdf | filetype:docx | filetype:xlsx | filetype:pptx", f"site:{domain} filetype:log | filetype:txt | filetype:cfg | filetype:env | filetype:ini", f"site:{domain} filetype:sql | filetype:db | filetype:mdb | filetype:bak", f"site:{domain} intitle:\"index of\"", f"site:{domain} inurl:login | inurl:signin | inurl:admin | inurl:user | inurl:register | inurl:auth", f"site:{domain} intext:\"password\" | intext:\"secret\" | intext:\"confidential\" | intext:\"internal use only\" | intext:\"api_key\"", f"site:{domain} intext:\"@{domain}\"", f"site:{domain} ext:php | ext:asp | ext:aspx | ext:jsp | ext:cfm | ext:swf", f"site:{domain} inurl:wp-content | inurl:wp-includes", f"site:{domain} \"Error Occurred\" | \"Warning:\"" ]

    for dork_query in dorks_to_try:
        params = { "q": dork_query, "api_key": SERPAPI_API_KEY, "num": max_results_per_dork }
        logging.info(f"  Querying SerpApi: {dork_query}")
        try:
            search = GoogleSearch(params); data = search.get_dict(); dork_results = []
            if "organic_results" in data and data["organic_results"]:
                for result in data["organic_results"][:max_results_per_dork]:
                    dork_results.append({ "title": result.get("title", "N/A"), "link": result.get("link", "#"), "snippet": result.get("snippet", "N/A") })
            elif "error" in data:
                logging.warning(f"SerpApi Error for '{dork_query}': {data['error']}")
                dork_results.append({"error": data["error"]})
            else: dork_results.append({"info": "No organic results found for this dork."})
            results["dorks"][dork_query] = dork_results
        except Exception as e:
            error_msg = f"SerpApi request failed for '{dork_query}': {type(e).__name__}"
            logging.error(f"    Error: {error_msg}")
            results["dorks"][dork_query] = [{"error": error_msg}]
    logging.info("SerpApi Google Dork searches finished.")
    return results

def detect_technologies(url):
    """ Detects web technologies using webtech """
    target_url = format_url(url)
    logging.info(f"Starting Technology Detection on {target_url}")
    results = {"url": target_url, "technologies": [], "error": None}
    try:
        wt = webtech.WebTech(options={'json': False})
        response = safe_get_request(target_url)
        if isinstance(response, str):
            results["error"] = f"Technology Detection: Could not fetch URL: {response}"
            logging.error(results["error"])
            return results
        tech_results = wt.start_from_response(response=response)
        if tech_results:
            processed_tech = []
            for tech_name, tech_info in tech_results.items():
                version = tech_info.get('version') if isinstance(tech_info, dict) else None
                tech_entry = {"name": tech_name}
                if version: tech_entry["version"] = version
                processed_tech.append(tech_entry)
            results["technologies"] = sorted(processed_tech, key=lambda x: x['name'])
        else: results["info"] = "No specific technologies detected by webtech."
    except ImportError:
        results["error"] = "The 'webtech' library is not installed. Cannot perform technology detection."
        logging.error(results["error"])
    except Exception as e:
        results["error"] = f"Technology detection failed: {type(e).__name__}"
        logging.exception(f"Technology detection failed for {target_url}") # Log exception details
    logging.info(f"Technology Detection finished for {target_url}. Found: {len(results.get('technologies', []))} techs.")
    return results

def search_github_repos(domain_or_org, max_repos=10, max_code_results=5):
    """ Searches GitHub for repositories and code snippets related to the target """
    if not GITHUB_TOKEN:
        logging.error("GitHub Token not configured.")
        return {"error": "GitHub Token (GITHUB_TOKEN) not configured."}
    logging.info(f"Starting GitHub search for: {domain_or_org}")
    results = {"query": domain_or_org, "repositories": [], "code_snippets": [], "error": None}
    try:
        g = Github(GITHUB_TOKEN)
        repo_query = f'"{domain_or_org}" in:name,description,readme'; logging.info(f"  Searching GitHub Repos: {repo_query}")
        repositories = g.search_repositories(query=repo_query); repo_count = 0
        for repo in repositories:
            if repo_count >= max_repos: break
            results["repositories"].append({ "name": repo.full_name, "url": repo.html_url, "description": repo.description, "stars": repo.stargazers_count, "last_updated": str(repo.updated_at) })
            repo_count += 1
        logging.info(f"  Found {len(results['repositories'])} potentially relevant repositories (limit {max_repos}).")
        code_keywords = ["password", "secret", "apikey", "token", "config", "internal", "staging", "database", "backup", "credential", "pwd", "admin"]
        code_queries = [f'"{domain_or_org}"'] + [f'"{domain_or_org}" "{keyword}"' for keyword in code_keywords]
        total_code_found = 0; snippet_urls_found = set()
        for code_query in code_queries:
             if total_code_found >= max_code_results: break
             logging.info(f"  Searching GitHub Code: {code_query}")
             try:
                 code_items = g.search_code(query=code_query); limit_per_query = max(1, max_code_results - total_code_found); found_this_query = 0
                 for item in code_items:
                     if total_code_found >= max_code_results or found_this_query >= limit_per_query : break
                     if item.html_url not in snippet_urls_found:
                         results["code_snippets"].append({ "filename": item.name, "repo": item.repository.full_name, "url": item.html_url, "query_matched": code_query })
                         snippet_urls_found.add(item.html_url); total_code_found += 1; found_this_query += 1
             except GithubException as ge:
                  if ge.status == 403: err_msg = f"GitHub API Error (Code Search: '{code_query}'): {ge.status} {ge.data.get('message', '')}. Check token/permissions or rate limit."; logging.warning(f"    {err_msg}"); results["code_snippets"].append({"error": err_msg}); break
                  elif ge.status == 422: err_msg = f"GitHub API Error (Code Search: '{code_query}'): {ge.status} {ge.data.get('message', '')}. Invalid query?"; logging.warning(f"    {err_msg}") # Skip query
                  else: err_msg = f"GitHub API Error (Code Search: '{code_query}'): Status {ge.status}"; logging.warning(f"    {err_msg}"); results["code_snippets"].append({"error": err_msg})
             except Exception as e_code: err_msg = f"Unexpected Error during GitHub Code Search ('{code_query}'): {type(e_code).__name__}"; logging.error(f"    {err_msg}"); results["code_snippets"].append({"error": err_msg})
        logging.info(f"  Found {len(results['code_snippets'])} unique potentially relevant code snippets (limit {max_code_results}).")
        if not results["repositories"] and not results["code_snippets"]: results["info"] = "No relevant repositories or code snippets found on GitHub."
    except GithubException as ge:
        if ge.status == 401: results["error"] = "GitHub Authentication Error: Invalid Token. Please check GITHUB_TOKEN."
        elif ge.status == 403: results["error"] = f"GitHub API Error (Initial Setup/Repo Search): {ge.status} {ge.data.get('message', '')}. Check token/permissions or rate limit."
        else: results["error"] = f"GitHub API Error: Status {ge.status} - {ge.data.get('message', 'Unknown Error')}"
        logging.error(results["error"])
    except Exception as e:
        results["error"] = f"GitHub search failed: {type(e).__name__}"
        logging.exception(f"GitHub search failed for {domain_or_org}")
    logging.info("GitHub search finished.")
    return results

def get_wayback_snapshots(domain, max_snapshots=20):
    """ Fetches historical snapshots from the Wayback Machine """
    logging.info(f"Starting Wayback Machine search for: {domain}")
    results = {"domain": domain, "snapshots": [], "error": None}
    try:
        user_agent = "Mozilla/5.0 (compatible; ReconTool/1.1; +http://example.com/bot)"
        wayback = waybackpy.WaybackMachine(domain, user_agent=user_agent)
        try:
             oldest = wayback.oldest(); newest = wayback.newest()
             results["oldest_snapshot_url"] = oldest.archive_url; results["oldest_snapshot_time"] = str(oldest.timestamp)
             results["newest_snapshot_url"] = newest.archive_url; results["newest_snapshot_time"] = str(newest.timestamp)
        except waybackpy.exceptions.NoCDXRecordFound:
             results["info"] = "No snapshots found for this domain on Wayback Machine."; logging.info(f"  Info: {results['info']}"); return results
        except Exception as e_snap: logging.warning(f"Could not get oldest/newest snapshot details for {domain}: {e_snap}")
        logging.info(f"Fetching known URLs/snapshots for {domain} (limit {max_snapshots})...")
        try: urls_data = wayback.known_urls(limit=max_snapshots)
        except Exception as e_known: logging.warning(f"Failed to fetch known URLs from Wayback for {domain}: {e_known}"); urls_data = []
        if urls_data:
            snapshot_list = []; processed_urls = set()
            for item in urls_data:
                 if isinstance(item, dict):
                     timestamp = item.get('timestamp'); original_url = item.get('urlkey') or item.get('original'); status_code = item.get('statuscode')
                     if timestamp and original_url:
                         archive_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
                         if archive_url not in processed_urls:
                             snapshot_list.append({ "url": original_url, "timestamp": timestamp, "archive_url": archive_url, "status": status_code }); processed_urls.add(archive_url)
                 elif isinstance(item, str):
                      if item not in processed_urls: snapshot_list.append({"url": item, "timestamp": "Unknown", "archive_url": "#unknown"}); processed_urls.add(item)
            try: results["snapshots"] = sorted(snapshot_list, key=lambda x: x.get('timestamp', '0'), reverse=True)
            except: results["snapshots"] = snapshot_list
            if not results.get("info"): results["info"] = f"Found {len(results['snapshots'])} unique snapshots/known URLs (limit {max_snapshots})."
        elif not results.get("info"): results["info"] = "Could not retrieve list of known URLs/snapshots."
    except ImportError: results["error"] = "The 'waybackpy' library is not installed."; logging.error(results["error"])
    except Exception as e: results["error"] = f"Wayback Machine search failed unexpectedly: {type(e).__name__}"; logging.exception(f"Wayback search failed for {domain}")
    logging.info(f"Wayback Machine search finished for {domain}.")
    return results

# --- Active Recon Functions (Keep Existing) ---
# ... (scan_ports, crawl_web, attempt_zone_transfer, fuzz_directories remain the same) ...
def scan_ports(target, ports=DEFAULT_PORTS):
    """ Performs Nmap port scan """
    if not is_valid_target(target):
        logging.error(f"Invalid target for Nmap scan: {target}")
        return {"error": f"Invalid target for Nmap scan: {target}"}
    try:
        nm = nmap.PortScanner()
        logging.info(f"Starting Nmap scan on {target} for ports: {ports}")
        arguments = f'-p {ports} -sV -T4 --open'
        # Consider adding -Pn: arguments += ' -Pn'
        nm.scan(target, arguments=arguments)
        results = {}
        if not nm.all_hosts():
             scan_info = nm.scaninfo()
             if 'error' in scan_info and scan_info['error']: err_msg = f"Nmap scan failed: {' '.join(scan_info['error'])}"; logging.error(err_msg); return {"error": err_msg}
             try:
                 host_state = nm[target].state() if target in nm else 'unknown'
                 if host_state == 'up': err_msg = f"Nmap scan completed but no host data found for {target} (State: {host_state})."; logging.warning(err_msg); return {"info": err_msg} # Changed to info
                 else: err_msg = f"Nmap scan failed or host {target} is down/unreachable (State: {host_state}). Consider '-Pn' argument."; logging.error(err_msg); return {"error": err_msg}
             except KeyError: err_msg = f"Nmap scan failed to get results for host {target}. It might be down or unreachable."; logging.error(err_msg); return {"error": err_msg}
        host_info = nm[target]
        results['host'] = target; results['hostname'] = host_info.hostname() or 'N/A'; results['state'] = host_info.state(); results['open_ports'] = {}; results['scan_arguments'] = arguments
        for proto in host_info.all_protocols():
            lport = host_info[proto].keys()
            for port in sorted(list(lport)):
                port_info = host_info[proto][port]
                if port_info['state'] == 'open':
                     results['open_ports'][f"{port}/{proto}"] = { 'state': port_info['state'], 'service': port_info.get('name', '?'), 'product': port_info.get('product', ''), 'version': port_info.get('version', ''), 'extrainfo': port_info.get('extrainfo', ''), 'cpe': port_info.get('cpe', '') }
        if not results['open_ports']: results['info'] = "No open ports found in the specified range."
        logging.info(f"Nmap scan finished for {target}.")
        return results
    except nmap.PortScannerError as e: logging.error(f"Nmap command execution error: {e}. Check path/install."); return {"error": f"Nmap command execution error: {e}. Check path/install."}
    except KeyError as e: logging.warning(f"Nmap result parsing error (KeyError: {e}) for {target}. Host might be down."); return {"error": f"Nmap result parsing error (KeyError: {e}). Host likely down?"}
    except Exception as e: logging.exception(f"Port scan failed unexpectedly for {target}"); return {"error": f"Port scan failed: {type(e).__name__}"}

def crawl_web(start_url, max_depth=1, max_urls=50):
    """ Basic web crawler, follows redirects, handles SSL errors """
    try:
        formatted_start_url = format_url(start_url); base_domain = urlparse(formatted_start_url).netloc
        if not base_domain: raise ValueError("Invalid base domain parsed from URL.")
    except Exception as e: logging.error(f"Error processing start URL '{start_url}': {e}"); return {'error': f"Invalid start URL '{start_url}': {e}"}
    visited = set(); urls_to_visit = queue.Queue(); urls_to_visit.put((formatted_start_url, 0))
    crawled_data = {'start_url': formatted_start_url, 'crawled_pages': {}, 'errors': [], 'external_links': set()}; count = 0
    logging.info(f"Starting web crawl from {formatted_start_url}")
    while not urls_to_visit.empty() and count < max_urls:
        current_url, depth = urls_to_visit.get(); normalized_url = current_url.rstrip('/')
        if normalized_url in visited or depth > max_depth: continue
        visited.add(normalized_url); count += 1; logging.info(f"Crawling ({count}/{max_urls}): {current_url} (Depth: {depth})")
        response = safe_get_request(current_url)
        if isinstance(response, str): crawled_data['errors'].append(response); continue
        content_type = response.headers.get('Content-Type', '').lower()
        if 'html' not in content_type:
             logging.info(f"Skipping non-HTML content at {current_url} (Type: {content_type})")
             crawled_data['crawled_pages'][current_url] = {'title': f'Non-HTML Content ({content_type})', 'status_code': response.status_code}
             continue
        try:
            soup = BeautifulSoup(response.text, 'html.parser'); page_title = soup.title.string.strip() if soup.title else 'No Title Found'
            crawled_data['crawled_pages'][current_url] = {'title': page_title, 'status_code': response.status_code}
            if depth < max_depth:
                for link in soup.find_all('a', href=True):
                    href = link['href'].strip()
                    if not href or href.startswith(('#', 'mailto:', 'javascript:', 'tel:')): continue
                    try:
                        abs_url = urljoin(current_url, href); parsed_abs_url = urlparse(abs_url)
                        if parsed_abs_url.scheme not in ['http', 'https'] or not parsed_abs_url.netloc: continue
                        normalized_abs_url = abs_url.rstrip('/')
                        if parsed_abs_url.netloc == base_domain:
                            if normalized_abs_url not in visited: urls_to_visit.put((abs_url, depth + 1))
                        else: crawled_data['external_links'].add(abs_url)
                    except Exception as e_link: logging.warning(f"Error processing link '{href}' on page {current_url}: {e_link}"); crawled_data['errors'].append(f"Error processing link '{href}' on page {current_url}: {e_link}")
        except Exception as e_parse: logging.error(f"Error parsing HTML from {current_url}: {e_parse}"); crawled_data['errors'].append(f"Error parsing HTML from {current_url}: {e_parse}")
    crawled_data['external_links'] = sorted(list(crawled_data['external_links']))
    crawled_data['info'] = f"Crawled {len(crawled_data['crawled_pages'])} pages ({len(visited)} unique URLs visited) up to depth {max_depth} (limit {max_urls} URLs)."
    logging.info(f"Web crawl finished for {formatted_start_url}.");
    return crawled_data

def attempt_zone_transfer(domain):
    """ Attempts DNS Zone Transfer (AXFR) """
    results = {"status": "Not Attempted", "records": [], "error": None, "checked_ns": []}
    logging.info(f"Attempting Zone Transfer (AXFR) for {domain}")
    try:
        resolver = dns.resolver.Resolver(); resolver.timeout = 5; resolver.lifetime = 5
        ns_records = resolver.resolve(domain, 'NS'); ns_servers = [str(ns.target).rstrip('.') for ns in ns_records]
        if not ns_servers: raise dns.resolver.NoNameservers("Could not find Name Servers (NS records).")
        results["status"] = f"Found {len(ns_servers)} NS servers. Attempting AXFR..."; results["checked_ns"] = ns_servers
        zone_data = None; successful_ns = None
        for ns_server in ns_servers:
            logging.info(f"  Trying AXFR against NS: {ns_server}")
            try:
                try: ns_ip_info = resolver.resolve(ns_server, 'A'); ns_ip = str(ns_ip_info[0]); logging.info(f"    Resolved {ns_server} to {ns_ip}")
                except Exception as e_ip: logging.warning(f"Could not resolve IP for NS {ns_server}: {e_ip}. Skipping."); results["status"] += f"\n - Failed to resolve IP for {ns_server}."; continue
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=15, lifetime=20))
                if z: zone_data = z; successful_ns = ns_server; logging.info(f"    SUCCESS: Zone Transfer successful from {ns_server} ({ns_ip})!"); results["status"] = f"Zone Transfer successful from {successful_ns}!"; break
                else: logging.warning(f"AXFR query to {ns_server} ({ns_ip}) returned no zone but no exception?"); results["status"] += f"\n - Query returned no zone on {ns_server}"
            except dns.exception.FormError: logging.info(f"    Failed: FormError/Not Authorized on {ns_server} ({ns_ip})."); results["status"] += f"\n - Failed (FormError/Not Authorized) on {ns_server}"
            except dns.exception.Timeout: logging.info(f"    Failed: Timeout connecting/transferring from {ns_server} ({ns_ip})."); results["status"] += f"\n - Failed (Timeout) on {ns_server}"
            except ConnectionRefusedError: logging.info(f"    Failed: Connection refused by {ns_server} ({ns_ip})."); results["status"] += f"\n - Failed (Connection Refused) on {ns_server}"
            except EOFError: logging.warning(f"    Failed: EOFError (Server closed connection unexpectedly) on {ns_server} ({ns_ip})."); results["status"] += f"\n - Failed (EOFError) on {ns_server}"
            except Exception as e_xfr: error_type = type(e_xfr).__name__; logging.warning(f"    Failed: Unexpected {error_type} on {ns_server} ({ns_ip}): {e_xfr}"); results["status"] += f"\n - Failed ({error_type}) on {ns_server}"; results["error"] = f"An error occurred during AXFR attempt on {ns_server}: {e_xfr}"
        if zone_data:
            for name, node in zone_data.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                         record_name = str(name); record_name = domain + "." if record_name == "@" else record_name if record_name.endswith('.') else f"{record_name}.{domain}."
                         record_data_str = str(rdata).rstrip('.'); results["records"].append(f"{record_name} {rdataset.rdtype} {record_data_str}")
            results["records"] = sorted(results["records"])
        elif not results["error"]: final_status = "Zone Transfer failed on all checked NS servers (likely refused or server errors)."; logging.info(f"    {final_status}"); results["status"] = final_status
    except dns.resolver.NoAnswer: results["error"] = f"Could not find NS records for {domain}."; results["status"] = "Failed (No NS Found)"; logging.warning(results["error"])
    except dns.resolver.NXDOMAIN: results["error"] = f"Domain {domain} does not exist (NXDOMAIN)."; results["status"] = "Failed (NXDOMAIN)"; logging.warning(results["error"])
    except dns.resolver.NoNameservers: results["error"] = f"Authoritative nameservers could not be found for {domain}."; results["status"] = "Failed (No Nameservers Found)"; logging.warning(results["error"])
    except Exception as e_setup: error_type = type(e_setup).__name__; results["error"] = f"An unexpected error occurred during AXFR setup: {error_type}"; results["status"] = "Failed (Setup Error)"; logging.exception(f"AXFR setup failed for {domain}")
    logging.info(f"Zone Transfer attempt finished for {domain}.")
    return results

def fuzz_directories(base_url):
    """ Basic directory/file fuzzing """
    try:
        formatted_base_url = format_url(base_url).rstrip('/'); urlparse(formatted_base_url).netloc # Validate
    except Exception as e: logging.error(f"Invalid base URL '{base_url}': {e}"); return {"error": f"Invalid base URL '{base_url}': {e}"}
    results = {"base_url": formatted_base_url, "found": [], "errors": [], "wordlist_status": "Not found"}
    logging.info(f"Starting directory fuzzing on {formatted_base_url}")
    if not os.path.exists(WORDLIST_FILE):
        results["errors"].append(f"Wordlist file not found: {WORDLIST_FILE}"); logging.error(f"Wordlist file not found at {WORDLIST_FILE}"); return results
    results["wordlist_status"] = f"Using '{os.path.basename(WORDLIST_FILE)}'"; found_count = 0; processed_count = 0; wordlist = []
    try:
        with open(WORDLIST_FILE, 'r', encoding='utf-8', errors='ignore') as f: wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        logging.info(f"  Loaded {len(wordlist)} items from wordlist.")
        for item in wordlist:
            processed_count += 1; fuzz_url = f"{formatted_base_url}/{item}"
            try:
                response = requests.head(fuzz_url, timeout=5, allow_redirects=False, headers={'User-Agent': 'ReconTool/1.1'}, verify=True)
                if response.status_code < 400 or response.status_code == 403: status_info = f"{fuzz_url} - Status: {response.status_code}"; logging.info(f"    Found: {status_info}"); results["found"].append(status_info); found_count += 1
            except requests.exceptions.SSLError:
                 try:
                     response = requests.head(fuzz_url, timeout=5, allow_redirects=False, headers={'User-Agent': 'ReconTool/1.1'}, verify=False)
                     if response.status_code < 400 or response.status_code == 403: status_info = f"{fuzz_url} - Status: {response.status_code} (SSL Verify Failed)"; logging.info(f"    Found: {status_info}"); results["found"].append(status_info); found_count += 1
                 except requests.exceptions.RequestException: pass # Ignore errors after SSL fallback
            except requests.exceptions.Timeout: pass # Usually ignore timeouts
            except requests.exceptions.ConnectionError: pass # Ignore connection errors
            except requests.exceptions.RequestException: pass # Ignore other request errors unless debugging
    except FileNotFoundError: results["errors"].append(f"Wordlist file error: {WORDLIST_FILE} not found during read."); logging.error(f"Wordlist disappeared? Path: {WORDLIST_FILE}")
    except Exception as e_fuzz: error_msg = f"Error during fuzzing process: {type(e_fuzz).__name__}"; results["errors"].append(error_msg); logging.exception("Error during fuzzing loop")
    results["info"] = f"Fuzzing complete ({processed_count} paths checked). Found {found_count} potential items."
    logging.info(f"Directory fuzzing finished for {formatted_base_url}. Found: {found_count} items.")
    return results

# --- Forensic Helper Function (Using ExifTool) ---

def analyze_image_with_exiftool(image_stream, image_filename):
    """Analyzes image metadata using the exiftool command line utility."""
    global EXIFTOOL_PATH
    if not EXIFTOOL_PATH:
        logging.error("ExifTool path not found or not configured.")
        return {"error": "ExifTool not found on the server. Please install it and ensure it's in the PATH."}, None

    temp_file_path = None
    try:
        # Create a temporary file to store the uploaded image stream
        # delete=False is important because exiftool needs to open the file by path
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(image_filename)[1]) as temp_file:
            shutil.copyfileobj(image_stream, temp_file)
            temp_file_path = temp_file.name
        logging.info(f"Saved uploaded file to temporary path: {temp_file_path}")

        # Construct the command
        # -j: JSON output
        # -G: Group names (e.g., EXIF:Make)
        # -n: Output numerical values where possible (important for GPS!)
        # Use utf8 encoding for output and handle errors
        command = [EXIFTOOL_PATH, '-j', '-G', '-n', temp_file_path]
        logging.info(f"Running command: {' '.join(command)}")

        # Run ExifTool
        process = subprocess.run(
            command,
            capture_output=True,
            text=True, # Decodes stdout/stderr as text
            encoding='utf-8', # Specify encoding
            errors='replace', # Replace invalid characters
            check=False # Don't raise exception on non-zero exit code
        )

        # Check for errors during execution
        if process.returncode != 0:
            error_message = f"ExifTool exited with error code {process.returncode}."
            if process.stderr:
                error_message += f"\nStderr: {process.stderr.strip()}"
            if process.stdout: # Sometimes errors are on stdout too
                error_message += f"\nStdout: {process.stdout.strip()}"
            logging.error(error_message)
            # Try to give a more specific common error message
            if "File not found" in process.stderr or "File not found" in process.stdout:
                 return {"error": f"ExifTool could not find the temporary file: {temp_file_path}"}, None
            elif "Invalid file type" in process.stderr or "Not a valid" in process.stderr:
                 return {"error": "ExifTool reported an invalid or unsupported file type."}, None
            return {"error": f"ExifTool execution failed (code {process.returncode}). Check server logs."}, None

        # Parse the JSON output
        try:
            # ExifTool -j returns a list containing one object per file
            metadata_list = json.loads(process.stdout)
            if not metadata_list:
                 logging.warning(f"Exiftool returned empty JSON for {image_filename}")
                 return {"info": "ExifTool processed the file but found no metadata or returned empty output."}, None
            # Extract the first (and only) object
            metadata = metadata_list[0]
        except json.JSONDecodeError as json_err:
            logging.error(f"Failed to decode ExifTool JSON output: {json_err}")
            logging.debug(f"ExifTool Raw Output:\n{process.stdout[:1000]}...") # Log beginning of output
            return {"error": "Failed to parse metadata output from ExifTool."}, None
        except IndexError:
             logging.error(f"Exiftool JSON output was an empty list for {image_filename}")
             return {"info": "ExifTool processed the file but returned empty JSON list."}, None


        # --- Extract GPS Coordinates from ExifTool output ---
        # Exiftool composite tags (-n option helps get decimal degrees directly)
        gps_coords = None
        lat = metadata.get("Composite:GPSLatitude") or metadata.get("EXIF:GPSLatitude") # Check composite first
        lon = metadata.get("Composite:GPSLongitude") or metadata.get("EXIF:GPSLongitude")
        alt = metadata.get("Composite:GPSAltitude") or metadata.get("EXIF:GPSAltitude")
        # Check if lat/lon are valid numbers (Exiftool -n provides them as numbers)
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            gps_coords = {
                'latitude': float(lat),
                'longitude': float(lon)
            }
            if isinstance(alt, (int, float)):
                gps_coords['altitude'] = float(alt)
                # Altitude Ref might still be text or number
                alt_ref_val = metadata.get("EXIF:GPSAltitudeRef") # Composite usually doesn't have ref separate
                if alt_ref_val is not None:
                    # Exiftool -n outputs 0 for above, 1 for below
                     gps_coords['altitude_ref'] = "Below Sea Level" if int(alt_ref_val) == 1 else "Above Sea Level"

            logging.info(f"Extracted GPS Coordinates: {gps_coords}")
        else:
            logging.info("GPS coordinates (Composite:GPSLatitude/Longitude as numbers) not found in ExifTool output.")


        # Remove the SourceFile tag added by exiftool if desired
        metadata.pop('SourceFile', None)

        return metadata, gps_coords

    except FileNotFoundError:
        logging.error(f"Could not create temporary file or copy stream for {image_filename}.")
        return {"error": "Server error creating temporary file for analysis."}, None
    except Exception as e:
        logging.exception(f"Unexpected error during ExifTool analysis for {image_filename}")
        return {"error": f"An unexpected server error occurred during ExifTool analysis: {type(e).__name__}"}, None
    finally:
        # --- CRITICAL: Cleanup ---
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
                logging.info(f"Removed temporary file: {temp_file_path}")
            except OSError as e_remove:
                logging.error(f"Error removing temporary file {temp_file_path}: {e_remove}")

# --- Flask Routes ---
@app.route('/')
def index():
    """ Renders the main HTML page """
    # Pass exiftool status to template (optional)
    return render_template('index.html', exiftool_enabled=(EXIFTOOL_PATH is not None))

@app.route('/scan', methods=['POST'])
def scan():
    """ Handles the recon scan request based on selected tasks """
    data = request.get_json()
    if not data: return jsonify({"error": "Invalid request data."}), 400
    target = data.get('target', '').strip(); tasks = data.get('tasks', [])
    if not target: return jsonify({"error": "No target specified."}), 400
    if not tasks: return jsonify({"error": "No tasks selected."}), 400
    if not isinstance(tasks, list): return jsonify({"error": "Invalid format for tasks list."}), 400

    logging.info(f"New Scan Request --- Target: {target}, Tasks: {', '.join(tasks)}")
    is_ip = False; domain_target = None
    try: socket.inet_aton(target); is_ip = True; logging.info("Target identified as IP address.")
    except socket.error:
        logging.info("Target identified as hostname/domain.")
        domain_target = target
        if '.' not in domain_target or ' ' in domain_target: logging.warning(f"Target '{domain_target}' may not be a valid domain name.")

    scan_results = {}; passive_tasks_run_flag = False; active_tasks_run_flag = False
    PASSIVE_TASK_IDS = ['whois', 'dns', 'ct_logs', 'tech_passive', 'github', 'wayback', 'serpapi']
    ACTIVE_TASK_IDS = ['nmap', 'crawl', 'tech_active', 'axfr', 'fuzz']

    for task_id in tasks:
        logging.info(f"  Executing task: {task_id}")
        result_data = {"error": "Task execution failed or not implemented."}
        try:
            if task_id == 'whois': result_data = get_whois_info(domain_target or target); passive_tasks_run_flag = True
            elif task_id == 'dns': result_data = get_dns_records(domain_target) if domain_target else {"info": "DNS records require a domain."}; passive_tasks_run_flag = True
            elif task_id == 'ct_logs': result_data = find_subdomains_crtsh(domain_target) if domain_target else {"info": "Subdomain search requires a domain."}; passive_tasks_run_flag = True
            elif task_id == 'tech_passive': result_data = detect_technologies(target); passive_tasks_run_flag = True
            elif task_id == 'github': result_data = search_github_repos(domain_target) if domain_target else {"info": "GitHub Recon requires a domain/org name."}; passive_tasks_run_flag = True
            elif task_id == 'wayback': result_data = get_wayback_snapshots(domain_target) if domain_target else {"info": "Wayback Machine requires a domain."}; passive_tasks_run_flag = True
            elif task_id == 'serpapi': result_data = search_google_dorks_serpapi(domain_target) if domain_target else {"info": "Google Dorking requires a domain."}; passive_tasks_run_flag = True
            elif task_id == 'nmap': result_data = scan_ports(target) if is_valid_target(target) else {"error": "Invalid target for Nmap scan."}; active_tasks_run_flag = True
            elif task_id == 'crawl': result_data = crawl_web(target); active_tasks_run_flag = True
            elif task_id == 'tech_active': result_data = detect_technologies(target); active_tasks_run_flag = True
            elif task_id == 'axfr': result_data = attempt_zone_transfer(domain_target) if domain_target else {"info": "Zone transfer applies to domains."}; active_tasks_run_flag = True
            elif task_id == 'fuzz': result_data = fuzz_directories(target); active_tasks_run_flag = True
            scan_results[task_id] = result_data
        except Exception as e:
            logging.exception(f"ERROR during task '{task_id}'")
            scan_results[task_id] = {"error": f"Unexpected error during task '{task_id}': {type(e).__name__}"}
            if task_id in PASSIVE_TASK_IDS: passive_tasks_run_flag = True
            if task_id in ACTIVE_TASK_IDS: active_tasks_run_flag = True

    # Add general passive/active info
    if passive_tasks_run_flag:
        if 'manual_google_dorks' not in scan_results: scan_results['manual_google_dorks'] = { "info": "Manual Google Dork Suggestions:", "examples": [ f"site:{target}", f"site:{target} filetype:pdf", "..." ] }
        if 'shodan_censys' not in scan_results: scan_results['shodan_censys'] = { "info": "Check these services manually:", "links": [ f"https://www.shodan.io/search?query={quote(target)}", f"https://search.censys.io/search?resource=hosts&q={quote(target)}" ] }
        if 'manual_checks' not in scan_results: scan_results['manual_checks'] = [ "Check official website...", "Search LinkedIn, GitHub...", "Analyze job postings...", "Look for breach data...", "Check technologies found against vulnerability databases..." ]
    if active_tasks_run_flag:
        if 'manual_vuln_check_suggestion' not in scan_results: scan_results['manual_vuln_check_suggestion'] = "Check identified services/versions & web tech against vulnerability databases."

    logging.info("Scan Request Processing Complete")
    return jsonify({"target": target, "results": scan_results})


@app.route('/analyze_image', methods=['POST'])
def analyze_image():
    """ Handles image upload and performs metadata analysis using ExifTool """
    global EXIFTOOL_PATH
    if not EXIFTOOL_PATH:
        logging.error("Image analysis request received but ExifTool is not available.")
        return jsonify({"error": "Image metadata analysis tool (ExifTool) is not available on the server."}), 503 # Service Unavailable

    if 'image_file' not in request.files:
        return jsonify({"error": "No image file provided in the request."}), 400

    file = request.files['image_file']
    if file.filename == '':
        return jsonify({"error": "No image file selected."}), 400

    # Basic check for common image extensions (ExifTool supports more, but good first filter)
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'tiff', 'bmp', 'webp', 'heic', 'cr2', 'nef', 'arw', 'dng'}
    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if not file_ext or file_ext not in allowed_extensions:
        logging.warning(f"Received file with potentially unsupported extension: {file.filename}")
        # Allow ExifTool to try anyway, but maybe return a warning later if it fails specifically on type
        # return jsonify({"error": f"Potentially unsupported file type '{file_ext}'. Allowed: {', '.join(allowed_extensions)}"}), 400

    logging.info(f"New Forensic Request --- Analyzing image: {file.filename} (using ExifTool)")
    try:
        # Call the helper function that uses ExifTool
        metadata, gps_coords = analyze_image_with_exiftool(file.stream, file.filename)

        logging.info("Image Analysis (ExifTool) Complete")
        return jsonify({
            "filename": file.filename,
            "metadata": metadata, # Contains ExifTool JSON output or error/info
            "gps_coordinates": gps_coords # Contains calculated coords or None
        })

    except Exception as e:
        # Catchall for unexpected errors in the route handler itself
        logging.exception(f"Unexpected error in /analyze_image route for {file.filename}")
        return jsonify({"error": f"An unexpected server error occurred during analysis: {type(e).__name__}"}), 500


# --- Main Execution ---
def find_exiftool():
    """Finds the path to the exiftool executable."""
    path = shutil.which('exiftool')
    if not path:
        # Common Windows location if not in PATH
        path = shutil.which('exiftool.exe')
    # Add other potential common paths if needed, e.g., specific install locations
    if not path and os.name == 'nt':
        path = os.path.join('C:\\Users\\harbl\\Downloads\\exiftool-13.27_64\\exiftool-13.27_64', 'exiftool.exe') # Example
    return path

if __name__ == '__main__':
    logging.info("--- Recon & Forensics Tool ---")
    logging.info("Initializing...")

    # Check ExifTool availability ONCE at startup
    EXIFTOOL_PATH = find_exiftool()
    if EXIFTOOL_PATH:
        logging.info(f"[+] ExifTool found at: {EXIFTOOL_PATH}. Image Forensics enabled.")
    else:
        logging.error("[!] CRITICAL: ExifTool not found in system PATH. Image Forensics features will be disabled.")
        # Decide if the app should exit or just disable the feature
        # For now, we just log the error and the route will return an error message.

    # Check other dependencies (optional, but good practice)
    if not SERPAPI_API_KEY: logging.warning("SERPAPI_API_KEY environment variable not set (Google Dorking disabled).")
    else: logging.info("[+] SerpApi Key found.")
    if not GITHUB_TOKEN: logging.warning("GITHUB_TOKEN environment variable not set (GitHub Recon disabled).")
    else: logging.info("[+] GitHub Token found.")
    try: nmap.PortScanner(); logging.info("[+] Nmap wrapper initialized successfully.")
    except nmap.PortScannerError as e: logging.error(f"Nmap initialization failed: {e}. Ensure Nmap is installed and in PATH."); exit(1)
    if not os.path.exists(WORDLIST_FILE): logging.warning(f"Wordlist file '{WORDLIST_FILE}' not found. Directory fuzzing will fail.")

    logging.info(f"Starting Flask server at http://127.0.0.1:5000 (or http://0.0.0.0:5000)")
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True) # debug=False for production