"""
Utility functions for the enumeration tool
"""
import asyncio
import logging
import json
import subprocess
from typing import List, Dict, Any
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import dns.resolver
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Enumerate subdomains using multiple methods"""
    
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }
        self.results = set()
    
    async def enumerate_crt_sh(self, domain: str) -> List[str]:
        """Get subdomains from crt.sh"""
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            subdomains = []
            for entry in response.json():
                name_value = entry.get('name_value', '')
                for subdomain in name_value.split('\n'):
                    subdomain = subdomain.strip().lower()
                    if subdomain and subdomain not in subdomains:
                        subdomains.append(subdomain)
            
            return subdomains
        except Exception as e:
            logger.error(f"Error fetching from crt.sh: {e}")
            return []
    
    async def enumerate_dnsdumpster(self, domain: str) -> List[str]:
        """Get subdomains from DNS Dumpster"""
        try:
            url = "https://dnsdumpster.com/"
            session = requests.Session()
            response = session.get(url, headers=self.headers, timeout=10)
            csrf_token = response.cookies.get('csrftoken')
            
            data = {'csrfmiddlewaretoken': csrf_token, 'targetip': domain}
            response = session.post(
                url,
                data=data,
                headers={**self.headers, 'Referer': url},
                timeout=10
            )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            subdomains = []
            
            for td in soup.find_all('td'):
                text = td.get_text()
                if '.' in text and domain in text:
                    subdomains.append(text.strip())
            
            return list(set(subdomains))
        except Exception as e:
            logger.error(f"Error fetching from DNSDumpster: {e}")
            return []
    
    async def enumerate_dns_brute(self, domain: str, wordlist: List[str]) -> List[str]:
        """Brute force subdomains using DNS"""
        subdomains = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 5
        
        for word in wordlist:
            try:
                subdomain = f"{word}.{domain}"
                resolver.resolve(subdomain, 'A')
                subdomains.append(subdomain)
                logger.info(f"Found: {subdomain}")
            except:
                pass
        
        return subdomains
    
    async def get_all_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from all sources"""
        tasks = [
            self.enumerate_crt_sh(domain),
            self.enumerate_dnsdumpster(domain)
        ]
        
        results = await asyncio.gather(*tasks)
        all_subdomains = set()
        
        for result in results:
            all_subdomains.update(result)
        
        return sorted(list(all_subdomains))


class DirectoryBuster:
    """Directory and file busting"""
    
    def __init__(self, wordlist: List[str] = None):
        self.wordlist = wordlist or self._load_default_wordlist()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }
        self.found_paths = []
    
    def _load_default_wordlist(self) -> List[str]:
        """Load default common paths"""
        return [
            "admin", "api", "app", "assets", "backup", "bin",
            "build", "cache", "config", "css", "dashboard",
            "data", "debug", "docs", "download", "etc",
            "files", "images", "img", "js", "lib",
            "login", "media", "old", "panel", "public",
            "resources", "scripts", "src", "static", "test",
            "tmp", "upload", "user", "users", "var",
            "vendor", "web", "wp-admin", "wp-content", "wp-includes"
        ]
    
    async def bust_directories(self, base_url: str) -> List[Dict[str, Any]]:
        """Bust directories"""
        found = []
        base_url = base_url.rstrip('/')
        
        for path in self.wordlist:
            try:
                url = f"{base_url}/{path}"
                response = requests.get(url, headers=self.headers, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    found.append({
                        "path": path,
                        "url": url,
                        "status": response.status_code
                    })
                    logger.info(f"Found: {url} ({response.status_code})")
            except Exception as e:
                logger.debug(f"Error checking {path}: {e}")
        
        return found
    
    async def bust_files(self, base_url: str, extensions: List[str] = None) -> List[Dict[str, Any]]:
        """Bust files with common extensions"""
        if extensions is None:
            extensions = [".txt", ".php", ".html", ".xml", ".json", ".bak", ".old", ".zip"]
        
        found = []
        base_url = base_url.rstrip('/')
        
        for path in self.wordlist[:50]:  # Limit to avoid long scans
            for ext in extensions:
                try:
                    url = f"{base_url}/{path}{ext}"
                    response = requests.get(url, headers=self.headers, timeout=5, allow_redirects=False)
                    
                    if response.status_code == 200:
                        found.append({
                            "file": f"{path}{ext}",
                            "url": url,
                            "status": response.status_code,
                            "size": len(response.content)
                        })
                        logger.info(f"Found: {url}")
                except Exception as e:
                    logger.debug(f"Error checking {path}{ext}: {e}")
        
        return found


class TechIdentifier:
    """Identify web technologies"""
    
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }
    
    async def identify_tech(self, url: str) -> Dict[str, Any]:
        """Identify technologies used"""
        tech = {
            "frameworks": [],
            "cms": [],
            "servers": [],
            "languages": [],
            "cdn": [],
            "headers": {}
        }
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            
            # Check headers
            tech["headers"] = dict(response.headers)
            
            # Server detection
            if "Server" in response.headers:
                tech["servers"].append(response.headers["Server"])
            
            # Check HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                content = meta.get('content', '')
                if 'generator' in name:
                    tech["cms"].append(content)
                if 'framework' in name:
                    tech["frameworks"].append(content)
            
            # Common indicators
            html_lower = response.text.lower()
            
            if "wp-content" in html_lower or "wp-includes" in html_lower:
                tech["cms"].append("WordPress")
            if "joomla" in html_lower:
                tech["cms"].append("Joomla")
            if "drupal" in html_lower:
                tech["cms"].append("Drupal")
            if "react" in html_lower:
                tech["frameworks"].append("React")
            if "vue" in html_lower:
                tech["frameworks"].append("Vue.js")
            if "angular" in html_lower:
                tech["frameworks"].append("Angular")
            if "jquery" in html_lower:
                tech["frameworks"].append("jQuery")
            
            return tech
        except Exception as e:
            logger.error(f"Error identifying tech: {e}")
            return tech


class PortScanner:
    """Port scanning and OS detection"""
    
    def __init__(self):
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5984: "CouchDB", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
            27017: "MongoDB", 50070: "Hadoop"
        }
    
    async def scan_ports(self, host: str, ports: List[int] = None) -> List[Dict[str, Any]]:
        """Scan ports on host"""
        if ports is None:
            ports = list(self.common_ports.keys())
        
        open_ports = []
        
        try:
            # Use nmap if available
            import nmap
            nm = nmap.PortScanner()
            port_str = ",".join(map(str, ports[:100]))  # Limit to 100 ports
            nm.scan(host, arguments=f"-p {port_str} -sV --script vuln")
            
            for host_addr in nm.all_hosts():
                for proto in nm[host_addr].all_protocols():
                    ports_dict = nm[host_addr][proto]
                    for port in ports_dict.keys():
                        state = ports_dict[port]['state']
                        if state == 'open':
                            service = self.common_ports.get(port, "Unknown")
                            open_ports.append({
                                "port": port,
                                "state": state,
                                "service": service,
                                "version": ports_dict[port].get('version', 'Unknown')
                            })
        except ImportError:
            logger.warning("nmap not installed, using basic TCP connect scan")
            open_ports = await self._basic_port_scan(host, ports)
        except Exception as e:
            logger.error(f"Port scan error: {e}")
        
        return sorted(open_ports, key=lambda x: x['port'])
    
    async def _basic_port_scan(self, host: str, ports: List[int]) -> List[Dict[str, Any]]:
        """Basic TCP connect scan fallback"""
        import socket
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    service = self.common_ports.get(port, "Unknown")
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "service": service,
                        "version": "Unknown"
                    })
                
                sock.close()
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")
        
        return open_ports


class VulnerabilitySearcher:
    """Search for vulnerabilities from multiple sources"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }
    
    async def search_cve(self, cve_id: str) -> Dict[str, Any]:
        """Search CVE from NIST"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/1.0/{cve_id}"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            return {
                "source": "NIST",
                "cve_id": cve_id,
                "data": data,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            }
        except Exception as e:
            logger.error(f"Error searching CVE: {e}")
            return {"error": str(e)}
    
    async def search_exploitdb(self, query: str) -> List[Dict[str, Any]]:
        """Search ExploitDB"""
        try:
            url = "https://www.exploit-db.com/search"
            params = {"q": query}
            response = requests.get(url, params=params, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            exploits = []
            
            # Parse ExploitDB results
            for row in soup.find_all('tr')[1:]:
                cols = row.find_all('td')
                if len(cols) >= 3:
                    exploit_id = cols[0].text.strip()
                    title = cols[1].text.strip()
                    date = cols[3].text.strip()
                    
                    exploits.append({
                        "id": exploit_id,
                        "title": title,
                        "date": date,
                        "url": f"https://www.exploit-db.com/exploits/{exploit_id}"
                    })
            
            return exploits
        except Exception as e:
            logger.error(f"Error searching ExploitDB: {e}")
            return []
    
    async def check_poc_available(self, vulnerability: str) -> Dict[str, Any]:
        """Check if POC is available"""
        try:
            # Search GitHub for POCs
            url = f"https://api.github.com/search/repositories?q={vulnerability}+poc&sort=stars&order=desc"
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            repos = response.json().get('items', [])
            
            pocs = []
            for repo in repos[:5]:
                pocs.append({
                    "name": repo['name'],
                    "url": repo['html_url'],
                    "stars": repo['stargazers_count'],
                    "description": repo['description']
                })
            
            return {
                "vulnerability": vulnerability,
                "poc_available": len(pocs) > 0,
                "pocs": pocs
            }
        except Exception as e:
            logger.error(f"Error checking POC: {e}")
            return {"error": str(e)}