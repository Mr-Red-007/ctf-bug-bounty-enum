"""
Web scanning module for enumeration
"""
import asyncio
import json
from typing import List, Dict, Any
import logging
from modules.utils import (
    SubdomainEnumerator, DirectoryBuster, TechIdentifier,
    VulnerabilitySearcher
)

logger = logging.getLogger(__name__)


class WebScanner:
    """Main web scanner class"""
    
    def __init__(self):
        self.subdomain_enum = SubdomainEnumerator()
        self.dir_buster = DirectoryBuster()
        self.tech_identifier = TechIdentifier()
        self.vuln_searcher = VulnerabilitySearcher()
        self.results = {}
    
    async def scan_domain(self, domain: str, options: Dict[str, bool] = None) -> Dict[str, Any]:
        """
        Scan a domain with configurable options
        
        Options:
        - enum_subdomains: Enumerate subdomains
        - bust_directories: Bust directories
        - bust_files: Bust files
        - identify_tech: Identify technologies
        - search_vulns: Search for vulnerabilities
        """
        if options is None:
            options = {
                "enum_subdomains": True,
                "bust_directories": True,
                "bust_files": True,
                "identify_tech": True,
                "search_vulns": False
            }
        
        self.results = {
            "domain": domain,
            "timestamp": str(asyncio.get_event_loop().time()),
            "subdomains": [],
            "directories": [],
            "files": [],
            "technologies": {},
            "vulnerabilities": []
        }
        
        # Enumerate subdomains
        if options.get("enum_subdomains"):
            logger.info(f"Enumerating subdomains for {domain}...")
            self.results["subdomains"] = await self.subdomain_enum.get_all_subdomains(domain)
            logger.info(f"Found {len(self.results['subdomains'])} subdomains")
        
        # Bust directories
        if options.get("bust_directories"):
            logger.info(f"Busting directories for {domain}...")
            base_url = f"http://{domain}"
            directories = await self.dir_buster.bust_directories(base_url)
            self.results["directories"] = directories
            
            # Also bust subdomains if enabled
            if options.get("enum_subdomains") and self.results["subdomains"]:
                for subdomain in self.results["subdomains"][:5]:  # Limit to first 5
                    sub_url = f"http://{subdomain}"
                    sub_dirs = await self.dir_buster.bust_directories(sub_url)
                    if sub_dirs:
                        if "subdomain_directories" not in self.results:
                            self.results["subdomain_directories"] = {}
                        self.results["subdomain_directories"][subdomain] = sub_dirs
        
        # Bust files
        if options.get("bust_files"):
            logger.info(f"Busting files for {domain}...")
            base_url = f"http://{domain}"
            files = await self.dir_buster.bust_files(base_url)
            self.results["files"] = files
        
        # Identify technologies
        if options.get("identify_tech"):
            logger.info(f"Identifying technologies for {domain}...")
            tech = await self.tech_identifier.identify_tech(f"http://{domain}")
            self.results["technologies"] = tech
        
        # Search vulnerabilities
        if options.get("search_vulns") and self.results.get("technologies"):
            logger.info("Searching for vulnerabilities...")
            for tech in self.results["technologies"].get("frameworks", [])[:3]:
                vulns = await self.vuln_searcher.search_exploitdb(tech)
                self.results["vulnerabilities"].extend(vulns)
        
        return self.results
    
    async def scan_subdomains(self, domain: str, options: Dict[str, bool] = None) -> Dict[str, Any]:
        """Scan all subdomains"""
        if options is None:
            options = {}
        
        subdomains = await self.subdomain_enum.get_all_subdomains(domain)
        results = {}
        
        for subdomain in subdomains:
            logger.info(f"Scanning {subdomain}...")
            results[subdomain] = await self.scan_domain(
                subdomain,
                {**options, "enum_subdomains": False}
            )
        
        return results
    
    def get_results(self) -> Dict[str, Any]:
        """Get current results"""
        return self.results
    
    def export_results(self, format: str = "json") -> str:
        """Export results"""
        if format == "json":
            return json.dumps(self.results, indent=2)
        elif format == "csv":
            # Simple CSV export
            lines = []
            lines.append("Type,Value,Status/Info")
            
            for subdomain in self.results.get("subdomains", []):
                lines.append(f"Subdomain,{subdomain},Found")
            
            for directory in self.results.get("directories", []):
                lines.append(f"Directory,{directory['path']},{directory['status']}")
            
            return "\n".join(lines)
        
        return ""