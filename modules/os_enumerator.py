"""
OS enumeration module
"""
import asyncio
import json
from typing import List, Dict, Any
import logging
from modules.utils import PortScanner, VulnerabilitySearcher

logger = logging.getLogger(__name__)


class OSEnumerator:
    """OS and system enumeration"""
    
    def __init__(self):
        self.port_scanner = PortScanner()
        self.vuln_searcher = VulnerabilitySearcher()
        self.results = {}
    
    async def enumerate_host(self, host: str, options: Dict[str, bool] = None) -> Dict[str, Any]:
        """
        Enumerate host with options
        
        Options:
        - scan_ports: Scan common ports
        - full_scan: Scan all ports
        - identify_os: Try to identify OS
        - search_vulns: Search for vulnerabilities
        """
        if options is None:
            options = {
                "scan_ports": True,
                "identify_os": True,
                "search_vulns": True
            }
        
        self.results = {
            "host": host,
            "timestamp": str(asyncio.get_event_loop().time()),
            "open_ports": [],
            "os_info": {},
            "services": {},
            "vulnerabilities": [],
            "recommendations": []
        }
        
        # Scan ports
        if options.get("scan_ports"):
            logger.info(f"Scanning ports on {host}...")
            ports = None
            if not options.get("full_scan"):
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 9200, 27017]
            
            self.results["open_ports"] = await self.port_scanner.scan_ports(host, ports)
            logger.info(f"Found {len(self.results['open_ports'])} open ports")
        
        # Identify services and potential vulnerabilities
        for port_info in self.results["open_ports"]:
            port = port_info["port"]
            service = port_info["service"]
            
            # Add service details
            self.results["services"][port] = {
                "name": service,
                "vulnerabilities": await self._get_service_vulns(service)
            }
            
            # Add recommendations
            self.results["recommendations"].extend(
                self._get_recommendations(service, port)
            )
        
        return self.results
    
    async def _get_service_vulns(self, service: str) -> List[str]:
        """Get known vulnerabilities for service"""
        common_vulns = {
            "FTP": ["Unencrypted credentials", "Directory traversal", "Buffer overflow"],
            "SSH": ["Weak keys", "Default credentials", "Version disclosure"],
            "HTTP": ["XSS", "CSRF", "SQL Injection", "LFI", "RFI"],
            "HTTPS": ["SSL/TLS misconfiguration", "Certificate issues"],
            "MySQL": ["SQL Injection", "Default credentials", "Privilege escalation"],
            "PostgreSQL": ["SQL Injection", "Weak authentication"],
            "SMB": ["Null session", "Credential brute force", "EternalBlue"],
            "RDP": ["Credential brute force", "BlueKeep", "Weak encryption"],
            "SNMP": ["Community string disclosure", "Information disclosure"],
            "Redis": ["No authentication", "Command injection", "RCE"],
            "MongoDB": ["No authentication", "Data exfiltration"],
            "Elasticsearch": ["No authentication", "Data exfiltration"],
            "Jenkins": ["Default credentials", "JNDI injection", "Script console"],
        }
        
        return common_vulns.get(service, ["Unknown vulnerabilities"])
    
    def _get_recommendations(self, service: str, port: int) -> List[str]:
        """Get recommendations for a service"""
        recommendations = []
        
        if service in ["FTP", "Telnet"]:
            recommendations.append(
                f"Port {port} ({service}): Use encrypted alternatives (SFTP, SSH)"
            )
        elif service == "HTTP":
            recommendations.append(
                f"Port {port} ({service}): Upgrade to HTTPS and set HSTS headers"
            )
        elif service in ["MySQL", "PostgreSQL", "MongoDB", "Redis"]:
            recommendations.append(
                f"Port {port} ({service}): Restrict network access, require authentication"
            )
        elif service == "SMB":
            recommendations.append(
                f"Port {port} ({service}): Disable if not needed, apply security patches"
            )
        
        return recommendations
    
    def get_results(self) -> Dict[str, Any]:
        """Get current results"""
        return self.results
    
    def export_results(self, format: str = "json") -> str:
        """Export results"""
        if format == "json":
            return json.dumps(self.results, indent=2)
        elif format == "csv":
            lines = ["Port,Service,Status,Vulnerabilities,Recommendation"]
            
            for port_info in self.results.get("open_ports", []):
                port = port_info["port"]
                service = port_info["service"]
                vulns = ";".join(self.results["services"].get(port, {}).get("vulnerabilities", []))
                
                lines.append(f"{port},{service},Open,{vulns},Check recommendations")
            
            return "\n".join(lines)
        
        return ""