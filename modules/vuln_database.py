"""
Vulnerability database module
"""
import requests
import json
import logging
from typing import List, Dict, Any
from modules.utils import VulnerabilitySearcher

logger = logging.getLogger(__name__)


class VulnerabilityDatabase:
    """Query vulnerability databases"""
    
    def __init__(self):
        self.searcher = VulnerabilitySearcher()
        self.cache = {}
    
    async def search_vulnerability(self, query: str) -> Dict[str, Any]:
        """Search vulnerability across multiple sources"""
        results = {
            "query": query,
            "sources": {
                "exploitdb": [],
                "github_poc": [],
                "nist": {},
                "mitre": {}
            }
        }
        
        # Search ExploitDB
        logger.info(f"Searching ExploitDB for {query}...")
        results["sources"]["exploitdb"] = await self.searcher.search_exploitdb(query)
        
        # Check for POCs
        logger.info(f"Checking for POCs for {query}...")
        poc_results = await self.searcher.check_poc_available(query)
        results["sources"]["github_poc"] = poc_results.get("pocs", [])
        
        return results
    
    async def search_cve(self, cve_id: str) -> Dict[str, Any]:
        """Search specific CVE"""
        return await self.searcher.search_cve(cve_id)
    
    def get_owasp_top10(self) -> List[Dict[str, str]]:
        """Get OWASP Top 10 2021"""
        return [
            {
                "rank": "A01:2021",
                "title": "Broken Access Control",
                "description": "Users can perform actions outside their permissions"
            },
            {
                "rank": "A02:2021",
                "title": "Cryptographic Failures",
                "description": "Sensitive data exposed due to weak cryptography"
            },
            {
                "rank": "A03:2021",
                "title": "Injection",
                "description": "Untrusted data sent as commands or queries"
            },
            {
                "rank": "A04:2021",
                "title": "Insecure Design",
                "description": "Missing or ineffective control design"
            },
            {
                "rank": "A05:2021",
                "title": "Security Misconfiguration",
                "description": "Insecure default configurations or incomplete setup"
            },
            {
                "rank": "A06:2021",
                "title": "Vulnerable and Outdated Components",
                "description": "Using libraries with known vulnerabilities"
            },
            {
                "rank": "A07:2021",
                "title": "Authentication Failures",
                "description": "Weak or ineffective authentication"
            },
            {
                "rank": "A08:2021",
                "title": "Data Integrity Failures",
                "description": "Insecure data integrity checks"
            },
            {
                "rank": "A09:2021",
                "title": "Logging and Monitoring Failures",
                "description": "Insufficient logging and monitoring"
            },
            {
                "rank": "A10:2021",
                "title": "SSRF",
                "description": "Server-Side Request Forgery"
            }
        ]
    
    def get_nist_guidelines(self) -> List[Dict[str, str]]:
        """Get NIST SP 800-53 security categories"""
        return [
            {
                "category": "AC",
                "title": "Access Control",
                "description": "Authentication and authorization"
            },
            {
                "category": "AU",
                "title": "Audit and Accountability",
                "description": "Logging and monitoring"
            },
            {
                "category": "AT",
                "title": "Awareness and Training",
                "description": "Security awareness programs"
            },
            {
                "category": "CA",
                "title": "Security Assessment and Authorization",
                "description": "Risk assessment and authorization"
            },
            {
                "category": "CM",
                "title": "Configuration Management",
                "description": "Configuration control"
            },
            {
                "category": "IA",
                "title": "Identification and Authentication",
                "description": "User and device identification"
            },
            {
                "category": "SC",
                "title": "System and Communications Protection",
                "description": "Data protection and encryption"
            },
            {
                "category": "SI",
                "title": "System and Information Integrity",
                "description": "Flaw remediation and malware protection"
            }
        ]