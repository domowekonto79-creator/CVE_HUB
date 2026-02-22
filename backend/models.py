from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class CVERecord(BaseModel):
    id: str
    published_at: Optional[datetime]
    last_modified: Optional[datetime]
    description: Optional[str]
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    cvss_vector: Optional[str]
    cwe_id: Optional[str]
    cpe_list: Optional[List[Dict[str, Any]]]
    references: Optional[List[Dict[str, Any]]]
    
    in_kev: bool = False
    kev_date_added: Optional[str]
    kev_due_date: Optional[str]
    kev_required_action: Optional[str]
    kev_ransomware: Optional[str]
    kev_description: Optional[str]
    
    osv_data: Optional[Dict[str, Any]]
    affected_packages: Optional[List[Dict[str, Any]]]
    
    ghsa_id: Optional[str]
    github_advisory: Optional[Dict[str, Any]]
    patch_versions: Optional[List[Dict[str, Any]]]
    
    otx_pulse_count: Optional[int]
    otx_campaigns: Optional[List[str]]
    otx_industries: Optional[List[str]]
    otx_malware_families: Optional[List[str]]
    
    partial_enrichment: bool = False
    enriched_at: Optional[datetime]
