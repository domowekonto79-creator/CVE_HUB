import httpx
import asyncio
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class NVDClient:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {"apiKey": api_key} if api_key else {}
        self.delay = 0.6 if api_key else 6.0

    async def fetch_recent_cves(self, days=7):
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "resultsPerPage": 100,
            "startIndex": 0
        }
        
        cves = []
        async with httpx.AsyncClient() as client:
            while True:
                try:
                    logger.info(f"Fetching NVD CVEs, startIndex: {params['startIndex']}")
                    response = await client.get(self.base_url, params=params, headers=self.headers, timeout=30.0)
                    
                    if response.status_code == 429:
                        logger.warning("NVD Rate limit hit, sleeping 60s")
                        await asyncio.sleep(60)
                        continue
                        
                    response.raise_for_status()
                    data = response.json()
                    
                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        break
                        
                    for item in vulnerabilities:
                        cve = item.get("cve", {})
                        cves.append(self._parse_cve(cve))
                        
                    params["startIndex"] += params["resultsPerPage"]
                    total_results = data.get("totalResults", 0)
                    
                    if params["startIndex"] >= total_results:
                        break
                        
                    await asyncio.sleep(self.delay)
                    
                except Exception as e:
                    logger.error(f"Error fetching from NVD: {e}")
                    break
                    
        return cves

    def _parse_cve(self, cve):
        metrics = cve.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        
        description = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        cwe_id = None
        weaknesses = cve.get("weaknesses", [])
        if weaknesses:
            cwe_id = weaknesses[0].get("description", [{}])[0].get("value")
            
        return {
            "id": cve.get("id"),
            "published_at": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": description,
            "cvss_score": cvss_data.get("baseScore"),
            "cvss_severity": cvss_data.get("baseSeverity"),
            "cvss_vector": cvss_data.get("vectorString"),
            "cwe_id": cwe_id,
            "cpe_list": cve.get("configurations", []),
            "references": cve.get("references", [])
        }
