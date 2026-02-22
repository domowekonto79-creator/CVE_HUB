import httpx
import logging
import asyncio

logger = logging.getLogger(__name__)

class OSVClient:
    def __init__(self):
        self.url = "https://api.osv.dev/v1/query"

    async def get_affected_packages(self, cve_id):
        async with httpx.AsyncClient() as client:
            for attempt in range(3):
                try:
                    logger.info(f"OSV Query for {cve_id} (Attempt {attempt+1})")
                    response = await client.post(self.url, json={"id": cve_id}, timeout=10.0)
                    
                    if response.status_code == 429:
                        await asyncio.sleep(60)
                        continue
                        
                    response.raise_for_status()
                    data = response.json()
                    
                    vulns = data.get("vulns", [])
                    if not vulns:
                        return None, []
                        
                    osv_id = vulns[0].get("id")
                    affected_packages = []
                    
                    for vuln in vulns:
                        for affected in vuln.get("affected", []):
                            pkg = affected.get("package", {})
                            ranges = affected.get("ranges", [])
                            
                            vulnerable_range = []
                            fixed_version = None
                            
                            for r in ranges:
                                for event in r.get("events", []):
                                    if "introduced" in event:
                                        vulnerable_range.append(f">={event['introduced']}")
                                    if "fixed" in event:
                                        fixed_version = event['fixed']
                                        vulnerable_range.append(f"<{event['fixed']}")
                                        
                            affected_packages.append({
                                "package": pkg.get("name"),
                                "ecosystem": pkg.get("ecosystem"),
                                "vulnerable_range": ", ".join(vulnerable_range),
                                "fixed_version": fixed_version,
                                "versions": affected.get("versions", [])
                            })
                            
                    return osv_id, affected_packages
                    
                except Exception as e:
                    logger.error(f"OSV Error for {cve_id}: {e}")
                    await asyncio.sleep(2 ** attempt)
                    
        return None, []
