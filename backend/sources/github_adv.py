import httpx
import logging
import asyncio

logger = logging.getLogger(__name__)

class GitHubAdvisoryClient:
    def __init__(self, token):
        self.token = token
        self.url = "https://api.github.com/advisories"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    async def get_advisory(self, cve_id):
        if not self.token:
            return None
            
        async with httpx.AsyncClient() as client:
            for attempt in range(3):
                try:
                    logger.info(f"GitHub Advisory Query for {cve_id} (Attempt {attempt+1})")
                    response = await client.get(f"{self.url}?cve_id={cve_id}", headers=self.headers, timeout=10.0)
                    
                    if response.status_code == 429:
                        await asyncio.sleep(60)
                        continue
                        
                    response.raise_for_status()
                    data = response.json()
                    
                    if not data:
                        return None
                        
                    adv = data[0]
                    
                    patch_versions = []
                    for vuln in adv.get("vulnerabilities", []):
                        if vuln.get("patched_versions"):
                            patch_versions.append({
                                "package": vuln.get("package", {}).get("name"),
                                "patched_versions": vuln.get("patched_versions")
                            })
                            
                    return {
                        "ghsa_id": adv.get("ghsa_id"),
                        "github_severity": adv.get("severity"),
                        "github_summary": adv.get("summary"),
                        "patch_versions": patch_versions,
                        "references": adv.get("references", [])
                    }
                    
                except Exception as e:
                    logger.error(f"GitHub Advisory Error for {cve_id}: {e}")
                    await asyncio.sleep(2 ** attempt)
                    
        return None
