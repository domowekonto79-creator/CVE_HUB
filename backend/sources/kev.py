import httpx
import logging
import asyncio

logger = logging.getLogger(__name__)

class KEVClient:
    def __init__(self):
        self.url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.catalog = {}

    async def load_catalog(self):
        logger.info("Loading CISA KEV catalog...")
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(self.url, timeout=30.0)
                response.raise_for_status()
                data = response.json()
                
                for vuln in data.get("vulnerabilities", []):
                    self.catalog[vuln["cveID"]] = {
                        "kev_date_added": vuln.get("dateAdded"),
                        "kev_due_date": vuln.get("dueDate"),
                        "kev_required_action": vuln.get("requiredAction"),
                        "kev_ransomware": vuln.get("knownRansomwareCampaignUse"),
                        "kev_description": vuln.get("shortDescription"),
                        "in_kev": True
                    }
                logger.info(f"Loaded {len(self.catalog)} KEV records.")
            except Exception as e:
                logger.error(f"Failed to load KEV catalog: {e}")

    def get_cve_info(self, cve_id):
        return self.catalog.get(cve_id, {"in_kev": False})
