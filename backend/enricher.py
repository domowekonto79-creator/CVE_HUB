import asyncio
import logging
from datetime import datetime
from sources.nvd import NVDClient
from sources.kev import KEVClient
from sources.osv import OSVClient
from sources.github_adv import GitHubAdvisoryClient
from sources.otx import OTXClient
from database import Database
from models import CVERecord
import os

logger = logging.getLogger(__name__)

class EnricherPipeline:
    def __init__(self):
        self.nvd = NVDClient(api_key=os.getenv("NVD_API_KEY"))
        self.kev = KEVClient()
        self.osv = OSVClient()
        self.github = GitHubAdvisoryClient(token=os.getenv("GITHUB_TOKEN"))
        self.otx = OTXClient(api_key=os.getenv("OTX_API_KEY"))
        self.db = Database()

    async def enrich_cve(self, cve_data):
        cve_id = cve_data["id"]
        
        # Add KEV data
        kev_info = self.kev.get_cve_info(cve_id)
        cve_data.update(kev_info)
        
        # Parallel enrichment
        results = await asyncio.gather(
            self.osv.get_affected_packages(cve_id),
            self.github.get_advisory(cve_id),
            self.otx.get_otx_data(cve_id),
            return_exceptions=True
        )
        
        partial = False
        
        # OSV
        if isinstance(results[0], Exception):
            logger.error(f"OSV failed for {cve_id}: {results[0]}")
            partial = True
        elif results[0]:
            osv_id, affected_packages = results[0]
            cve_data["osv_data"] = {"id": osv_id} if osv_id else None
            cve_data["affected_packages"] = affected_packages
            
        # GitHub
        if isinstance(results[1], Exception):
            logger.error(f"GitHub failed for {cve_id}: {results[1]}")
            partial = True
        elif results[1]:
            gh_data = results[1]
            cve_data["ghsa_id"] = gh_data.get("ghsa_id")
            cve_data["github_advisory"] = gh_data
            cve_data["patch_versions"] = gh_data.get("patch_versions")
            
        # OTX
        if isinstance(results[2], Exception):
            logger.error(f"OTX failed for {cve_id}: {results[2]}")
            partial = True
        elif results[2]:
            otx_data = results[2]
            cve_data.update(otx_data)
            
        cve_data["partial_enrichment"] = partial
        cve_data["enriched_at"] = datetime.utcnow()
        
        return CVERecord(**cve_data)

    async def run_pipeline(self):
        logger.info("Starting enrichment pipeline...")
        await self.kev.load_catalog()
        
        cves = await self.nvd.fetch_recent_cves(days=7)
        logger.info(f"Fetched {len(cves)} CVEs from NVD.")
        
        batch_size = 10
        for i in range(0, len(cves), batch_size):
            batch = cves[i:i+batch_size]
            tasks = [self.enrich_cve(cve) for cve in batch]
            enriched_batch = await asyncio.gather(*tasks)
            
            # Upsert to DB
            self.db.upsert_cves(enriched_batch)
            
        logger.info("Pipeline run completed.")
