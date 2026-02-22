import os
import logging
from supabase import create_client, Client

logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_SERVICE_KEY")
        if not url or not key:
            logger.warning("Supabase credentials not found. DB operations will fail.")
            self.client = None
        else:
            self.client: Client = create_client(url, key)

    def upsert_cves(self, cves: list):
        if not self.client:
            return
        try:
            # Supabase upsert
            data = [cve.dict(exclude_none=True) for cve in cves]
            # Convert datetime to ISO format strings
            for row in data:
                for k, v in row.items():
                    if hasattr(v, 'isoformat'):
                        row[k] = v.isoformat()
                        
            result = self.client.table("cve_records").upsert(data).execute()
            logger.info(f"Upserted {len(data)} records to Supabase.")
            return result
        except Exception as e:
            logger.error(f"Database upsert error: {e}")
