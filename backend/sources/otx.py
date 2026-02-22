import httpx
import logging
import asyncio

logger = logging.getLogger(__name__)

class OTXClient:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1/indicators/cve"
        self.headers = {"X-OTX-API-KEY": api_key} if api_key else {}

    async def get_otx_data(self, cve_id):
        if not self.api_key:
            return None
            
        async with httpx.AsyncClient() as client:
            for attempt in range(3):
                try:
                    logger.info(f"OTX Query for {cve_id} (Attempt {attempt+1})")
                    
                    # Fetch general info
                    gen_res = await client.get(f"{self.base_url}/{cve_id}/general", headers=self.headers, timeout=10.0)
                    if gen_res.status_code == 429:
                        await asyncio.sleep(60)
                        continue
                    if gen_res.status_code == 404:
                        return {"otx_pulse_count": 0, "otx_campaigns": [], "otx_industries": [], "otx_malware_families": []}
                    gen_res.raise_for_status()
                    gen_data = gen_res.json()
                    
                    pulse_info = gen_data.get("pulse_info", {})
                    otx_pulse_count = pulse_info.get("count", 0)
                    
                    campaigns = []
                    industries = set()
                    for pulse in pulse_info.get("pulses", []):
                        campaigns.append(pulse.get("name"))
                        for ind in pulse.get("industries", []):
                            industries.add(ind)
                            
                    # Fetch malware families
                    mal_res = await client.get(f"{self.base_url}/{cve_id}/malware_families", headers=self.headers, timeout=10.0)
                    mal_data = mal_res.json() if mal_res.status_code == 200 else {"data": []}
                    malware_families = [m.get("display_name") for m in mal_data.get("data", [])]
                    
                    return {
                        "otx_pulse_count": otx_pulse_count,
                        "otx_campaigns": campaigns,
                        "otx_industries": list(industries),
                        "otx_malware_families": malware_families
                    }
                    
                except Exception as e:
                    logger.error(f"OTX Error for {cve_id}: {e}")
                    await asyncio.sleep(2 ** attempt)
                    
        return None
