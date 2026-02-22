import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.3";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const NVD_API_KEY = Deno.env.get("NVD_API_KEY");
const GITHUB_TOKEN = Deno.env.get("GITHUB_TOKEN");
const OTX_API_KEY = Deno.env.get("OTX_API_KEY");

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// --- Helpers ---
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

async function fetchWithRetry(url: string, options: RequestInit = {}, retries = 3): Promise<Response> {
  for (let i = 0; i < retries; i++) {
    const res = await fetch(url, options);
    if (res.status === 429) {
      console.warn(`Rate limit hit for ${url}, sleeping 60s`);
      await sleep(60000);
      continue;
    }
    if (!res.ok && res.status !== 404) {
      console.error(`Error ${res.status} for ${url}`);
      await sleep(Math.pow(2, i) * 1000);
      continue;
    }
    return res;
  }
  throw new Error(`Failed to fetch ${url} after ${retries} retries`);
}

// --- Sources ---
async function loadKevCatalog() {
  console.log("Loading CISA KEV catalog...");
  const res = await fetchWithRetry("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
  const data = await res.json();
  const catalog: Record<string, any> = {};
  for (const vuln of data.vulnerabilities || []) {
    catalog[vuln.cveID] = {
      kev_date_added: vuln.dateAdded,
      kev_due_date: vuln.dueDate,
      kev_required_action: vuln.requiredAction,
      kev_ransomware: vuln.knownRansomwareCampaignUse,
      kev_description: vuln.shortDescription,
      in_kev: true
    };
  }
  return catalog;
}

async function fetchNvdCves(days = 7) {
  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - days * 24 * 60 * 60 * 1000);
  const startStr = startDate.toISOString().replace(/\.\d{3}Z$/, '.000Z');
  const endStr = endDate.toISOString().replace(/\.\d{3}Z$/, '.000Z');
  
  let startIndex = 0;
  const resultsPerPage = 100;
  const cves = [];
  const delay = NVD_API_KEY ? 600 : 6000;
  const headers = NVD_API_KEY ? { "apiKey": NVD_API_KEY } : {};

  while (true) {
    console.log(`Fetching NVD CVEs, startIndex: ${startIndex}`);
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startStr}&pubEndDate=${endStr}&resultsPerPage=${resultsPerPage}&startIndex=${startIndex}`;
    
    const res = await fetchWithRetry(url, { headers });
    const data = await res.json();
    
    const vulnerabilities = data.vulnerabilities || [];
    if (vulnerabilities.length === 0) break;
    
    for (const item of vulnerabilities) {
      const cve = item.cve;
      const metrics = cve.metrics || {};
      const cvssData = (metrics.cvssMetricV31 && metrics.cvssMetricV31[0]?.cvssData) || {};
      const description = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";
      const cwe_id = cve.weaknesses?.[0]?.description?.[0]?.value || null;
      
      cves.push({
        id: cve.id,
        published_at: cve.published,
        last_modified: cve.lastModified,
        description,
        cvss_score: cvssData.baseScore || null,
        cvss_severity: cvssData.baseSeverity || null,
        cvss_vector: cvssData.vectorString || null,
        cwe_id,
        cpe_list: cve.configurations || [],
        references: cve.references || []
      });
    }
    
    startIndex += resultsPerPage;
    if (startIndex >= (data.totalResults || 0)) break;
    await sleep(delay);
  }
  return cves;
}

async function fetchOsv(cveId: string) {
  try {
    const res = await fetchWithRetry(`https://api.osv.dev/v1/vulns/${cveId}`);
    if (res.status === 404) return { osv_data: null, affected_packages: [] };
    
    const data = await res.json();
    const osv_id = data.id;
    const affected_packages = [];
    
    for (const affected of data.affected || []) {
      const pkg = affected.package || {};
      const ranges = affected.ranges || [];
      const vulnerable_range = [];
      let fixed_version = null;
      
      for (const r of ranges) {
        for (const event of r.events || []) {
          if (event.introduced) vulnerable_range.push(`>=${event.introduced}`);
          if (event.fixed) {
            fixed_version = event.fixed;
            vulnerable_range.push(`<${event.fixed}`);
          }
        }
      }
      
      affected_packages.push({
        package: pkg.name,
        ecosystem: pkg.ecosystem,
        vulnerable_range: vulnerable_range.join(", "),
        fixed_version,
        versions: affected.versions || []
      });
    }
    return { osv_data: { id: osv_id }, affected_packages };
  } catch (e) {
    console.error(`OSV error for ${cveId}:`, e);
    throw e;
  }
}

async function fetchGitHubAdvisory(cveId: string) {
  if (!GITHUB_TOKEN) return { ghsa_id: null, github_advisory: null, patch_versions: [] };
  try {
    const res = await fetchWithRetry(`https://api.github.com/advisories?cve_id=${cveId}`, {
      headers: {
        "Authorization": `Bearer ${GITHUB_TOKEN}`,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
      }
    });
    const data = await res.json();
    if (!data || data.length === 0) return { ghsa_id: null, github_advisory: null, patch_versions: [] };
    
    const adv = data[0];
    const patch_versions = [];
    for (const vuln of adv.vulnerabilities || []) {
      if (vuln.patched_versions) {
        patch_versions.push({
          package: vuln.package?.name,
          patched_versions: vuln.patched_versions
        });
      }
    }
    
    return {
      ghsa_id: adv.ghsa_id,
      github_advisory: {
        severity: adv.severity,
        summary: adv.summary,
        references: adv.references
      },
      patch_versions
    };
  } catch (e) {
    console.error(`GitHub error for ${cveId}:`, e);
    throw e;
  }
}

async function fetchOtx(cveId: string) {
  if (!OTX_API_KEY) return { otx_pulse_count: 0, otx_campaigns: [], otx_industries: [], otx_malware_families: [] };
  try {
    const headers = { "X-OTX-API-KEY": OTX_API_KEY };
    const genRes = await fetchWithRetry(`https://otx.alienvault.com/api/v1/indicators/cve/${cveId}/general`, { headers });
    if (genRes.status === 404) return { otx_pulse_count: 0, otx_campaigns: [], otx_industries: [], otx_malware_families: [] };
    
    const genData = await genRes.json();
    const pulseInfo = genData.pulse_info || {};
    const otx_pulse_count = pulseInfo.count || 0;
    
    const campaigns = [];
    const industries = new Set<string>();
    for (const pulse of pulseInfo.pulses || []) {
      if (pulse.name) campaigns.push(pulse.name);
      for (const ind of pulse.industries || []) industries.add(ind);
    }
    
    const malRes = await fetchWithRetry(`https://otx.alienvault.com/api/v1/indicators/cve/${cveId}/malware_families`, { headers });
    const malData = malRes.ok ? await malRes.json() : { data: [] };
    const otx_malware_families = (malData.data || []).map((m: any) => m.display_name).filter(Boolean);
    
    return {
      otx_pulse_count,
      otx_campaigns: campaigns,
      otx_industries: Array.from(industries),
      otx_malware_families
    };
  } catch (e) {
    console.error(`OTX error for ${cveId}:`, e);
    throw e;
  }
}

// --- Main Handler ---
serve(async (req) => {
  try {
    console.log("Starting enrichment pipeline...");
    const kevCatalog = await loadKevCatalog();
    const cves = await fetchNvdCves(7); // Fetch last 7 days
    console.log(`Fetched ${cves.length} CVEs from NVD.`);
    
    const batchSize = 5; // Smaller batch size for Edge Function limits
    for (let i = 0; i < cves.length; i += batchSize) {
      const batch = cves.slice(i, i + batchSize);
      
      const enrichedBatch = await Promise.all(batch.map(async (cve) => {
        let partial = false;
        const kevInfo = kevCatalog[cve.id] || { in_kev: false };
        
        const [osvRes, ghRes, otxRes] = await Promise.allSettled([
          fetchOsv(cve.id),
          fetchGitHubAdvisory(cve.id),
          fetchOtx(cve.id)
        ]);
        
        const osvData = osvRes.status === "fulfilled" ? osvRes.value : (partial = true, { osv_data: null, affected_packages: [] });
        const ghData = ghRes.status === "fulfilled" ? ghRes.value : (partial = true, { ghsa_id: null, github_advisory: null, patch_versions: [] });
        const otxData = otxRes.status === "fulfilled" ? otxRes.value : (partial = true, { otx_pulse_count: 0, otx_campaigns: [], otx_industries: [], otx_malware_families: [] });
        
        return {
          ...cve,
          ...kevInfo,
          ...osvData,
          ...ghData,
          ...otxData,
          partial_enrichment: partial,
          enriched_at: new Date().toISOString()
        };
      }));
      
      // Upsert to Supabase
      const { error } = await supabase.from("cve_records").upsert(enrichedBatch);
      if (error) {
        console.error("Supabase upsert error:", error);
        if (error.code === "PGRST205") {
          console.error("CRITICAL ERROR: The table 'cve_records' does not exist in your Supabase database. You MUST run the schema.sql script in your Supabase SQL Editor.");
        }
      }
    }
    
    return new Response(JSON.stringify({ message: "Pipeline run completed successfully" }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  } catch (error: any) {
    console.error("Pipeline failed:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  }
});
