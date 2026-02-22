import express from "express";
import { createServer as createViteServer } from "vite";
import { createClient } from "@supabase/supabase-js";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const supabaseUrl = process.env.SUPABASE_URL || "";
const supabaseKey = process.env.SUPABASE_SERVICE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "";
const supabase = supabaseUrl && supabaseKey ? createClient(supabaseUrl, supabaseKey) : null;

// Mock data for preview if Supabase is not configured
const mockCves = [
  {
    id: "CVE-2023-38545",
    published_at: "2023-10-18T00:00:00Z",
    description: "This vulnerability affects curl and libcurl, allowing a heap-based buffer overflow in the SOCKS5 proxy handshake.",
    cvss_score: 9.8,
    cvss_severity: "CRITICAL",
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cwe_id: "CWE-122",
    cpe_list: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*" }] }] }],
    in_kev: true,
    kev_date_added: "2023-10-25",
    kev_due_date: "2023-11-15",
    kev_required_action: "Apply updates per vendor instructions.",
    kev_ransomware: "Unknown",
    affected_packages: [
      { package: "curl", ecosystem: "Alpine", vulnerable_range: "<8.4.0-r0", fixed_version: "8.4.0-r0" }
    ],
    otx_pulse_count: 12,
    otx_campaigns: ["Operation DreamJob", "Lazarus Group"],
    otx_malware_families: ["Lazarus", "Andariel"],
    references: [{ url: "https://curl.se/docs/CVE-2023-38545.html", tags: ["Patch", "Vendor Advisory"] }]
  },
  {
    id: "CVE-2024-3094",
    published_at: "2024-03-29T00:00:00Z",
    description: "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. The code modifies liblzma to intercept and modify data.",
    cvss_score: 10.0,
    cvss_severity: "CRITICAL",
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cwe_id: "CWE-506",
    cpe_list: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*" }] }] }],
    in_kev: true,
    kev_date_added: "2024-04-01",
    kev_due_date: "2024-04-15",
    kev_required_action: "Downgrade xz to 5.4.x or update to a patched version.",
    kev_ransomware: "Unknown",
    affected_packages: [
      { package: "xz", ecosystem: "Debian", vulnerable_range: ">=5.6.0, <=5.6.1", fixed_version: "5.6.1+really5.4.5-1" }
    ],
    otx_pulse_count: 45,
    otx_campaigns: ["XZ Backdoor"],
    otx_malware_families: [],
    references: [{ url: "https://openwall.com/lists/oss-security/2024/03/29/4", tags: ["Exploit", "Mailing List"] }]
  },
  {
    id: "CVE-2021-44228",
    published_at: "2021-12-10T00:00:00Z",
    description: "Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
    cvss_score: 10.0,
    cvss_severity: "CRITICAL",
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cwe_id: "CWE-502",
    cpe_list: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*" }] }] }],
    in_kev: true,
    kev_date_added: "2021-12-10",
    kev_due_date: "2021-12-24",
    kev_required_action: "Apply updates per vendor instructions.",
    kev_ransomware: "Known",
    affected_packages: [
      { package: "org.apache.logging.log4j:log4j-core", ecosystem: "Maven", vulnerable_range: ">=2.0-beta9, <=2.14.1", fixed_version: "2.15.0" }
    ],
    otx_pulse_count: 150,
    otx_campaigns: ["Log4Shell", "MuddyWater"],
    otx_malware_families: ["Mirai", "Kinsing", "Muhstik"],
    references: [{ url: "https://logging.apache.org/log4j/2.x/security.html", tags: ["Vendor Advisory"] }]
  }
];

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(express.json());

  // API Routes
  app.get("/api/cves", async (req, res) => {
    if (supabase) {
      try {
        const { data, error } = await supabase
          .from("cve_records")
          .select("*")
          .order("in_kev", { ascending: false })
          .order("cvss_score", { ascending: false })
          .limit(25);
        
        if (error) throw error;
        
        // If DB is empty, return mock data for preview
        if (!data || data.length === 0) {
          return res.json(mockCves);
        }
        
        return res.json(data);
      } catch (err) {
        console.error("Supabase error:", err);
        return res.json(mockCves); // Fallback to mock data
      }
    } else {
      // Fallback to mock data if Supabase is not configured
      return res.json(mockCves);
    }
  });

  app.get("/api/cves/:id", async (req, res) => {
    const { id } = req.params;
    
    if (supabase) {
      try {
        const { data, error } = await supabase
          .from("cve_records")
          .select("*")
          .eq("id", id)
          .single();
          
        if (error && error.code !== "PGRST116") throw error;
        
        if (data) return res.json(data);
      } catch (err) {
        console.error("Supabase error:", err);
      }
    }
    
    // Fallback to mock data
    const mockCve = mockCves.find(c => c.id === id);
    if (mockCve) {
      return res.json(mockCve);
    }
    
    return res.status(404).json({ error: "CVE not found" });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
