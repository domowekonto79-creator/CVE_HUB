import React, { useEffect, useState } from 'react';
import { ShieldAlert, ArrowLeft } from 'lucide-react';
import { createClient } from '@supabase/supabase-js';

// Initialize Supabase client
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

const supabase = supabaseUrl && supabaseAnonKey ? createClient(supabaseUrl, supabaseAnonKey) : null;

// --- Components ---

function SeverityBadge({ severity, score }: { severity: string | null, score?: number | null }) {
  if (!severity) return <span className="px-2 py-1 text-xs rounded-full bg-gray-800 text-gray-300">UNKNOWN</span>;

  const s = severity.toUpperCase();
  let color = 'bg-gray-800 text-gray-300';
  
  if (s === 'CRITICAL') color = 'bg-red-900/50 text-red-400 border border-red-800';
  else if (s === 'HIGH') color = 'bg-orange-900/50 text-orange-400 border border-orange-800';
  else if (s === 'MEDIUM') color = 'bg-yellow-900/50 text-yellow-400 border border-yellow-800';
  else if (s === 'LOW') color = 'bg-green-900/50 text-green-400 border border-green-800';

  return (
    <span className={`px-2 py-1 text-xs font-bold rounded-full ${color}`}>
      {s} {score ? `(${score})` : ''}
    </span>
  );
}

function KevBanner({ dateAdded, dueDate, action, ransomware }: any) {
  return (
    <div className="bg-red-950/40 border border-red-900 rounded-lg p-4 mb-6">
      <div className="flex items-center gap-3 mb-2">
        <ShieldAlert className="text-red-500 w-6 h-6" />
        <h3 className="text-red-500 font-bold text-lg">⚠️ AKTYWNIE EXPLOITOWANY W RZECZYWISTYCH ATAKACH</h3>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-red-200 mt-4">
        <div>
          <p><span className="font-semibold text-red-400">Dodano do KEV:</span> {dateAdded}</p>
          <p><span className="font-semibold text-red-400">Wymagana akcja do:</span> {dueDate}</p>
        </div>
        <div>
          <p><span className="font-semibold text-red-400">Akcja:</span> {action}</p>
          <p><span className="font-semibold text-red-400">Ransomware:</span> {ransomware || 'Nieznane'}</p>
        </div>
      </div>
    </div>
  );
}

function MitigationSection({ cve }: { cve: any }) {
  const priorities = [];

  if (cve.in_kev) {
    priorities.push({
      level: 1,
      text: `PILNE: ${cve.kev_required_action} — deadline ${cve.kev_due_date}`,
      color: 'text-red-400'
    });
  }

  if (cve.patch_versions && cve.patch_versions.length > 0) {
    cve.patch_versions.forEach((pv: any) => {
      priorities.push({
        level: 2,
        text: `Zaktualizuj ${pv.package} do wersji ${pv.patched_versions}`,
        color: 'text-orange-400'
      });
    });
  }

  if (cve.affected_packages && cve.affected_packages.length > 0) {
    cve.affected_packages.forEach((ap: any) => {
      if (ap.fixed_version) {
        priorities.push({
          level: 2,
          text: `Zaktualizuj ${ap.package} (${ap.ecosystem}) do ${ap.fixed_version}`,
          color: 'text-orange-400'
        });
      }
    });
  }

  if (priorities.length === 0) {
    priorities.push({
      level: 3,
      text: "Monitoruj producenta, zastosuj workaround z references",
      color: 'text-yellow-400'
    });
  }

  return (
    <div className="bg-gray-900 rounded-xl p-6 border border-gray-800">
      <h2 className="text-xl font-bold text-white mb-4">Jak się zabezpieczyć</h2>
      <ul className="space-y-3">
        {priorities.map((p, i) => (
          <li key={i} className={`flex items-start gap-2 ${p.color}`}>
            <span className="font-bold whitespace-nowrap">Priorytet {p.level}:</span>
            <span>{p.text}</span>
          </li>
        ))}
      </ul>
      
      {cve.references && cve.references.length > 0 && (
        <div className="mt-6">
          <h3 className="text-sm font-semibold text-gray-400 mb-2">Przydatne linki:</h3>
          <div className="flex flex-wrap gap-2">
            {cve.references.slice(0, 5).map((ref: any, i: number) => (
              <a 
                key={i} 
                href={ref.url} 
                target="_blank" 
                rel="noreferrer"
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-xs text-blue-400 rounded-md transition-colors"
              >
                {ref.tags ? ref.tags.join(', ') : 'Link'} ↗
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// --- Pages ---

function Dashboard({ onSelectCve }: { onSelectCve: (id: string) => void }) {
  const [cves, setCves] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    async function fetchCves() {
      if (!supabase) {
        setErrorMsg("Brak konfiguracji Supabase. Ustaw zmienne środowiskowe VITE_SUPABASE_URL i VITE_SUPABASE_ANON_KEY (lub NEXT_PUBLIC_...).");
        setLoading(false);
        return;
      }
      
      try {
        const { data, error } = await supabase
          .from("cve_records")
          .select("*")
          .order("in_kev", { ascending: false })
          .order("cvss_score", { ascending: false })
          .limit(25);
          
        if (error) throw error;
        setCves(data || []);
      } catch (err: any) {
        console.error("Error fetching CVEs:", err);
        setErrorMsg(`Błąd pobierania danych: ${err.message}`);
      } finally {
        setLoading(false);
      }
    }
    
    fetchCves();
  }, []);

  return (
    <div className="max-w-7xl mx-auto">
      <header className="mb-12">
        <h1 className="text-4xl font-bold text-white tracking-tight mb-2">CVE Enrichment Hub</h1>
        <p className="text-gray-500">Zintegrowane dane z NVD, CISA KEV, OSV, GitHub i AlienVault OTX.</p>
        <p className="text-blue-400 text-sm mt-2">Wersja podglądowa (Express + React SPA)</p>
      </header>

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-8 flex flex-wrap gap-4 items-center">
        <div className="flex-1 min-w-[200px]">
          <input type="text" placeholder="Szukaj CVE ID..." className="w-full bg-black border border-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500 text-white" />
        </div>
        <div className="flex items-center gap-2 bg-black border border-gray-700 rounded-lg px-4 py-2">
          <ShieldAlert className="w-4 h-4 text-red-500" />
          <span className="text-sm text-gray-300">Tylko KEV</span>
        </div>
        <select className="bg-black border border-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500 text-gray-300">
          <option>Wszystkie Severity</option>
          <option>CRITICAL</option>
          <option>HIGH</option>
          <option>MEDIUM</option>
          <option>LOW</option>
        </select>
      </div>

      {loading ? (
        <div className="text-center py-20 bg-gray-900 rounded-xl border border-gray-800">
          <p className="text-gray-500">Ładowanie danych...</p>
        </div>
      ) : errorMsg ? (
        <div className="text-center py-20 bg-red-950/40 rounded-xl border border-red-900">
          <p className="text-red-400 font-bold">{errorMsg}</p>
        </div>
      ) : cves.length > 0 ? (
        <div className="overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-left text-sm text-gray-400">
            <thead className="bg-gray-900 text-xs uppercase text-gray-500">
              <tr>
                <th className="px-6 py-4">CVE ID</th>
                <th className="px-6 py-4">Severity</th>
                <th className="px-6 py-4">Produkt</th>
                <th className="px-6 py-4">KEV</th>
                <th className="px-6 py-4">Opublikowano</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800 bg-black">
              {cves.map((cve) => {
                const product = cve.cpe_list?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria?.split(':')[4] || '-';
                return (
                  <tr key={cve.id} className="hover:bg-gray-900/50 transition-colors cursor-pointer" onClick={() => onSelectCve(cve.id)}>
                    <td className="px-6 py-4 font-medium text-blue-400">
                      {cve.id}
                    </td>
                    <td className="px-6 py-4">
                      <SeverityBadge severity={cve.cvss_severity} score={cve.cvss_score} />
                    </td>
                    <td className="px-6 py-4 truncate max-w-[200px]">{product}</td>
                    <td className="px-6 py-4">
                      {cve.in_kev ? <ShieldAlert className="text-red-500 w-5 h-5" /> : '-'}
                    </td>
                    <td className="px-6 py-4">{new Date(cve.published_at).toLocaleDateString()}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="text-center py-20 bg-gray-900 rounded-xl border border-gray-800">
          <p className="text-gray-500">Brak danych.</p>
        </div>
      )}
    </div>
  );
}

function CveDetail({ id, onBack }: { id: string, onBack: () => void }) {
  const [cve, setCve] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchCve() {
      if (!supabase) {
        setLoading(false);
        return;
      }
      
      try {
        const { data, error } = await supabase
          .from("cve_records")
          .select("*")
          .eq("id", id)
          .single();
          
        if (error) throw error;
        setCve(data);
      } catch (err) {
        console.error("Error fetching CVE details:", err);
      } finally {
        setLoading(false);
      }
    }
    
    fetchCve();
  }, [id]);

  if (loading) {
    return <div className="p-8 text-white">Ładowanie...</div>;
  }

  if (!cve || cve.error) {
    return (
      <div className="p-8 text-white">
        <button onClick={onBack} className="text-blue-400 mb-4">← Wróć</button>
        <p>CVE not found</p>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto">
      <button onClick={onBack} className="inline-flex items-center gap-2 text-blue-400 hover:text-blue-300 mb-8 transition-colors">
        <ArrowLeft className="w-4 h-4" /> Wróć do listy
      </button>

      <div className="mb-10">
        <div className="flex flex-wrap items-center gap-4 mb-4">
          <h1 className="text-4xl font-bold text-white tracking-tight">{cve.id}</h1>
          <SeverityBadge severity={cve.cvss_severity} score={cve.cvss_score} />
        </div>
        <p className="text-lg text-gray-400 leading-relaxed max-w-4xl">{cve.description}</p>
        <div className="flex gap-6 mt-6 text-sm">
          <div><span className="text-gray-500">Wektor:</span> <span className="font-mono text-gray-300">{cve.cvss_vector || '-'}</span></div>
          <div><span className="text-gray-500">CWE:</span> <span className="font-mono text-gray-300">{cve.cwe_id || '-'}</span></div>
        </div>
      </div>

      {cve.in_kev && (
        <KevBanner 
          dateAdded={cve.kev_date_added} 
          dueDate={cve.kev_due_date} 
          action={cve.kev_required_action} 
          ransomware={cve.kev_ransomware} 
        />
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-8">
          <section className="bg-gray-900 rounded-xl p-6 border border-gray-800">
            <h2 className="text-xl font-bold text-white mb-4">Co jest podatne</h2>
            {cve.affected_packages && cve.affected_packages.length > 0 ? (
              <div className="space-y-4">
                {cve.affected_packages.map((pkg: any, i: number) => (
                  <div key={i} className="bg-black p-4 rounded-lg border border-gray-800">
                    <div className="flex justify-between mb-2">
                      <span className="font-bold text-blue-400">{pkg.package}</span>
                      <span className="text-xs bg-gray-800 px-2 py-1 rounded text-gray-300">{pkg.ecosystem}</span>
                    </div>
                    <div className="text-sm">
                      <p><span className="text-gray-500">Podatne wersje:</span> <span className="text-gray-300">{pkg.vulnerable_range}</span></p>
                      {pkg.fixed_version && <p><span className="text-gray-500">Fix:</span> <span className="text-green-400">{pkg.fixed_version}</span></p>}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 italic">Brak danych z OSV. Sprawdź CPE w NVD.</p>
            )}
          </section>

          <section className="bg-gray-900 rounded-xl p-6 border border-gray-800">
            <h2 className="text-xl font-bold text-white mb-4">Kontekst zagrożenia (OTX)</h2>
            {cve.otx_pulse_count > 0 ? (
              <div className="space-y-4">
                <p><span className="text-gray-500">Liczba pulsów:</span> <span className="text-white font-bold">{cve.otx_pulse_count}</span></p>
                {cve.otx_campaigns?.length > 0 && (
                  <div>
                    <span className="text-gray-500 block mb-1">Kampanie:</span>
                    <div className="flex flex-wrap gap-2">
                      {cve.otx_campaigns.map((c: string, i: number) => <span key={i} className="bg-gray-800 text-xs px-2 py-1 rounded text-gray-300">{c}</span>)}
                    </div>
                  </div>
                )}
                {cve.otx_malware_families?.length > 0 && (
                  <div>
                    <span className="text-gray-500 block mb-1">Malware:</span>
                    <div className="flex flex-wrap gap-2">
                      {cve.otx_malware_families.map((m: string, i: number) => <span key={i} className="bg-red-900/30 text-red-400 border border-red-900/50 text-xs px-2 py-1 rounded">{m}</span>)}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-gray-500 italic">Brak potwierdzonych kampanii w OTX</p>
            )}
          </section>
        </div>

        <div className="space-y-8">
          <MitigationSection cve={cve} />

          <section className="bg-gray-900 rounded-xl p-6 border border-gray-800">
            <h2 className="text-xl font-bold text-white mb-4">Źródła</h2>
            <div className="flex flex-col gap-3">
              <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noreferrer" className="flex justify-between items-center p-3 bg-black rounded-lg hover:bg-gray-800 transition-colors text-gray-300">
                <span>NVD NIST</span> <span>↗</span>
              </a>
              {cve.in_kev && (
                <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noreferrer" className="flex justify-between items-center p-3 bg-black rounded-lg hover:bg-gray-800 transition-colors text-gray-300">
                  <span>CISA KEV</span> <span>↗</span>
                </a>
              )}
              {cve.ghsa_id && (
                <a href={`https://github.com/advisories/${cve.ghsa_id}`} target="_blank" rel="noreferrer" className="flex justify-between items-center p-3 bg-black rounded-lg hover:bg-gray-800 transition-colors text-gray-300">
                  <span>GitHub Advisory</span> <span>↗</span>
                </a>
              )}
              <a href={`https://osv.dev/vulnerability/${cve.id}`} target="_blank" rel="noreferrer" className="flex justify-between items-center p-3 bg-black rounded-lg hover:bg-gray-800 transition-colors text-gray-300">
                <span>OSV.dev</span> <span>↗</span>
              </a>
              <a href={`https://otx.alienvault.com/indicator/cve/${cve.id}`} target="_blank" rel="noreferrer" className="flex justify-between items-center p-3 bg-black rounded-lg hover:bg-gray-800 transition-colors text-gray-300">
                <span>AlienVault OTX</span> <span>↗</span>
              </a>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

// --- Main App ---

export default function App() {
  const [selectedCve, setSelectedCve] = useState<string | null>(null);

  return (
    <main className="min-h-screen bg-black text-gray-300 p-6 md:p-12 font-sans">
      {selectedCve ? (
        <CveDetail id={selectedCve} onBack={() => setSelectedCve(null)} />
      ) : (
        <Dashboard onSelectCve={setSelectedCve} />
      )}
    </main>
  );
}
