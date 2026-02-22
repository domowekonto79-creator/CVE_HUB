import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import SeverityBadge from '../components/SeverityBadge';
import KevBanner from '../components/KevBanner';
import MitigationSection from '../components/MitigationSection';
import { ArrowLeft } from 'lucide-react';

export default function CveDetailPage() {
  const { id } = useParams();
  const [cve, setCve] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch(`/api/cves/${id}`)
      .then(res => {
        if (!res.ok) throw new Error('Failed to fetch CVE details');
        return res.json();
      })
      .then(data => {
        setCve(data);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setError('Nie udało się pobrać szczegółów podatności.');
        setLoading(false);
      });
  }, [id]);

  if (loading) {
    return <div className="min-h-screen bg-black text-white p-12 text-center">Ładowanie danych...</div>;
  }

  if (error || !cve) {
    return <div className="min-h-screen bg-black text-red-400 p-12 text-center">{error || 'CVE not found'}</div>;
  }

  return (
    <main className="min-h-screen bg-black text-gray-300 p-6 md:p-12 font-sans max-w-6xl mx-auto">
      <Link to="/" className="inline-flex items-center gap-2 text-blue-400 hover:text-blue-300 mb-8 transition-colors">
        <ArrowLeft className="w-4 h-4" /> Wróć do listy
      </Link>

      {/* SEKCJA 1 - PODSUMOWANIE */}
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

      {/* SEKCJA 3 - KEV */}
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
          {/* SEKCJA 2 - CO JEST PODATNE */}
          <section className="bg-gray-900 rounded-xl p-6 border border-gray-800">
            <h2 className="text-xl font-bold text-white mb-4">Co jest podatne</h2>
            {cve.affected_packages && cve.affected_packages.length > 0 ? (
              <div className="space-y-4">
                {cve.affected_packages.map((pkg: any, i: number) => (
                  <div key={i} className="bg-black p-4 rounded-lg border border-gray-800">
                    <div className="flex justify-between mb-2">
                      <span className="font-bold text-blue-400">{pkg.package}</span>
                      <span className="text-xs bg-gray-800 px-2 py-1 rounded">{pkg.ecosystem}</span>
                    </div>
                    <div className="text-sm">
                      <p><span className="text-gray-500">Podatne wersje:</span> {pkg.vulnerable_range}</p>
                      {pkg.fixed_version && <p><span className="text-gray-500">Fix:</span> <span className="text-green-400">{pkg.fixed_version}</span></p>}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 italic">Brak danych z OSV. Sprawdź CPE w NVD.</p>
            )}
          </section>

          {/* SEKCJA 4 - OTX */}
          <section className="bg-gray-900 rounded-xl p-6 border border-gray-800">
            <h2 className="text-xl font-bold text-white mb-4">Kontekst zagrożenia (OTX)</h2>
            {cve.otx_pulse_count > 0 ? (
              <div className="space-y-4">
                <p><span className="text-gray-500">Liczba pulsów:</span> <span className="text-white font-bold">{cve.otx_pulse_count}</span></p>
                {cve.otx_campaigns?.length > 0 && (
                  <div>
                    <span className="text-gray-500 block mb-1">Kampanie:</span>
                    <div className="flex flex-wrap gap-2">
                      {cve.otx_campaigns.map((c: string, i: number) => <span key={i} className="bg-gray-800 text-xs px-2 py-1 rounded">{c}</span>)}
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
          {/* SEKCJA 5 - MITIGATION */}
          <MitigationSection cve={cve} />

          {/* SEKCJA 6 - ŹRÓDŁA */}
          <section className="bg-gray-900 rounded-xl p-6 border border-gray-800">
            <h2 className="text-xl font-bold text-white mb-4">Źródła</h2>
            <div className="flex flex-col gap-3">
              <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noreferrer" className="flex justify-between items-center p-3 bg-black rounded-lg hover:bg-gray-800 transition-colors">
                <span>NVD NIST</span> <span>↗</span>
              </a>
              {cve.in_kev && (
                <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noreferrer" className="flex justify-between items-center p-3 bg-black rounded-lg hover:bg-gray-800 transition-colors">
                  <span>CISA KEV</span> <span>↗</span>
                </a>
              )}
              {cve.ghsa_id && (
                <a href={`https://github.com/advisories/${cve.ghsa_id}`} target="_blank" rel="noreferrer" className="flex justify-between items-center p-3 bg-black rounded-lg hover:bg-gray-800 transition-colors">
                  <span>GitHub Advisory</span> <span>↗</span>
                </a>
              )}
              <a href={`https://osv.dev/vulnerability/${cve.id}`} target="_blank" rel="noreferrer" className="flex justify-between items-center p-3 bg-black rounded-lg hover:bg-gray-800 transition-colors">
                <span>OSV.dev</span> <span>↗</span>
              </a>
              <a href={`https://otx.alienvault.com/indicator/cve/${cve.id}`} target="_blank" rel="noreferrer" className="flex justify-between items-center p-3 bg-black rounded-lg hover:bg-gray-800 transition-colors">
                <span>AlienVault OTX</span> <span>↗</span>
              </a>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
