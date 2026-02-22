import React, { useEffect, useState } from 'react';
import CveTable from '../components/CveTable';
import { ShieldAlert } from 'lucide-react';

export default function DashboardPage() {
  const [cves, setCves] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch('/api/cves')
      .then(res => {
        if (!res.ok) throw new Error('Failed to fetch CVEs');
        return res.json();
      })
      .then(data => {
        setCves(data);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setError('Nie udało się pobrać danych z NVD. Spróbuj ponownie za chwilę.');
        setLoading(false);
      });
  }, []);

  return (
    <main className="min-h-screen bg-black text-gray-300 p-6 md:p-12 font-sans">
      <div className="max-w-7xl mx-auto">
        <header className="mb-12">
          <h1 className="text-4xl font-bold text-white tracking-tight mb-2">CVE Enrichment Hub</h1>
          <p className="text-gray-500">Zintegrowane dane z NVD, CISA KEV, OSV, GitHub i AlienVault OTX.</p>
        </header>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-8 flex flex-wrap gap-4 items-center">
          <div className="flex-1 min-w-[200px]">
            <input type="text" placeholder="Szukaj CVE ID..." className="w-full bg-black border border-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500" />
          </div>
          <div className="flex items-center gap-2 bg-black border border-gray-700 rounded-lg px-4 py-2">
            <ShieldAlert className="w-4 h-4 text-red-500" />
            <span className="text-sm">Tylko KEV</span>
          </div>
          <select className="bg-black border border-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500">
            <option>Wszystkie Severity</option>
            <option>CRITICAL</option>
            <option>HIGH</option>
            <option>MEDIUM</option>
            <option>LOW</option>
          </select>
        </div>

        {loading ? (
          <div className="text-center py-20 bg-gray-900 rounded-xl border border-gray-800">
            <p className="text-gray-500 animate-pulse">Pobieranie najnowszych podatności z NVD...</p>
          </div>
        ) : error ? (
          <div className="text-center py-20 bg-red-900/20 rounded-xl border border-red-900/50">
            <p className="text-red-400">{error}</p>
          </div>
        ) : cves && cves.length > 0 ? (
          <CveTable cves={cves} />
        ) : (
          <div className="text-center py-20 bg-gray-900 rounded-xl border border-gray-800">
            <p className="text-gray-500">Brak danych.</p>
          </div>
        )}
      </div>
    </main>
  );
}
