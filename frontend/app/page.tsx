import React from 'react';
import { supabase } from '@/lib/supabase';
import CveTable from '@/components/CveTable';
import { ShieldAlert } from 'lucide-react';

export const dynamic = 'force-dynamic'; // Force dynamic rendering, bypass cache

export default async function DashboardPage() {
  // Fetch CVEs sorted by KEV first, then CVSS score
  const { data: cves, error } = await supabase
    .from('cve_records')
    .select('*')
    .order('in_kev', { ascending: false })
    .order('cvss_score', { ascending: false })
    .limit(25);

  return (
    <main className="min-h-screen bg-black text-gray-300 p-6 md:p-12 font-sans">
      <div className="max-w-7xl mx-auto">
        <header className="mb-12">
          <h1 className="text-4xl font-bold text-white tracking-tight mb-2">CVE Enrichment Hub</h1>
          <p className="text-gray-500">Zintegrowane dane z NVD, CISA KEV, OSV, GitHub i AlienVault OTX.</p>
        </header>

        {/* Filters placeholder - in a real app this would be a client component */}
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

        {error ? (
          <div className="text-center py-20 bg-red-950/40 rounded-xl border border-red-900">
            <p className="text-red-400 font-bold">Błąd pobierania danych z Supabase:</p>
            <p className="text-red-300 mt-2">{error.message}</p>
            <p className="text-red-300 mt-2 text-sm">Upewnij się, że zmienne NEXT_PUBLIC_SUPABASE_URL i NEXT_PUBLIC_SUPABASE_ANON_KEY są ustawione w Vercel.</p>
          </div>
        ) : cves && cves.length > 0 ? (
          <CveTable cves={cves} />
        ) : (
          <div className="text-center py-20 bg-gray-900 rounded-xl border border-gray-800">
            <p className="text-gray-500">Brak danych. Upewnij się, że backend pobrał dane do Supabase.</p>
          </div>
        )}
      </div>
    </main>
  );
}
