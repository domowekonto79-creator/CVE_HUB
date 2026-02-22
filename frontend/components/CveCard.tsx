import React from 'react';
import Link from 'next/link';
import SeverityBadge from './SeverityBadge';
import { ShieldAlert } from 'lucide-react';

export default function CveCard({ cve }: { cve: any }) {
  return (
    <Link href={`/cve/${cve.id}`} className="block">
      <div className="bg-gray-900 border border-gray-800 hover:border-gray-700 rounded-xl p-5 transition-all">
        <div className="flex justify-between items-start mb-3">
          <h3 className="text-lg font-bold text-blue-400">{cve.id}</h3>
          <div className="flex gap-2">
            {cve.in_kev && <ShieldAlert className="text-red-500 w-5 h-5" title="In KEV" />}
            <SeverityBadge severity={cve.cvss_severity} score={cve.cvss_score} />
          </div>
        </div>
        <p className="text-gray-400 text-sm line-clamp-2 mb-4">{cve.description}</p>
        <div className="flex justify-between text-xs text-gray-500">
          <span>Pub: {new Date(cve.published_at).toLocaleDateString()}</span>
          {cve.otx_pulse_count > 0 && <span>OTX Pulses: {cve.otx_pulse_count}</span>}
        </div>
      </div>
    </Link>
  );
}
