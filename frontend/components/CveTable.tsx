import React from 'react';
import Link from 'next/link';
import SeverityBadge from './SeverityBadge';
import { ShieldAlert } from 'lucide-react';

export default function CveTable({ cves }: { cves: any[] }) {
  return (
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
            // Safely extract product name, fallback to '-' if not available
            let product = '-';
            try {
              if (cve.cpe_list && Array.isArray(cve.cpe_list) && cve.cpe_list.length > 0) {
                const nodes = cve.cpe_list[0]?.nodes;
                if (nodes && Array.isArray(nodes) && nodes.length > 0) {
                  const matches = nodes[0]?.cpeMatch;
                  if (matches && Array.isArray(matches) && matches.length > 0) {
                    const criteria = matches[0]?.criteria;
                    if (criteria) {
                      const parts = criteria.split(':');
                      if (parts.length > 4) {
                        product = parts[4];
                      }
                    }
                  }
                }
              }
            } catch (e) {
              console.error("Error parsing CPE list for", cve.id, e);
            }

            return (
              <tr key={cve.id} className="hover:bg-gray-900/50 transition-colors">
                <td className="px-6 py-4 font-medium text-blue-400">
                  <Link href={`/cve/${cve.id}`}>{cve.id}</Link>
                </td>
                <td className="px-6 py-4">
                  <SeverityBadge severity={cve.cvss_severity} score={cve.cvss_score} />
                </td>
                <td className="px-6 py-4 truncate max-w-[200px]">{product}</td>
                <td className="px-6 py-4">
                  {cve.in_kev ? <ShieldAlert className="text-red-500 w-5 h-5" /> : '-'}
                </td>
                <td className="px-6 py-4">{cve.published_at ? new Date(cve.published_at).toLocaleDateString() : '-'}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
