import React from 'react';

interface Props {
  cve: any;
}

export default function MitigationSection({ cve }: Props) {
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
            <span className="font-bold">Priorytet {p.level}:</span>
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
