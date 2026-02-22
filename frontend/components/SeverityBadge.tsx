import React from 'react';

interface Props {
  severity: string | null;
  score?: number | null;
}

export default function SeverityBadge({ severity, score }: Props) {
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
