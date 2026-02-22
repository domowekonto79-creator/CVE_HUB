import React from 'react';
import { AlertTriangle } from 'lucide-react';

interface Props {
  dateAdded: string;
  dueDate: string;
  action: string;
  ransomware: string;
}

export default function KevBanner({ dateAdded, dueDate, action, ransomware }: Props) {
  return (
    <div className="bg-red-950/40 border border-red-900 rounded-lg p-4 mb-6">
      <div className="flex items-center gap-3 mb-2">
        <AlertTriangle className="text-red-500 w-6 h-6" />
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
