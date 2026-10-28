import React from 'react';
import { X, Trash2, Clock, ArrowUpRight } from 'lucide-react';

export default function HistoryDrawer({ isOpen, onClose, history = [], onSelectScan, onClearHistory }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-900/40 backdrop-blur-xs flex justify-end">
      <div className="w-full max-w-md bg-white border-l border-slate-200 h-full flex flex-col shadow-elevated animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-5 border-b border-slate-100 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Clock className="w-4 h-4 text-sky-600" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900">
              Scan History ({history.length})
            </h3>
          </div>
          <div className="flex items-center space-x-1.5">
            {history.length > 0 && (
              <button
                onClick={onClearHistory}
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-slate-100 transition-colors"
                title="Clear all history"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content list */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2.5">
          {history.length === 0 ? (
            <div className="text-center py-20 text-slate-400 text-xs">
              No recent scans recorded. Upload a file or run an interactive test sample to see history here.
            </div>
          ) : (
            history.map((item, idx) => {
              const isCrit = item.riskLevel === 'CRITICAL';
              const isHigh = item.riskLevel === 'HIGH';
              const isMed = item.riskLevel === 'MEDIUM';

              return (
                <div
                  key={idx}
                  onClick={() => {
                    onSelectScan(item);
                    onClose();
                  }}
                  className="p-3.5 rounded-xl border border-slate-200 bg-white hover:border-sky-300 hover:shadow-card cursor-pointer transition-all space-y-2 group"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-900 group-hover:text-sky-700 transition-colors truncate max-w-[240px]">
                      {item.filename}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
                        isCrit
                          ? 'bg-red-50 text-red-800 border-red-200'
                          : isHigh
                          ? 'bg-rose-50 text-rose-800 border-rose-200'
                          : isMed
                          ? 'bg-amber-50 text-amber-800 border-amber-200'
                          : 'bg-emerald-50 text-emerald-800 border-emerald-200'
                      }`}
                    >
                      {item.riskLevel}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span className="truncate max-w-[180px]">{item.detectedType}</span>
                    <span>{item.sizeFormatted}</span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1.5 border-t border-slate-100">
                    <span className="truncate max-w-[200px]">SHA-256: {item.sha256?.slice(0, 10)}...</span>
                    <span>{new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-100 text-[11px] text-slate-400 text-center font-medium">
          Stored locally in your browser. No file contents are retained.
        </div>
      </div>
    </div>
  );
}
