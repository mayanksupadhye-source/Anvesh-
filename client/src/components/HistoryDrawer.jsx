import React from 'react';
import { X, Trash2, Clock, ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink } from 'lucide-react';

export default function HistoryDrawer({ isOpen, onClose, history = [], onSelectScan, onClearHistory }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end">
      <div className="w-full max-w-md bg-cyber-bg border-l border-cyber-border h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-5 border-b border-cyber-border flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-white">
              Scan History ({history.length})
            </h3>
          </div>
          <div className="flex items-center space-x-2">
            {history.length > 0 && (
              <button
                onClick={onClearHistory}
                className="p-1.5 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                title="Clear all history"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content list */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {history.length === 0 ? (
            <div className="text-center py-16 text-slate-500 text-xs">
              No recent scans recorded. Upload a file or run a demonstration sample to see history here.
            </div>
          ) : (
            history.map((item, idx) => {
              const isCritOrHigh = item.riskLevel === 'CRITICAL' || item.riskLevel === 'HIGH';
              const isMed = item.riskLevel === 'MEDIUM';

              return (
                <div
                  key={idx}
                  onClick={() => {
                    onSelectScan(item);
                    onClose();
                  }}
                  className="p-3.5 rounded-xl border border-cyber-border bg-cyber-surface hover:bg-cyber-surfaceHover cursor-pointer transition-all space-y-2 group"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors truncate max-w-[240px]">
                      {item.filename}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        isCritOrHigh
                          ? 'bg-rose-950 text-rose-400 border border-rose-800'
                          : isMed
                          ? 'bg-amber-950 text-amber-400 border border-amber-800'
                          : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      }`}
                    >
                      {item.riskLevel}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>{item.detectedType}</span>
                    <span>{item.sizeFormatted}</span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1 border-t border-slate-800/80">
                    <span className="truncate max-w-[200px]">SHA-256: {item.sha256?.slice(0, 10)}...</span>
                    <span>{new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer info */}
        <div className="p-4 border-t border-cyber-border text-[11px] text-slate-500 text-center">
          Metadata stored in browser localStorage. No file contents are retained.
        </div>
      </div>
    </div>
  );
}
