import React from 'react';
import { Shield, History, Info, RefreshCw } from 'lucide-react';

export default function Navbar({
  systemHealth,
  historyCount,
  onOpenHistory,
  onOpenPrivacy,
  onNewScan,
  hasActiveReport
}) {
  const isClamavReady = systemHealth?.services?.clamav?.available;

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-200/80 bg-white/85 backdrop-blur-md transition-all">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand identity */}
        <div className="flex items-center space-x-3 cursor-pointer group" onClick={onNewScan}>
          <div className="w-9 h-9 rounded-xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-600 transition-transform group-hover:scale-105">
            <Shield className="w-5 h-5 text-sky-600" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-extrabold tracking-tight text-lg text-slate-900">
                ANVESH
              </span>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-sky-50 border border-sky-200 text-sky-700 font-semibold tracking-wider">
                AI Malware Detector
              </span>
            </div>
            <p className="text-[11px] text-slate-500 hidden sm:block font-medium">
              Uncover what your files hide.
            </p>
          </div>
        </div>

        {/* Status indicators and action buttons */}
        <div className="flex items-center space-x-2 sm:space-x-3">
          {/* Engine status indicator */}
          <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-50 border border-slate-200 text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                isClamavReady ? 'bg-emerald-500 shadow-sm shadow-emerald-500/40' : 'bg-amber-400'
              }`}
            />
            <span className="text-slate-600 font-mono text-[11px] font-medium">
              {isClamavReady ? 'ClamAV: Ready' : 'ClamAV: Offline (Static Mode)'}
            </span>
          </div>

          {/* Safe handling button */}
          <button
            onClick={onOpenPrivacy}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-600 hover:text-slate-900 bg-white hover:bg-slate-50 border border-slate-200 shadow-xs transition-colors"
            title="Safe File Handling & Privacy Architecture"
          >
            <Info className="w-3.5 h-3.5 text-sky-600" />
            <span className="hidden sm:inline">Safe Handling</span>
          </button>

          {/* History drawer trigger */}
          <button
            onClick={onOpenHistory}
            className="relative flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-600 hover:text-slate-900 bg-white hover:bg-slate-50 border border-slate-200 shadow-xs transition-colors"
          >
            <History className="w-3.5 h-3.5 text-slate-500" />
            <span className="hidden sm:inline">History</span>
            {historyCount > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-sky-100 text-sky-800 font-bold border border-sky-200">
                {historyCount}
              </span>
            )}
          </button>

          {/* New Scan button when in report view */}
          {hasActiveReport && (
            <button
              onClick={onNewScan}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 shadow-sm transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5 text-white" />
              <span>New Scan</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
