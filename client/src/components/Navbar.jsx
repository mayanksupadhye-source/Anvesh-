import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, History, Info, RefreshCw, Cpu } from 'lucide-react';

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
    <header className="sticky top-0 z-40 w-full border-b border-cyber-border/70 bg-cyber-bg/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand identity */}
        <div className="flex items-center space-x-3 cursor-pointer" onClick={onNewScan}>
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-500/10">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-extrabold tracking-wider text-xl bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                ANVESH
              </span>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-cyan-950/70 border border-cyan-700/50 text-cyan-300 font-semibold tracking-wide">
                AI Malware Detector
              </span>
            </div>
            <p className="text-[11px] text-slate-400 hidden sm:block tracking-wide">
              Uncover what your files hide.
            </p>
          </div>
        </div>

        {/* Status indicators and action buttons */}
        <div className="flex items-center space-x-2 sm:space-x-3">
          {/* Real Engine status pill */}
          <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-cyber-surface border border-cyber-border text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                isClamavReady ? 'bg-emerald-400 shadow-sm shadow-emerald-400/50' : 'bg-amber-400'
              }`}
            />
            <span className="text-slate-300 font-mono text-[11px]">
              {isClamavReady ? 'ClamAV: Ready' : 'ClamAV: Offline (Static Mode)'}
            </span>
          </div>

          {/* Privacy info button */}
          <button
            onClick={onOpenPrivacy}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-cyber-surface/70 hover:bg-cyber-surface border border-cyber-border transition-colors"
            title="Safe File Handling & Privacy Policy"
          >
            <Info className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Safe Handling</span>
          </button>

          {/* Scan History drawer button */}
          <button
            onClick={onOpenHistory}
            className="relative flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-cyber-surface/70 hover:bg-cyber-surface border border-cyber-border transition-colors"
          >
            <History className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">History</span>
            {historyCount > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                {historyCount}
              </span>
            )}
          </button>

          {/* New Scan button if viewing a report */}
          {hasActiveReport && (
            <button
              onClick={onNewScan}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-cyan-300 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-600/50 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>New Scan</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
