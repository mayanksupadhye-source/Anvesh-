import React from 'react';
import { Loader2, CheckCircle2, Shield, FileSearch, Hash, Binary, Cpu, BarChart3 } from 'lucide-react';

const STAGES = [
  { id: 'upload', label: 'Isolated File Ingestion', icon: FileSearch, desc: 'Storing in sandboxed temporary buffer without execution' },
  { id: 'identify', label: 'Magic-Byte & Format Identification', icon: Binary, desc: 'Inspecting raw file signature to detect extension spoofing' },
  { id: 'hash', label: 'Cryptographic Hashing', icon: Hash, desc: 'Computing SHA-256, SHA-1, and MD5 fingerprints' },
  { id: 'static', label: 'Deep Static Structural Analysis', icon: Cpu, desc: 'Analyzing PE headers, entropy, sections, macros, or PDF tags' },
  { id: 'clamav', label: 'Antivirus Signature Scan', icon: Shield, desc: 'Querying ClamAV daemon and external reputation feeds' },
  { id: 'risk', label: 'Explainable Risk Synthesis', icon: BarChart3, desc: 'Compiling evidence signals and plain-English recommendations' }
];

export function ScanProgress({ currentStageIndex = 0, fileName, fileSize }) {
  return (
    <div className="w-full max-w-2xl mx-auto space-y-6 p-8 rounded-2xl bg-cyber-surface border border-cyber-border shadow-2xl">
      <div className="flex items-center justify-between border-b border-cyber-border/70 pb-4">
        <div>
          <h3 className="text-lg font-bold text-white flex items-center space-x-2">
            <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
            <span>Analyzing File...</span>
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            <span className="font-mono text-cyan-300 font-semibold">{fileName}</span>
            {fileSize && <span className="ml-2 text-slate-500">({fileSize})</span>}
          </p>
        </div>
        <div className="text-right">
          <span className="text-xs font-mono font-bold text-cyan-400">
            Stage {Math.min(currentStageIndex + 1, STAGES.length)} of {STAGES.length}
          </span>
        </div>
      </div>

      <div className="space-y-4">
        {STAGES.map((stage, idx) => {
          const isDone = idx < currentStageIndex;
          const isCurrent = idx === currentStageIndex;
          const Icon = stage.icon;

          return (
            <div
              key={stage.id}
              className={`flex items-start space-x-3.5 p-3 rounded-xl transition-all ${
                isCurrent
                  ? 'bg-cyan-950/30 border border-cyan-800/40 text-cyan-300'
                  : isDone
                  ? 'bg-slate-900/40 border border-transparent text-slate-300'
                  : 'text-slate-600 opacity-60'
              }`}
            >
              <div className="mt-0.5">
                {isDone ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : isCurrent ? (
                  <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
                ) : (
                  <Icon className="w-5 h-5 text-slate-600" />
                )}
              </div>

              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h4 className={`text-xs sm:text-sm font-semibold ${isCurrent ? 'text-white' : ''}`}>
                    {stage.label}
                  </h4>
                  {isCurrent && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/60 text-cyan-300 animate-pulse">
                      Processing
                    </span>
                  )}
                  {isDone && (
                    <span className="text-[10px] font-mono text-emerald-400">
                      Completed
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  {stage.desc}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      <p className="text-center text-[11px] text-slate-500 italic pt-2">
        Static inspection operates purely on binary structures without executing files.
      </p>
    </div>
  );
}
export default ScanProgress;
