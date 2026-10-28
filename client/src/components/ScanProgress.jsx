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
  const progressPercent = Math.min(100, Math.round(((currentStageIndex + 1) / STAGES.length) * 100));

  return (
    <div className="w-full max-w-2xl mx-auto space-y-6 p-8 rounded-2xl bg-white border border-slate-200 shadow-elevated">
      {/* Header bar */}
      <div className="flex items-center justify-between border-b border-slate-100 pb-4">
        <div>
          <h3 className="text-base font-bold text-slate-900 flex items-center space-x-2">
            <Loader2 className="w-4 h-4 text-sky-600 animate-spin" />
            <span>Analyzing File In Sandbox...</span>
          </h3>
          <p className="text-xs text-slate-500 mt-1">
            <span className="font-mono text-slate-800 font-semibold">{fileName}</span>
            {fileSize && <span className="ml-2 text-slate-400">({fileSize})</span>}
          </p>
        </div>
        <div className="text-right">
          <span className="text-xs font-mono font-bold text-sky-700 bg-sky-50 px-2.5 py-1 rounded-md border border-sky-200">
            Stage {Math.min(currentStageIndex + 1, STAGES.length)} / {STAGES.length}
          </span>
        </div>
      </div>

      {/* Progress track */}
      <div className="w-full h-1.5 bg-slate-100 rounded-full overflow-hidden">
        <div
          className="h-full bg-sky-500 rounded-full transition-all duration-300"
          style={{ width: `${progressPercent}%` }}
        />
      </div>

      {/* Stages list */}
      <div className="space-y-2.5">
        {STAGES.map((stage, idx) => {
          const isDone = idx < currentStageIndex;
          const isCurrent = idx === currentStageIndex;
          const Icon = stage.icon;

          return (
            <div
              key={stage.id}
              className={`flex items-start space-x-3.5 p-3 rounded-xl transition-all ${
                isCurrent
                  ? 'bg-sky-50/80 border border-sky-200/80'
                  : isDone
                  ? 'bg-slate-50/60 border border-slate-100 text-slate-700'
                  : 'border border-transparent text-slate-400 opacity-60'
              }`}
            >
              <div className="mt-0.5">
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                ) : isCurrent ? (
                  <Loader2 className="w-4 h-4 text-sky-600 animate-spin" />
                ) : (
                  <Icon className="w-4 h-4 text-slate-400" />
                )}
              </div>

              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h4 className={`text-xs font-semibold ${isCurrent ? 'text-sky-950 font-bold' : isDone ? 'text-slate-800' : 'text-slate-500'}`}>
                    {stage.label}
                  </h4>
                  {isCurrent && (
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-sky-100 text-sky-800 border border-sky-200 animate-pulse">
                      Analyzing
                    </span>
                  )}
                  {isDone && (
                    <span className="text-[10px] font-mono text-emerald-700 font-semibold">
                      Completed
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  {stage.desc}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      <p className="text-center text-[11px] text-slate-400 italic pt-1">
        Static analysis executes non-destructively on read-only byte buffers.
      </p>
    </div>
  );
}
export default ScanProgress;
