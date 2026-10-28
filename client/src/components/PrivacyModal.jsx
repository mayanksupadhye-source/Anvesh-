import React from 'react';
import { X, ShieldCheck, Lock, Trash2, Cpu } from 'lucide-react';

export default function PrivacyModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-cyber-bg border border-cyber-border rounded-2xl shadow-2xl p-6 space-y-5 animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between border-b border-cyber-border pb-3">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white">
              Safe File Handling & Privacy Architecture
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-4 text-xs text-slate-300 leading-relaxed">
          <div className="flex items-start space-x-3">
            <Lock className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="font-bold text-white">Strict Non-Execution Policy</h4>
              <p className="text-slate-400 mt-0.5">
                Uploaded files are treated strictly as read-only binary data. The server never invokes, spawns, or executes any uploaded application, macro, or script.
              </p>
            </div>
          </div>

          <div className="flex items-start space-x-3">
            <Trash2 className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="font-bold text-white">Automated Immediate Cleanup</h4>
              <p className="text-slate-400 mt-0.5">
                Files are written to an isolated temporary directory with randomized filenames and are permanently deleted immediately after static analysis completes.
              </p>
            </div>
          </div>

          <div className="flex items-start space-x-3">
            <Cpu className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="font-bold text-white">Real Static Evidence</h4>
              <p className="text-slate-400 mt-0.5">
                ANVESH computes real cryptographic hashes, extracts structural headers, and calculates Shannon entropy without fabricating fake AI scores.
              </p>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400">
            Files are analyzed for security purposes and should not be uploaded if they contain sensitive personal data unless you trust the local system environment.
          </div>
        </div>

        <div className="pt-2 text-right">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors"
          >
            Understood
          </button>
        </div>
      </div>
    </div>
  );
}
