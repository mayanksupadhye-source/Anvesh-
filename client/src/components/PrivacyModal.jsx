import React from 'react';
import { X, ShieldCheck, Lock, Trash2, Cpu } from 'lucide-react';

export default function PrivacyModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-white border border-slate-200 rounded-2xl shadow-elevated p-6 space-y-5 animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-sky-600" />
            <h3 className="text-base font-bold text-slate-900">
              Safe Handling & Privacy Architecture
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-4 text-xs text-slate-600 leading-relaxed">
          <div className="flex items-start space-x-3">
            <div className="w-7 h-7 rounded-lg bg-sky-50 border border-sky-100 flex items-center justify-center text-sky-600 flex-shrink-0 mt-0.5">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-bold text-slate-900">Strict Non-Execution Policy</h4>
              <p className="text-slate-500 mt-0.5">
                Uploaded files are treated strictly as read-only binary data. The server never invokes, spawns, or executes any uploaded application, macro, or script.
              </p>
            </div>
          </div>

          <div className="flex items-start space-x-3">
            <div className="w-7 h-7 rounded-lg bg-rose-50 border border-rose-100 flex items-center justify-center text-rose-600 flex-shrink-0 mt-0.5">
              <Trash2 className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-bold text-slate-900">Automated Immediate Cleanup</h4>
              <p className="text-slate-500 mt-0.5">
                Files are written to an isolated temporary directory with randomized filenames and are permanently unlinked immediately after static analysis completes.
              </p>
            </div>
          </div>

          <div className="flex items-start space-x-3">
            <div className="w-7 h-7 rounded-lg bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600 flex-shrink-0 mt-0.5">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <h4 className="font-bold text-slate-900">Real Static Evidence</h4>
              <p className="text-slate-500 mt-0.5">
                ANVESH computes real cryptographic hashes, extracts structural headers, and calculates Shannon entropy without fabricating simulated results.
              </p>
            </div>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-[11px] text-slate-500">
            Files are analyzed for security purposes and should not be uploaded if they contain sensitive personal information unless you trust the local system environment.
          </div>
        </div>

        <div className="pt-2 text-right">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-semibold text-xs shadow-sm transition-colors"
          >
            Understood
          </button>
        </div>
      </div>
    </div>
  );
}
