import React, { useState, useRef } from 'react';
import { UploadCloud, FileCheck, AlertTriangle, Shield, PlayCircle, FileText, FileCode, Archive } from 'lucide-react';

export default function Dropzone({ onFileSelected, isScanning, onSelectSample }) {
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      onFileSelected(e.dataTransfer.files[0]);
    }
  };

  const handleFileInputChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      onFileSelected(e.target.files[0]);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-8">
      {/* Hero presentation title */}
      <div className="text-center space-y-3 pt-4 sm:pt-8">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950/40 border border-cyan-800/40 text-cyan-400 text-xs font-mono">
          <Shield className="w-3.5 h-3.5" />
          <span>Evidence-Based Static Malicious File Analysis</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white">
          Inspect Before You <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">Execute</span>.
        </h1>
        <p className="text-sm sm:text-base text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Deep static inspection, magic-byte verification, Shannon entropy, PE structural parsing, and signature detection — safe, non-executing threat assessment.
        </p>
      </div>

      {/* Main Drag-and-Drop Area */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative group rounded-2xl border-2 border-dashed p-8 sm:p-14 text-center cursor-pointer transition-all duration-300 ${
          isDragOver
            ? 'border-cyan-400 bg-cyan-950/20 scale-[1.01] shadow-2xl shadow-cyan-500/10'
            : 'border-cyber-border hover:border-slate-600 bg-cyber-surface/60 hover:bg-cyber-surface'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={handleFileInputChange}
          disabled={isScanning}
        />

        <div className="flex flex-col items-center justify-center space-y-4">
          <div
            className={`w-20 h-20 rounded-2xl flex items-center justify-center transition-transform group-hover:scale-110 ${
              isDragOver
                ? 'bg-cyan-500/20 text-cyan-300'
                : 'bg-cyber-border/40 text-slate-400 group-hover:text-cyan-400 group-hover:bg-cyan-950/30'
            }`}
          >
            <UploadCloud className="w-10 h-10" />
          </div>

          <div className="space-y-1">
            <h3 className="text-lg sm:text-xl font-bold text-white group-hover:text-cyan-300 transition-colors">
              Drop file here to analyze
            </h3>
            <p className="text-sm text-slate-400">
              or <span className="text-cyan-400 font-semibold underline underline-offset-2">browse from device</span>
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-2 pt-2 text-xs font-mono text-slate-400">
            <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">PDF</span>
            <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">DOCX</span>
            <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">XLSX</span>
            <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">ZIP</span>
            <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">EXE</span>
            <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">SCR</span>
            <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">PS1</span>
            <span className="text-slate-500">• Max 30 MB</span>
          </div>

          <p className="text-[11px] text-slate-500 max-w-md pt-2">
            Uploaded files are never executed. Isolated memory inspection with immediate automated server-side cleanup.
          </p>
        </div>
      </div>

      {/* Harmless Test Samples Section for Viva & Demonstration */}
      <div className="space-y-3 pt-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <PlayCircle className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Interactive Test Demonstration Samples
            </span>
          </div>
          <span className="text-[11px] text-slate-500 hidden sm:inline">
            100% harmless test cases for examiners & evaluators
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Sample 1: Clean PDF */}
          <button
            onClick={() => onSelectSample('clean-pdf')}
            disabled={isScanning}
            className="p-3.5 rounded-xl text-left bg-cyber-surface border border-cyber-border hover:border-emerald-500/40 hover:bg-cyber-surfaceHover transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-slate-200 group-hover:text-emerald-400 transition-colors">
                Clean Document
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/40">
                Safe
              </span>
            </div>
            <p className="text-[11px] text-slate-400 line-clamp-2">
              Standard valid PDF with normal structure and zero malicious tags.
            </p>
          </button>

          {/* Sample 2: Extension Mismatch */}
          <button
            onClick={() => onSelectSample('extension-mismatch')}
            disabled={isScanning}
            className="p-3.5 rounded-xl text-left bg-cyber-surface border border-cyber-border hover:border-amber-500/40 hover:bg-cyber-surfaceHover transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-slate-200 group-hover:text-amber-400 transition-colors">
                Extension Spoof
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-950/60 text-amber-400 border border-amber-800/40">
                High Risk
              </span>
            </div>
            <p className="text-[11px] text-slate-400 line-clamp-2">
              Named invoice.pdf but contains Windows PE binary header.
            </p>
          </button>

          {/* Sample 3: EICAR Test */}
          <button
            onClick={() => onSelectSample('eicar-test')}
            disabled={isScanning}
            className="p-3.5 rounded-xl text-left bg-cyber-surface border border-cyber-border hover:border-rose-500/40 hover:bg-cyber-surfaceHover transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-slate-200 group-hover:text-rose-400 transition-colors">
                EICAR Antivirus
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-950/60 text-rose-400 border border-rose-800/40">
                Signature
              </span>
            </div>
            <p className="text-[11px] text-slate-400 line-clamp-2">
              Standard benign test string to test antivirus engine detection.
            </p>
          </button>

          {/* Sample 4: Suspicious Script */}
          <button
            onClick={() => onSelectSample('suspicious-script')}
            disabled={isScanning}
            className="p-3.5 rounded-xl text-left bg-cyber-surface border border-cyber-border hover:border-cyan-500/40 hover:bg-cyber-surfaceHover transition-all group"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-slate-200 group-hover:text-cyan-400 transition-colors">
                Suspicious Script
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/40">
                Heuristic
              </span>
            </div>
            <p className="text-[11px] text-slate-400 line-clamp-2">
              PowerShell script with LOLBin certutil download pattern & base64.
            </p>
          </button>
        </div>
      </div>
    </div>
  );
}
