import React, { useState, useRef } from 'react';
import { UploadCloud, Shield, PlayCircle, Lock, ArrowUpRight } from 'lucide-react';

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
    <div className="w-full max-w-4xl mx-auto space-y-10">
      {/* Hero presentation title */}
      <div className="text-center space-y-3 pt-6 sm:pt-10">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-sky-50 border border-sky-200 text-sky-700 text-xs font-mono font-semibold">
          <Shield className="w-3.5 h-3.5 text-sky-600" />
          <span>Evidence-Based Static Malicious File Analysis</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-slate-900">
          Inspect Before You <span className="text-sky-600">Execute</span>.
        </h1>
        <p className="text-sm sm:text-base text-slate-600 max-w-2xl mx-auto leading-relaxed">
          Deep static structure inspection, magic-byte verification, Shannon entropy, PE binary parsing, and signature detection — safe, non-executing threat assessment.
        </p>
      </div>

      {/* Main Drag-and-Drop Area */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative group rounded-2xl border-2 border-dashed p-10 sm:p-14 text-center cursor-pointer transition-all duration-200 bg-white ${
          isDragOver
            ? 'border-sky-500 bg-sky-50/40 shadow-elevated scale-[1.005]'
            : 'border-slate-200 hover:border-sky-400 hover:shadow-elevated shadow-card'
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
            className={`w-16 h-16 rounded-2xl flex items-center justify-center transition-all ${
              isDragOver
                ? 'bg-sky-500 text-white shadow-md'
                : 'bg-sky-50 text-sky-600 border border-sky-100 group-hover:bg-sky-100/80 group-hover:scale-105'
            }`}
          >
            <UploadCloud className="w-8 h-8" />
          </div>

          <div className="space-y-1">
            <h3 className="text-base sm:text-lg font-bold text-slate-900 group-hover:text-sky-600 transition-colors">
              Drop file to analyze, or <span className="text-sky-600 underline underline-offset-4">browse from computer</span>
            </h3>
            <p className="text-xs text-slate-500 font-medium">
              Maximum file size: 30 MB per file
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-1.5 pt-2 text-xs font-mono text-slate-600">
            <span className="px-2.5 py-1 rounded-md bg-slate-100/80 border border-slate-200 font-medium">PDF</span>
            <span className="px-2.5 py-1 rounded-md bg-slate-100/80 border border-slate-200 font-medium">DOCX</span>
            <span className="px-2.5 py-1 rounded-md bg-slate-100/80 border border-slate-200 font-medium">XLSX</span>
            <span className="px-2.5 py-1 rounded-md bg-slate-100/80 border border-slate-200 font-medium">ZIP</span>
            <span className="px-2.5 py-1 rounded-md bg-slate-100/80 border border-slate-200 font-medium">EXE</span>
            <span className="px-2.5 py-1 rounded-md bg-slate-100/80 border border-slate-200 font-medium">SCR</span>
            <span className="px-2.5 py-1 rounded-md bg-slate-100/80 border border-slate-200 font-medium">PS1</span>
          </div>

          <div className="flex items-center space-x-1.5 text-[11px] text-slate-500 pt-2 font-medium">
            <Lock className="w-3 h-3 text-slate-400" />
            <span>Files are analyzed strictly as data without execution, and deleted immediately after analysis.</span>
          </div>
        </div>
      </div>

      {/* Harmless Test Samples Section for Viva & Demonstration */}
      <div className="space-y-3.5 pt-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <PlayCircle className="w-4 h-4 text-sky-600" />
            <span className="text-xs font-bold uppercase tracking-wider text-slate-700">
              Interactive Test Demonstration Samples
            </span>
          </div>
          <span className="text-[11px] text-slate-500 hidden sm:inline font-medium">
            100% harmless test cases for examiners & evaluators
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Sample 1: Clean PDF */}
          <button
            onClick={() => onSelectSample('clean-pdf')}
            disabled={isScanning}
            className="p-4 rounded-xl text-left bg-white border border-slate-200 hover:border-emerald-300 hover:shadow-card transition-all group relative"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-slate-800 group-hover:text-emerald-700 transition-colors">
                Clean Document
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                Safe
              </span>
            </div>
            <p className="text-[11px] text-slate-500 line-clamp-2 leading-relaxed">
              Standard valid PDF with normal structure and zero malicious tags.
            </p>
            <div className="flex items-center space-x-1 text-[10px] text-emerald-600 font-semibold mt-2.5 opacity-0 group-hover:opacity-100 transition-opacity">
              <span>Test clean scan</span>
              <ArrowUpRight className="w-3 h-3" />
            </div>
          </button>

          {/* Sample 2: Extension Mismatch */}
          <button
            onClick={() => onSelectSample('extension-mismatch')}
            disabled={isScanning}
            className="p-4 rounded-xl text-left bg-white border border-slate-200 hover:border-amber-300 hover:shadow-card transition-all group relative"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-slate-800 group-hover:text-amber-700 transition-colors">
                Extension Spoof
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold bg-amber-50 text-amber-800 border border-amber-200">
                High Risk
              </span>
            </div>
            <p className="text-[11px] text-slate-500 line-clamp-2 leading-relaxed">
              Named invoice.pdf but contains Windows PE binary header.
            </p>
            <div className="flex items-center space-x-1 text-[10px] text-amber-700 font-semibold mt-2.5 opacity-0 group-hover:opacity-100 transition-opacity">
              <span>Test spoof check</span>
              <ArrowUpRight className="w-3 h-3" />
            </div>
          </button>

          {/* Sample 3: EICAR Test */}
          <button
            onClick={() => onSelectSample('eicar-test')}
            disabled={isScanning}
            className="p-4 rounded-xl text-left bg-white border border-slate-200 hover:border-rose-300 hover:shadow-card transition-all group relative"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-slate-800 group-hover:text-rose-700 transition-colors">
                EICAR Antivirus
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold bg-rose-50 text-rose-800 border border-rose-200">
                Signature
              </span>
            </div>
            <p className="text-[11px] text-slate-500 line-clamp-2 leading-relaxed">
              Standard benign test string to test antivirus engine detection.
            </p>
            <div className="flex items-center space-x-1 text-[10px] text-rose-700 font-semibold mt-2.5 opacity-0 group-hover:opacity-100 transition-opacity">
              <span>Test AV signature</span>
              <ArrowUpRight className="w-3 h-3" />
            </div>
          </button>

          {/* Sample 4: Suspicious Script */}
          <button
            onClick={() => onSelectSample('suspicious-script')}
            disabled={isScanning}
            className="p-4 rounded-xl text-left bg-white border border-slate-200 hover:border-sky-300 hover:shadow-card transition-all group relative"
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-mono font-bold text-slate-800 group-hover:text-sky-700 transition-colors">
                Suspicious Script
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold bg-sky-50 text-sky-800 border border-sky-200">
                Heuristic
              </span>
            </div>
            <p className="text-[11px] text-slate-500 line-clamp-2 leading-relaxed">
              PowerShell script with LOLBin certutil download pattern & base64.
            </p>
            <div className="flex items-center space-x-1 text-[10px] text-sky-700 font-semibold mt-2.5 opacity-0 group-hover:opacity-100 transition-opacity">
              <span>Test heuristic</span>
              <ArrowUpRight className="w-3 h-3" />
            </div>
          </button>
        </div>
      </div>
    </div>
  );
}
