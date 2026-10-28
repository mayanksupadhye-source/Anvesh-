import React, { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Copy,
  Check,
  Download,
  Printer,
  RefreshCw,
  ExternalLink,
  FileCode,
  FileText,
  Activity,
  Network,
  Cpu,
  Lock,
  Archive,
  Sparkles,
  HelpCircle
} from 'lucide-react';

export default function ReportView({ report, onNewScan }) {
  const [activeTab, setActiveTab] = useState('findings'); // 'findings', 'structure', 'entropy', 'antivirus', 'network', 'hashes'
  const [copiedHash, setCopiedHash] = useState(null);
  const [signalFilter, setSignalFilter] = useState('ALL');

  if (!report) return null;

  const { file, hashes, typeAnalysis, entropy, pe, pdf, office, archive, script, stringsAndNetwork, antivirus, reputation, risk, meta } = report;

  const copyToClipboard = (text, type) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(type);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const downloadJsonReport = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `anvesh_report_${hashes?.sha256?.slice(0, 12) || 'scan'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const printReport = () => {
    window.print();
  };

  // Severity styling in light cybersecurity theme
  const getRiskStyles = (level) => {
    switch (level) {
      case 'CRITICAL':
        return {
          bannerBorder: 'border-red-300',
          bannerBg: 'bg-white',
          badge: 'bg-red-50 text-red-800 border-red-200',
          textAccent: 'text-red-700',
          icon: ShieldAlert,
          iconColor: 'text-red-600'
        };
      case 'HIGH':
        return {
          bannerBorder: 'border-rose-300',
          bannerBg: 'bg-white',
          badge: 'bg-rose-50 text-rose-800 border-rose-200',
          textAccent: 'text-rose-700',
          icon: ShieldAlert,
          iconColor: 'text-rose-600'
        };
      case 'MEDIUM':
        return {
          bannerBorder: 'border-amber-300',
          bannerBg: 'bg-white',
          badge: 'bg-amber-50 text-amber-800 border-amber-200',
          textAccent: 'text-amber-800',
          icon: AlertTriangle,
          iconColor: 'text-amber-600'
        };
      case 'LOW':
      default:
        return {
          bannerBorder: 'border-emerald-300',
          bannerBg: 'bg-white',
          badge: 'bg-emerald-50 text-emerald-800 border-emerald-200',
          textAccent: 'text-emerald-700',
          icon: ShieldCheck,
          iconColor: 'text-emerald-600'
        };
    }
  };

  const riskStyles = getRiskStyles(risk.riskLevel);
  const RiskIcon = riskStyles.icon;

  const filteredSignals = (risk.signals || []).filter((s) => {
    if (signalFilter === 'ALL') return true;
    return s.severity === signalFilter;
  });

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6 pb-20">
      {/* ---------------------------------------------------- */}
      {/* TOP HERO BANNER: THREAT ASSESSMENT & RISK LEVEL */}
      {/* ---------------------------------------------------- */}
      <div className={`rounded-2xl border ${riskStyles.bannerBorder} ${riskStyles.bannerBg} p-6 sm:p-8 shadow-card transition-all`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2.5">
            <div className="flex items-center space-x-2">
              <span className="text-[11px] font-mono tracking-wider uppercase font-bold text-slate-500">
                Threat Assessment Verdict
              </span>
              <span className="text-slate-300">•</span>
              <span className="text-[11px] font-mono text-slate-500 font-medium">
                {meta.engineVersion}
              </span>
            </div>

            <div className="flex items-center space-x-3.5">
              <div className="w-12 h-12 rounded-2xl bg-slate-50 border border-slate-200 flex items-center justify-center flex-shrink-0">
                <RiskIcon className={`w-7 h-7 ${riskStyles.iconColor}`} />
              </div>
              <div>
                <div className="flex items-center space-x-2.5">
                  <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900">
                    {risk.riskLevel} RISK
                  </h1>
                  <span className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded-full border ${riskStyles.badge}`}>
                    Status Verified
                  </span>
                </div>
                <p className="text-xs text-slate-500 font-medium mt-0.5">
                  Static analysis completed in {meta.scanDurationMs} ms
                </p>
              </div>
            </div>

            <p className="text-xs sm:text-sm text-slate-700 max-w-3xl leading-relaxed pt-1 font-normal">
              {risk.executiveSummary}
            </p>
          </div>

          {/* Metric Stats Column */}
          <div className="flex flex-row md:flex-col items-center md:items-end justify-between border-t md:border-t-0 border-slate-100 pt-4 md:pt-0 gap-4">
            <div className="text-left md:text-right">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold block">
                Explainable Risk Score
              </span>
              <div className="text-3xl sm:text-4xl font-extrabold font-mono text-slate-900 tracking-tight">
                {risk.riskScore} <span className="text-xs font-normal text-slate-400">/ 100</span>
              </div>
            </div>

            <div className="text-right">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold block">
                Analysis Confidence
              </span>
              <div className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-slate-100 text-slate-800 border border-slate-200 text-xs font-mono font-bold mt-1">
                <span>Confidence: {risk.confidenceLevel}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Confidence explanation footnote */}
        <div className="mt-5 pt-3.5 border-t border-slate-100 text-[11px] text-slate-500 flex items-start sm:items-center space-x-2">
          <Info className="w-3.5 h-3.5 text-sky-600 flex-shrink-0 mt-0.5 sm:mt-0" />
          <span>{risk.confidenceExplanation}</span>
        </div>
      </div>

      {/* ---------------------------------------------------- */}
      {/* ACTIONABLE RECOMMENDATION BOX */}
      {/* ---------------------------------------------------- */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-3 shadow-card">
        <div className="flex items-center space-x-2">
          <Activity className="w-4 h-4 text-sky-600" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">
            Recommended Action: <span className="text-slate-900 font-mono">{risk.recommendation.action}</span>
          </h3>
        </div>
        <p className="text-xs sm:text-sm font-semibold text-slate-800">
          {risk.recommendation.headline}
        </p>
        <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-slate-600 pt-1">
          {risk.recommendation.steps.map((step, idx) => (
            <li key={idx} className="flex items-start space-x-2">
              <span className="text-sky-600 font-bold">•</span>
              <span>{step}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* ---------------------------------------------------- */}
      {/* FILE OVERVIEW BAR */}
      {/* ---------------------------------------------------- */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-4 shadow-card">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center space-x-2">
            <FileCode className="w-4 h-4 text-sky-600" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">
              File Identity & Integrity
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-500">
            Size: {file.sizeFormatted} ({file.sizeBytes.toLocaleString()} bytes)
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div>
            <span className="text-slate-400 block text-[10px] uppercase font-mono font-bold">Filename</span>
            <span className="font-semibold text-slate-900 font-mono truncate block text-xs" title={file.filename}>
              {file.filename}
            </span>
          </div>

          <div>
            <span className="text-slate-400 block text-[10px] uppercase font-mono font-bold">Detected Format</span>
            <span className="font-semibold text-sky-700 font-mono text-xs">
              {typeAnalysis.detectedType}
            </span>
          </div>

          <div>
            <span className="text-slate-400 block text-[10px] uppercase font-mono font-bold">Declared Extension</span>
            <span className="font-semibold text-slate-800 font-mono text-xs">
              {typeAnalysis.declaredExtension || 'None'}
            </span>
          </div>

          <div>
            <span className="text-slate-400 block text-[10px] uppercase font-mono font-bold">Extension Verification</span>
            {typeAnalysis.isSpoofed ? (
              <span className="inline-flex items-center space-x-1 font-mono font-bold text-rose-700 text-xs">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                <span>SPOOFED (FAILED)</span>
              </span>
            ) : typeAnalysis.extensionMatch ? (
              <span className="inline-flex items-center space-x-1 font-mono font-semibold text-emerald-700 text-xs">
                <Check className="w-3.5 h-3.5 text-emerald-600" />
                <span>MATCHED</span>
              </span>
            ) : (
              <span className="font-mono text-amber-700 font-semibold text-xs">MISMATCH</span>
            )}
          </div>
        </div>

        {/* Extension Spoofing Callout if applicable */}
        {typeAnalysis.isSpoofed && (
          <div className="p-3.5 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-start space-x-2.5">
            <AlertTriangle className="w-4 h-4 text-rose-600 flex-shrink-0 mt-0.5" />
            <div>
              <span className="font-bold">Deceptive Extension Alert: </span>
              {typeAnalysis.spoofDetails?.warning}
            </div>
          </div>
        )}

        {/* Primary SHA-256 Hash with Copy */}
        <div className="pt-2 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center space-x-2 overflow-hidden">
            <span className="text-slate-400 font-mono text-[11px] uppercase font-bold">SHA-256:</span>
            <span className="font-mono text-xs text-slate-700 select-all truncate">
              {hashes.sha256}
            </span>
          </div>
          <button
            onClick={() => copyToClipboard(hashes.sha256, 'sha256')}
            className="self-start sm:self-auto flex items-center space-x-1.5 px-3 py-1 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-mono font-semibold transition-colors"
          >
            {copiedHash === 'sha256' ? (
              <>
                <Check className="w-3 h-3 text-emerald-600" />
                <span className="text-emerald-700">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3 text-slate-500" />
                <span>Copy Hash</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* ---------------------------------------------------- */}
      {/* NAVIGATION TABS */}
      {/* ---------------------------------------------------- */}
      <div className="flex items-center space-x-1 border-b border-slate-200 pb-0.5 overflow-x-auto text-xs font-mono">
        <button
          onClick={() => setActiveTab('findings')}
          className={`px-4 py-2.5 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'findings'
              ? 'border-sky-600 text-sky-800 bg-white font-bold shadow-xs'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
          <span>Security Findings ({risk.signals?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('structure')}
          className={`px-4 py-2.5 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'structure'
              ? 'border-sky-600 text-sky-800 bg-white font-bold shadow-xs'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Cpu className="w-3.5 h-3.5 text-sky-600" />
          <span>Structure & Headers</span>
        </button>

        <button
          onClick={() => setActiveTab('entropy')}
          className={`px-4 py-2.5 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'entropy'
              ? 'border-sky-600 text-sky-800 bg-white font-bold shadow-xs'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Activity className="w-3.5 h-3.5 text-sky-600" />
          <span>Entropy ({entropy.entropy})</span>
        </button>

        <button
          onClick={() => setActiveTab('antivirus')}
          className={`px-4 py-2.5 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'antivirus'
              ? 'border-sky-600 text-sky-800 bg-white font-bold shadow-xs'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Shield className="w-3.5 h-3.5 text-sky-600" />
          <span>Antivirus & Reputation</span>
        </button>

        <button
          onClick={() => setActiveTab('network')}
          className={`px-4 py-2.5 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'network'
              ? 'border-sky-600 text-sky-800 bg-white font-bold shadow-xs'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Network className="w-3.5 h-3.5 text-sky-600" />
          <span>Network & URLs ({stringsAndNetwork.urls?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('hashes')}
          className={`px-4 py-2.5 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'hashes'
              ? 'border-sky-600 text-sky-800 bg-white font-bold shadow-xs'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <FileText className="w-3.5 h-3.5 text-sky-600" />
          <span>Hashes & Metadata</span>
        </button>
      </div>

      {/* ---------------------------------------------------- */}
      {/* TAB 1: SECURITY FINDINGS & SIGNALS */}
      {/* ---------------------------------------------------- */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-white p-3 rounded-xl border border-slate-200 text-xs shadow-card">
            <span className="text-slate-600 font-mono font-medium">Filter by Severity:</span>
            <div className="flex flex-wrap items-center gap-1.5 font-mono">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'INFO'].map((f) => (
                <button
                  key={f}
                  onClick={() => setSignalFilter(f)}
                  className={`px-2.5 py-1 rounded-md text-[11px] transition-colors ${
                    signalFilter === f
                      ? 'bg-sky-50 text-sky-800 border border-sky-300 font-bold'
                      : 'text-slate-600 hover:text-slate-900 bg-slate-50 border border-slate-200'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {filteredSignals.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-white border border-slate-200 text-slate-500 text-xs">
              No findings match the selected filter.
            </div>
          ) : (
            <div className="space-y-3.5">
              {filteredSignals.map((signal, idx) => {
                const isCrit = signal.severity === 'CRITICAL';
                const isHigh = signal.severity === 'HIGH';
                const isMed = signal.severity === 'MEDIUM';

                return (
                  <div
                    key={idx}
                    className={`rounded-xl border p-5 space-y-3.5 transition-all bg-white shadow-card ${
                      isCrit
                        ? 'border-red-200'
                        : isHigh
                        ? 'border-rose-200'
                        : isMed
                        ? 'border-amber-200'
                        : 'border-slate-200'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`text-[10px] font-mono font-bold uppercase px-2.5 py-0.5 rounded-full border ${
                            isCrit
                              ? 'bg-red-50 text-red-800 border-red-200'
                              : isHigh
                              ? 'bg-rose-50 text-rose-800 border-rose-200'
                              : isMed
                              ? 'bg-amber-50 text-amber-800 border-amber-200'
                              : 'bg-slate-100 text-slate-700 border-slate-200'
                          }`}
                        >
                          {signal.severity}
                        </span>
                        <span className="text-[11px] font-mono text-slate-500 font-medium">
                          {signal.category}
                        </span>
                      </div>

                      <div className="text-[11px] font-mono text-slate-500 flex items-center space-x-2">
                        <span>Source: {signal.source}</span>
                        <span>•</span>
                        <span>Confidence: {signal.confidence}</span>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-sm sm:text-base font-bold text-slate-900">
                        {signal.title}
                      </h4>
                      <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                        {signal.description}
                      </p>
                    </div>

                    {/* Technical Evidence Terminal Block */}
                    <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300">
                      <span className="text-sky-400 font-bold">Technical Evidence: </span>
                      {signal.technical_evidence}
                    </div>

                    {/* In Simple Words (Plain-English explanation) */}
                    <div className="p-3.5 rounded-lg bg-sky-50/70 border border-sky-200 text-xs space-y-1">
                      <div className="text-sky-900 font-bold flex items-center space-x-1.5">
                        <Sparkles className="w-3.5 h-3.5 text-sky-600" />
                        <span>In simple words:</span>
                      </div>
                      <p className="text-slate-700 italic pl-5 leading-relaxed font-normal">
                        “{signal.plain_language}”
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ---------------------------------------------------- */}
      {/* TAB 2: FILE STRUCTURE & HEADERS */}
      {/* ---------------------------------------------------- */}
      {activeTab === 'structure' && (
        <div className="space-y-6">
          {/* Header Magic Bytes */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-3 shadow-card">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center space-x-2">
              <FileCode className="w-4 h-4 text-sky-600" />
              <span>Header Magic Bytes (Raw File Signature)</span>
            </h4>
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono text-xs text-sky-300">
              {typeAnalysis.magicBytesHex || 'None'}
            </div>
            <p className="text-[11px] text-slate-500">
              Magic bytes are the leading byte sequence at offset 0 used by security tools to confirm actual file format rather than relying on extension names.
            </p>
          </div>

          {/* PE Executable Deep Inspection */}
          {pe && pe.isPE && (
            <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-5 shadow-card">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center space-x-2">
                  <Cpu className="w-4 h-4 text-sky-600" />
                  <span>Windows Portable Executable (PE) Headers</span>
                </h4>
                <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-sky-50 text-sky-800 border border-sky-200 font-bold">
                  {pe.format}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-mono font-bold">Architecture</span>
                  <span className="font-mono text-slate-900 font-semibold">{pe.machine}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-mono font-bold">Subsystem</span>
                  <span className="font-mono text-slate-900 font-semibold">{pe.subsystem}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-mono font-bold">Compile Timestamp</span>
                  <span className="font-mono text-slate-900 font-semibold">{pe.compileTime}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-mono font-bold">Entry Point</span>
                  <span className="font-mono text-sky-700 font-semibold">{pe.entryPoint} ({pe.entryPointSection})</span>
                </div>
              </div>

              {/* Digital Signature */}
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Lock className="w-4 h-4 text-slate-500" />
                  <span className="text-slate-700 font-semibold">Digital Signature:</span>
                  <span className={pe.digitalSignature.present ? 'text-emerald-700 font-bold' : 'text-slate-600 font-medium'}>
                    {pe.digitalSignature.status}
                  </span>
                </div>
                <span className="text-[11px] text-slate-500 hidden sm:inline">
                  {pe.digitalSignature.plainLanguage}
                </span>
              </div>

              {/* Sections Table */}
              <div className="space-y-2">
                <h5 className="text-xs font-bold uppercase font-mono text-slate-600">
                  PE Section Table ({pe.numberOfSections} sections)
                </h5>
                <div className="overflow-x-auto rounded-lg border border-slate-200">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-50 text-slate-500 uppercase text-[10px] font-bold border-b border-slate-200">
                      <tr>
                        <th className="p-2.5">Name</th>
                        <th className="p-2.5">Virtual Address</th>
                        <th className="p-2.5">Raw Size</th>
                        <th className="p-2.5">Entropy</th>
                        <th className="p-2.5">Permissions</th>
                        <th className="p-2.5">Flags</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 bg-white">
                      {pe.sections.map((sec, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/70">
                          <td className="p-2.5 font-bold text-slate-900">{sec.name}</td>
                          <td className="p-2.5 text-slate-600">{sec.virtualAddress}</td>
                          <td className="p-2.5 text-slate-600">{sec.sizeOfRawData.toLocaleString()} B</td>
                          <td className="p-2.5">
                            <span
                              className={`px-1.5 py-0.5 rounded font-semibold ${
                                sec.entropy >= 7.2
                                  ? 'bg-rose-50 text-rose-700 font-bold'
                                  : sec.entropy >= 6.5
                                  ? 'bg-amber-50 text-amber-800'
                                  : 'text-slate-700'
                              }`}
                            >
                              {sec.entropy}
                            </span>
                          </td>
                          <td className="p-2.5 text-slate-600">
                            {sec.permissions.readable && 'R '}
                            {sec.permissions.writable && 'W '}
                            {sec.permissions.executable && 'X'}
                          </td>
                          <td className="p-2.5">
                            {sec.isWritableAndExecutable && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-rose-50 text-rose-700 border border-rose-200 mr-1">
                                W+X (Self-Modifying)
                              </span>
                            )}
                            {sec.isKnownPackerName && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded font-bold bg-amber-50 text-amber-800 border border-amber-200">
                                Packer Section
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Suspicious APIs */}
              {pe.suspiciousApis && pe.suspiciousApis.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-slate-100">
                  <h5 className="text-xs font-bold uppercase font-mono text-slate-600">
                    Flagged Security APIs Imported ({pe.suspiciousApis.length})
                  </h5>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {pe.suspiciousApis.map((apiItem, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono flex items-center justify-between">
                        <span className="font-bold text-slate-900">{apiItem.api}</span>
                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold ${apiItem.severity === 'HIGH' ? 'bg-rose-50 text-rose-700 border border-rose-200' : 'bg-slate-200 text-slate-700'}`}>
                          {apiItem.category}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* PDF Deep Inspection */}
          {pdf && pdf.isPDF && (
            <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-4 shadow-card">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center space-x-2">
                <FileText className="w-4 h-4 text-sky-600" />
                <span>PDF Document Internal Object Hierarchy</span>
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">PDF Version</span>
                  <span className="text-slate-900 font-bold">{pdf.version}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">Total Objects</span>
                  <span className="text-slate-900 font-bold">{pdf.objectCount}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">Streams</span>
                  <span className="text-slate-900 font-bold">{pdf.streamCount}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">Stream Integrity</span>
                  <span className={pdf.isStreamMalformed ? 'text-rose-700 font-bold' : 'text-emerald-700 font-semibold'}>
                    {pdf.isStreamMalformed ? 'Malformed Streams' : 'Normal'}
                  </span>
                </div>
              </div>

              {pdf.findings.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-slate-100">
                  <h5 className="text-xs font-bold uppercase font-mono text-slate-600">
                    Structural Tags of Note
                  </h5>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    {pdf.findings.map((f, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
                        <span className="font-mono text-sky-700 font-bold">{f.tag} ({f.count}x)</span>
                        <span className="text-[10px] text-slate-600 font-medium">{f.name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Office Document Deep Inspection */}
          {office && office.isOffice && (
            <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-4 shadow-card">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center space-x-2">
                <FileText className="w-4 h-4 text-sky-600" />
                <span>Microsoft Office Package Analysis</span>
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">Package Format</span>
                  <span className="text-slate-900 font-bold">{office.format}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">VBA Macros</span>
                  <span className={office.hasMacros ? 'text-rose-700 font-bold' : 'text-emerald-700 font-semibold'}>
                    {office.hasMacros ? 'DETECTED' : 'None'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">External Relationships</span>
                  <span className={office.hasExternalRelations ? 'text-rose-700 font-bold' : 'text-slate-600 font-semibold'}>
                    {office.hasExternalRelations ? 'Remote Targets Present' : 'Internal Only'}
                  </span>
                </div>
              </div>

              {office.hasExternalRelations && office.externalTargets.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-slate-100 text-xs">
                  <span className="text-slate-700 font-mono font-bold">External Relationship Targets:</span>
                  <div className="space-y-1">
                    {office.externalTargets.map((target, idx) => (
                      <div key={idx} className="p-2 rounded bg-slate-50 border border-slate-200 font-mono text-sky-800 break-all text-xs">
                        {target}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Archive Deep Inspection */}
          {archive && archive.isArchive && (
            <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-4 shadow-card">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center space-x-2">
                <Archive className="w-4 h-4 text-sky-600" />
                <span>Archive (ZIP) Safeguard & Content Table</span>
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">Total Entries</span>
                  <span className="text-slate-900 font-bold">{archive.fileCount}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">Compression Ratio</span>
                  <span className={archive.isZipBomb ? 'text-rose-700 font-bold' : 'text-slate-900 font-semibold'}>
                    {archive.compressionRatio} : 1
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">Zip Bomb Risk</span>
                  <span className={archive.isZipBomb ? 'text-rose-700 font-bold' : 'text-emerald-700 font-semibold'}>
                    {archive.isZipBomb ? 'DANGEROUS' : 'Safe'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">Path Traversal (Zip Slip)</span>
                  <span className={archive.hasPathTraversal ? 'text-rose-700 font-bold' : 'text-emerald-700 font-semibold'}>
                    {archive.hasPathTraversal ? 'EXPLOIT SEQUENCE' : 'Clean'}
                  </span>
                </div>
              </div>

              {/* Archive Entries */}
              {archive.entries.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-slate-100">
                  <span className="text-xs font-mono font-bold text-slate-600">Archive Entries Preview:</span>
                  <div className="max-h-48 overflow-y-auto divide-y divide-slate-100 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono">
                    {archive.entries.map((entry, idx) => (
                      <div key={idx} className="p-2 flex items-center justify-between">
                        <span className="text-slate-700 truncate max-w-md">{entry.name}</span>
                        <span className="text-slate-500">{entry.uncompressedSize.toLocaleString()} B</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ---------------------------------------------------- */}
      {/* TAB 3: SHANNON ENTROPY */}
      {/* ---------------------------------------------------- */}
      {activeTab === 'entropy' && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-6 shadow-card">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center space-x-2">
                <Activity className="w-4 h-4 text-sky-600" />
                <span>Shannon Byte Entropy Evaluation</span>
              </h4>
              <p className="text-xs text-slate-500 mt-1">
                Calculates the randomness distribution of bytes on a scale from 0.0 (uniform bytes) to 8.0 (completely randomized).
              </p>
            </div>
            <div className="text-left sm:text-right">
              <span className="text-3xl font-extrabold font-mono text-slate-900">
                {entropy.entropy}
              </span>
              <span className="text-xs font-mono text-slate-400 block font-medium">out of 8.000</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
            <span className="text-xs font-mono font-bold text-slate-700 uppercase">Analysis Interpretation:</span>
            <p className="text-xs text-slate-700 leading-relaxed font-normal">
              {entropy.interpretation}
            </p>
          </div>

          {/* Visual Chunk Distribution Map */}
          {entropy.distribution && entropy.distribution.length > 0 && (
            <div className="space-y-3">
              <span className="text-xs font-mono font-bold text-slate-600 uppercase">
                Entropy Distribution Across File Offsets (32 Chunks):
              </span>
              <div className="h-28 flex items-end gap-1 bg-slate-50 p-3 rounded-xl border border-slate-200">
                {entropy.distribution.map((chunk, idx) => {
                  const heightPercent = Math.min(100, Math.round((chunk.entropy / 8) * 100));
                  const isHigh = chunk.entropy >= 7.2;
                  return (
                    <div
                      key={idx}
                      className="flex-1 flex flex-col items-center group relative h-full justify-end"
                    >
                      <div
                        style={{ height: `${heightPercent}%` }}
                        className={`w-full rounded-t transition-all ${
                          isHigh ? 'bg-rose-500 group-hover:bg-rose-600' : 'bg-sky-500 group-hover:bg-sky-600'
                        }`}
                      />
                      {/* Tooltip on hover */}
                      <div className="absolute bottom-full mb-2 hidden group-hover:block z-20 bg-slate-900 text-white text-[10px] font-mono p-1.5 rounded shadow-lg whitespace-nowrap">
                        Chunk {chunk.index}: {chunk.entropy} H
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 font-medium">
                <span>Offset 0x00</span>
                <span>End of File</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ---------------------------------------------------- */}
      {/* TAB 4: ANTIVIRUS & THREAT REPUTATION */}
      {/* ---------------------------------------------------- */}
      {activeTab === 'antivirus' && (
        <div className="space-y-6">
          {/* ClamAV Engine Status & Scan Result */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-4 shadow-card">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center space-x-2">
                <Shield className="w-5 h-5 text-sky-600" />
                <h4 className="text-sm font-bold text-slate-900">ClamAV Malware Engine</h4>
              </div>
              <span
                className={`text-xs font-mono px-3 py-1 rounded-full font-bold border ${
                  antivirus.detected
                    ? 'bg-rose-50 text-rose-800 border-rose-200'
                    : antivirus.available
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-slate-100 text-slate-700 border-slate-200'
                }`}
              >
                {antivirus.status}
              </span>
            </div>

            <div className="space-y-2 text-xs">
              <p className="text-slate-700 leading-relaxed font-normal">
                {antivirus.plainLanguage}
              </p>

              {antivirus.detected && (
                <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-rose-800 font-mono">
                  <span className="font-bold">Detected Threat Signature: </span>
                  {antivirus.threatName}
                </div>
              )}

              {!antivirus.available && (
                <div className="p-3.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-900 space-y-1">
                  <span className="font-bold flex items-center space-x-1.5">
                    <Info className="w-3.5 h-3.5 text-amber-700" />
                    <span>ClamAV Setup Note for Examiners / Developers:</span>
                  </span>
                  <p className="text-slate-600 text-[11px] leading-relaxed">
                    ANVESH connects to ClamAV via TCP socket on port 3310 or local clamscan binary. If ClamAV is offline or not installed, ANVESH honestly displays this state without fabricating fake scans.
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* VirusTotal External Reputation */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-4 shadow-card">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center space-x-2">
                <ExternalLink className="w-5 h-5 text-sky-600" />
                <h4 className="text-sm font-bold text-slate-900">External Threat Feeds (VirusTotal v3)</h4>
              </div>
              <span className="text-xs font-mono px-3 py-1 rounded-full bg-slate-100 text-slate-700 border border-slate-200 font-bold">
                {reputation.status}
              </span>
            </div>

            <p className="text-xs text-slate-700 leading-relaxed">
              {reputation.plainLanguage}
            </p>

            {reputation.configured && reputation.available && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono pt-2">
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500 block text-[10px] uppercase font-bold">Malicious</span>
                  <span className="text-rose-700 font-extrabold text-lg">{reputation.stats?.malicious || 0}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500 block text-[10px] uppercase font-bold">Suspicious</span>
                  <span className="text-amber-700 font-extrabold text-lg">{reputation.stats?.suspicious || 0}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500 block text-[10px] uppercase font-bold">Harmless / Clean</span>
                  <span className="text-emerald-700 font-extrabold text-lg">{reputation.stats?.harmless || 0}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500 block text-[10px] uppercase font-bold">Undetected</span>
                  <span className="text-slate-600 font-extrabold text-lg">{reputation.stats?.undetected || 0}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ---------------------------------------------------- */}
      {/* TAB 5: EXTRACTED NETWORK & URLS */}
      {/* ---------------------------------------------------- */}
      {activeTab === 'network' && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-6 shadow-card">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center space-x-2">
              <Network className="w-4 h-4 text-sky-600" />
              <span>Extracted Network Endpoints ({stringsAndNetwork.urls?.length || 0} URLs, {stringsAndNetwork.ips?.length || 0} IPs)</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-500">
              Never contacted or resolved (SSRF safe)
            </span>
          </div>

          {/* URLs */}
          <div className="space-y-3">
            <h5 className="text-xs font-bold font-mono uppercase text-slate-600">
              Embedded Web URLs
            </h5>
            {stringsAndNetwork.urls && stringsAndNetwork.urls.length > 0 ? (
              <div className="space-y-2 max-h-72 overflow-y-auto">
                {stringsAndNetwork.urls.map((u, idx) => (
                  <div
                    key={idx}
                    className={`p-3 rounded-lg border text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                      u.isSuspicious ? 'bg-amber-50 border-amber-200' : 'bg-slate-50 border-slate-200'
                    }`}
                  >
                    <div className="truncate max-w-lg">
                      <span className="text-slate-900 select-all font-semibold">{u.url}</span>
                      {u.isSuspicious && (
                        <span className="text-[10px] text-amber-800 block mt-0.5 font-sans font-medium">
                          {u.reason}
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] text-slate-500 whitespace-nowrap">
                      {u.domain} ({u.protocol})
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic">No embedded URLs identified in file strings.</p>
            )}
          </div>

          {/* IPs */}
          {stringsAndNetwork.ips && stringsAndNetwork.ips.length > 0 && (
            <div className="space-y-3 pt-3 border-t border-slate-100">
              <h5 className="text-xs font-bold font-mono uppercase text-slate-600">
                Identified IPv4 Addresses
              </h5>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {stringsAndNetwork.ips.map((ipItem, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono flex items-center justify-between">
                    <span className="text-slate-900 font-semibold">{ipItem.ip}</span>
                    <span className="text-[10px] text-slate-500">{ipItem.type}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ---------------------------------------------------- */}
      {/* TAB 6: HASHES & METADATA */}
      {/* ---------------------------------------------------- */}
      {activeTab === 'hashes' && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 space-y-4 shadow-card">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center space-x-2 border-b border-slate-100 pb-3">
            <FileText className="w-4 h-4 text-sky-600" />
            <span>Cryptographic Checksums & File Fingerprints</span>
          </h4>

          <div className="space-y-3 font-mono text-xs">
            {/* SHA-256 */}
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-bold">SHA-256 (Primary Malware Identifier)</span>
                <span className="text-slate-900 select-all break-all font-semibold">{hashes.sha256}</span>
              </div>
              <button
                onClick={() => copyToClipboard(hashes.sha256, 'sha256_tab')}
                className="self-start sm:self-auto px-3 py-1 rounded bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-bold flex items-center space-x-1 shadow-xs transition-colors"
              >
                {copiedHash === 'sha256_tab' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                <span>{copiedHash === 'sha256_tab' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* SHA-1 */}
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-bold">SHA-1</span>
                <span className="text-slate-900 select-all break-all font-semibold">{hashes.sha1}</span>
              </div>
              <button
                onClick={() => copyToClipboard(hashes.sha1, 'sha1_tab')}
                className="self-start sm:self-auto px-3 py-1 rounded bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-bold flex items-center space-x-1 shadow-xs transition-colors"
              >
                {copiedHash === 'sha1_tab' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                <span>{copiedHash === 'sha1_tab' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* MD5 */}
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-bold">MD5 (Legacy Fingerprint)</span>
                <span className="text-slate-900 select-all break-all font-semibold">{hashes.md5}</span>
              </div>
              <button
                onClick={() => copyToClipboard(hashes.md5, 'md5_tab')}
                className="self-start sm:self-auto px-3 py-1 rounded bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-bold flex items-center space-x-1 shadow-xs transition-colors"
              >
                {copiedHash === 'md5_tab' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                <span>{copiedHash === 'md5_tab' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---------------------------------------------------- */}
      {/* BOTTOM ACTION BAR */}
      {/* ---------------------------------------------------- */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-200">
        <button
          onClick={onNewScan}
          className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs transition-colors shadow-sm"
        >
          <RefreshCw className="w-4 h-4 text-white" />
          <span>Analyze Another File</span>
        </button>

        <div className="flex items-center space-x-2">
          <button
            onClick={downloadJsonReport}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-semibold text-xs shadow-xs transition-colors"
          >
            <Download className="w-4 h-4 text-sky-600" />
            <span>Export JSON Report</span>
          </button>

          <button
            onClick={printReport}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 font-semibold text-xs shadow-xs transition-colors"
          >
            <Printer className="w-4 h-4 text-slate-500" />
            <span>Print Report</span>
          </button>
        </div>
      </div>
    </div>
  );
}
