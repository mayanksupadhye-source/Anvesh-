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
  ChevronDown,
  ChevronUp,
  FileCode,
  FileText,
  Activity,
  Network,
  Cpu,
  Lock,
  Archive,
  Terminal,
  Layers
} from 'lucide-react';

export default function ReportView({ report, onNewScan }) {
  const [activeTab, setActiveTab] = useState('findings'); // 'findings', 'structure', 'entropy', 'antivirus', 'network', 'hashes'
  const [copiedHash, setCopiedHash] = useState(null);
  const [signalFilter, setSignalFilter] = useState('ALL'); // 'ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'INFO'

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

  // Risk styling helpers
  const getRiskBadgeStyles = (level) => {
    switch (level) {
      case 'CRITICAL':
        return {
          bg: 'bg-rose-950/80 border-rose-600/80 text-rose-300',
          badge: 'bg-rose-600 text-white',
          glow: 'glow-rose'
        };
      case 'HIGH':
        return {
          bg: 'bg-rose-950/40 border-rose-500/60 text-rose-300',
          badge: 'bg-rose-500 text-white',
          glow: 'glow-rose'
        };
      case 'MEDIUM':
        return {
          bg: 'bg-amber-950/40 border-amber-500/60 text-amber-300',
          badge: 'bg-amber-500 text-white',
          glow: 'glow-amber'
        };
      case 'LOW':
      default:
        return {
          bg: 'bg-emerald-950/40 border-emerald-500/60 text-emerald-300',
          badge: 'bg-emerald-500 text-white',
          glow: 'glow-emerald'
        };
    }
  };

  const riskStyles = getRiskBadgeStyles(risk.riskLevel);

  // Filter signals
  const filteredSignals = (risk.signals || []).filter((s) => {
    if (signalFilter === 'ALL') return true;
    return s.severity === signalFilter;
  });

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6 pb-16">
      {/* ---------------------------------------------------- */}
      {/* TOP HERO BANNER: RISK CLASSIFICATION & CONFIDENCE */}
      {/* ---------------------------------------------------- */}
      <div className={`rounded-2xl border p-6 sm:p-8 backdrop-blur-xl transition-all ${riskStyles.bg} ${riskStyles.glow}`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <span className="text-[11px] font-mono tracking-widest uppercase text-slate-400">
                ANVESH THREAT ASSESSMENT
              </span>
              <span className="text-slate-600">•</span>
              <span className="text-[11px] font-mono text-slate-400">
                {meta.engineVersion}
              </span>
            </div>

            <div className="flex items-center space-x-3">
              {risk.riskLevel === 'CRITICAL' || risk.riskLevel === 'HIGH' ? (
                <ShieldAlert className="w-9 h-9 text-rose-400 flex-shrink-0" />
              ) : risk.riskLevel === 'MEDIUM' ? (
                <AlertTriangle className="w-9 h-9 text-amber-400 flex-shrink-0" />
              ) : (
                <ShieldCheck className="w-9 h-9 text-emerald-400 flex-shrink-0" />
              )}
              <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
                {risk.riskLevel} RISK
              </h1>
            </div>

            <p className="text-sm text-slate-300 max-w-2xl leading-relaxed pt-1">
              {risk.executiveSummary}
            </p>
          </div>

          {/* Metrics Column: Score & Confidence */}
          <div className="flex flex-row md:flex-col items-center md:items-end justify-between border-t md:border-t-0 border-white/10 pt-4 md:pt-0 gap-4">
            <div className="text-left md:text-right">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                Explainable Risk Score
              </span>
              <div className="text-3xl sm:text-4xl font-black font-mono text-white">
                {risk.riskScore} <span className="text-sm font-normal text-slate-400">/ 100</span>
              </div>
            </div>

            <div className="text-right">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                Analysis Confidence
              </span>
              <div className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-cyber-surface border border-cyber-border text-xs font-mono font-bold text-cyan-300 mt-1">
                <span>Confidence: {risk.confidenceLevel}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Confidence explanation footnote */}
        <div className="mt-4 pt-3 border-t border-white/10 text-[11px] text-slate-400 flex items-center space-x-2">
          <Info className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
          <span>{risk.confidenceExplanation}</span>
        </div>
      </div>

      {/* ---------------------------------------------------- */}
      {/* ACTIONABLE RECOMMENDATION BOX */}
      {/* ---------------------------------------------------- */}
      <div className="rounded-xl border border-cyber-border bg-cyber-surface p-5 space-y-3">
        <div className="flex items-center space-x-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Recommended Action: <span className="text-white font-mono">{risk.recommendation.action}</span>
          </h3>
        </div>
        <p className="text-sm font-semibold text-slate-200">
          {risk.recommendation.headline}
        </p>
        <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-slate-400 pt-1">
          {risk.recommendation.steps.map((step, idx) => (
            <li key={idx} className="flex items-start space-x-2">
              <span className="text-cyan-400 font-bold">•</span>
              <span>{step}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* ---------------------------------------------------- */}
      {/* FILE OVERVIEW BAR */}
      {/* ---------------------------------------------------- */}
      <div className="rounded-xl border border-cyber-border bg-cyber-surface p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
          <div className="flex items-center space-x-2">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              File Identity & Integrity Verification
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Analyzed in {meta.scanDurationMs} ms
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div>
            <span className="text-slate-500 block text-[11px] uppercase font-mono">Filename</span>
            <span className="font-semibold text-white font-mono truncate block" title={file.filename}>
              {file.filename}
            </span>
          </div>

          <div>
            <span className="text-slate-500 block text-[11px] uppercase font-mono">File Size</span>
            <span className="font-semibold text-white font-mono">
              {file.sizeFormatted} ({file.sizeBytes.toLocaleString()} bytes)
            </span>
          </div>

          <div>
            <span className="text-slate-500 block text-[11px] uppercase font-mono">Detected Format</span>
            <span className="font-semibold text-cyan-300 font-mono">
              {typeAnalysis.detectedType}
            </span>
          </div>

          <div>
            <span className="text-slate-500 block text-[11px] uppercase font-mono">Extension Match</span>
            {typeAnalysis.isSpoofed ? (
              <span className="inline-flex items-center space-x-1 font-mono font-bold text-rose-400">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>SPOOFED (FAILED)</span>
              </span>
            ) : typeAnalysis.extensionMatch ? (
              <span className="inline-flex items-center space-x-1 font-mono text-emerald-400">
                <Check className="w-3.5 h-3.5" />
                <span>MATCHED</span>
              </span>
            ) : (
              <span className="font-mono text-amber-400">MISMATCH</span>
            )}
          </div>
        </div>

        {/* Extension Spoofing Callout if applicable */}
        {typeAnalysis.isSpoofed && (
          <div className="p-3.5 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs text-rose-200 flex items-start space-x-2.5">
            <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
            <div>
              <span className="font-bold">Deceptive File Extension Warning: </span>
              {typeAnalysis.spoofDetails?.warning}
            </div>
          </div>
        )}

        {/* Primary SHA-256 Hash with Copy */}
        <div className="pt-2 border-t border-cyber-border/70 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center space-x-2 overflow-hidden">
            <span className="text-slate-400 font-mono text-[11px] uppercase">SHA-256:</span>
            <span className="font-mono text-xs text-slate-200 select-all truncate">
              {hashes.sha256}
            </span>
          </div>
          <button
            onClick={() => copyToClipboard(hashes.sha256, 'sha256')}
            className="self-start sm:self-auto flex items-center space-x-1.5 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition-colors"
          >
            {copiedHash === 'sha256' ? (
              <>
                <Check className="w-3 h-3 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Copy Hash</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* ---------------------------------------------------- */}
      {/* NAVIGATION TABS */}
      {/* ---------------------------------------------------- */}
      <div className="flex items-center space-x-2 border-b border-cyber-border pb-1 overflow-x-auto text-xs font-mono">
        <button
          onClick={() => setActiveTab('findings')}
          className={`px-4 py-2 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'findings'
              ? 'border-cyan-400 text-cyan-300 bg-cyber-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>Security Findings ({risk.signals?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('structure')}
          className={`px-4 py-2 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'structure'
              ? 'border-cyan-400 text-cyan-300 bg-cyber-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>File Structure & Headers</span>
        </button>

        <button
          onClick={() => setActiveTab('entropy')}
          className={`px-4 py-2 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'entropy'
              ? 'border-cyan-400 text-cyan-300 bg-cyber-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Entropy ({entropy.entropy})</span>
        </button>

        <button
          onClick={() => setActiveTab('antivirus')}
          className={`px-4 py-2 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'antivirus'
              ? 'border-cyan-400 text-cyan-300 bg-cyber-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Antivirus & Reputation</span>
        </button>

        <button
          onClick={() => setActiveTab('network')}
          className={`px-4 py-2 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'network'
              ? 'border-cyan-400 text-cyan-300 bg-cyber-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Network & URLs ({stringsAndNetwork.urls?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('hashes')}
          className={`px-4 py-2 rounded-t-lg transition-colors border-b-2 font-medium flex items-center space-x-2 whitespace-nowrap ${
            activeTab === 'hashes'
              ? 'border-cyan-400 text-cyan-300 bg-cyber-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>Hashes & Metadata</span>
        </button>
      </div>

      {/* ---------------------------------------------------- */}
      {/* TAB 1: SECURITY FINDINGS & SIGNALS */}
      {/* ---------------------------------------------------- */}
      {activeTab === 'findings' && (
        <div className="space-y-4">
          {/* Signal Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-cyber-surface p-3 rounded-xl border border-cyber-border text-xs">
            <span className="text-slate-400 font-mono">Filter by Severity:</span>
            <div className="flex flex-wrap items-center gap-1.5 font-mono">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'INFO'].map((f) => (
                <button
                  key={f}
                  onClick={() => setSignalFilter(f)}
                  className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                    signalFilter === f
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                      : 'text-slate-400 hover:text-slate-200 bg-slate-800/50'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {filteredSignals.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-cyber-surface border border-cyber-border text-slate-400 text-sm">
              No findings match the selected filter.
            </div>
          ) : (
            <div className="space-y-3">
              {filteredSignals.map((signal, idx) => {
                const isCrit = signal.severity === 'CRITICAL';
                const isHigh = signal.severity === 'HIGH';
                const isMed = signal.severity === 'MEDIUM';
                const isInfo = signal.severity === 'INFO';

                return (
                  <div
                    key={idx}
                    className={`rounded-xl border p-5 space-y-3 transition-colors ${
                      isCrit
                        ? 'bg-rose-950/20 border-rose-800/60'
                        : isHigh
                        ? 'bg-rose-950/10 border-rose-700/40'
                        : isMed
                        ? 'bg-amber-950/10 border-amber-700/40'
                        : 'bg-cyber-surface border-cyber-border'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                            isCrit
                              ? 'bg-rose-600 text-white'
                              : isHigh
                              ? 'bg-rose-500 text-white'
                              : isMed
                              ? 'bg-amber-500 text-black'
                              : 'bg-slate-700 text-slate-300'
                          }`}
                        >
                          {signal.severity}
                        </span>
                        <span className="text-[11px] font-mono text-slate-400">
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
                      <h4 className="text-base font-bold text-white">
                        {signal.title}
                      </h4>
                      <p className="text-xs text-slate-400 mt-1">
                        {signal.description}
                      </p>
                    </div>

                    {/* Technical Evidence */}
                    <div className="p-2.5 rounded bg-black/40 border border-slate-800 text-[11px] font-mono text-slate-300">
                      <span className="text-cyan-400 font-bold">Evidence: </span>
                      {signal.technical_evidence}
                    </div>

                    {/* In Simple Words (Plain-English explanation) */}
                    <div className="p-3 rounded-lg bg-cyan-950/20 border border-cyan-800/30 text-xs space-y-1">
                      <div className="text-cyan-400 font-bold flex items-center space-x-1.5">
                        <Info className="w-3.5 h-3.5" />
                        <span>In simple words:</span>
                      </div>
                      <p className="text-slate-300 italic pl-5 leading-relaxed">
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
          {/* Magic bytes inspection */}
          <div className="rounded-xl border border-cyber-border bg-cyber-surface p-5 space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span>Header Magic Bytes (Raw Signature)</span>
            </h4>
            <div className="p-3 rounded bg-black/50 border border-slate-800 font-mono text-xs text-cyan-300">
              {typeAnalysis.magicBytesHex || 'None'}
            </div>
            <p className="text-[11px] text-slate-400">
              Magic bytes are the leading byte sequence at offset 0 used by operating systems and security engines to verify true file format.
            </p>
          </div>

          {/* PE Executable Deep Inspection */}
          {pe && pe.isPE && (
            <div className="rounded-xl border border-cyber-border bg-cyber-surface p-5 space-y-5">
              <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  <span>Windows Portable Executable (PE) Headers</span>
                </h4>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {pe.format}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                <div>
                  <span className="text-slate-500 block text-[11px] font-mono">Architecture</span>
                  <span className="font-mono text-white font-semibold">{pe.machine}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px] font-mono">Subsystem</span>
                  <span className="font-mono text-white font-semibold">{pe.subsystem}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px] font-mono">Compile Timestamp</span>
                  <span className="font-mono text-white font-semibold">{pe.compileTime}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px] font-mono">Entry Point</span>
                  <span className="font-mono text-cyan-300 font-semibold">{pe.entryPoint} ({pe.entryPointSection})</span>
                </div>
              </div>

              {/* Digital Signature */}
              <div className="p-3 rounded bg-slate-900/60 border border-slate-800 text-xs flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Lock className="w-4 h-4 text-slate-400" />
                  <span className="text-slate-300 font-semibold">Digital Signature:</span>
                  <span className={pe.digitalSignature.present ? 'text-emerald-400 font-bold' : 'text-slate-400'}>
                    {pe.digitalSignature.status}
                  </span>
                </div>
                <span className="text-[11px] text-slate-400 hidden sm:inline">
                  {pe.digitalSignature.plainLanguage}
                </span>
              </div>

              {/* Sections Table */}
              <div className="space-y-2">
                <h5 className="text-xs font-bold uppercase font-mono text-slate-400">
                  PE Section Table ({pe.numberOfSections} sections)
                </h5>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px]">
                      <tr>
                        <th className="p-2.5">Name</th>
                        <th className="p-2.5">Virtual Address</th>
                        <th className="p-2.5">Raw Size</th>
                        <th className="p-2.5">Entropy</th>
                        <th className="p-2.5">Permissions</th>
                        <th className="p-2.5">Flags</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {pe.sections.map((sec, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30">
                          <td className="p-2.5 font-bold text-white">{sec.name}</td>
                          <td className="p-2.5 text-slate-400">{sec.virtualAddress}</td>
                          <td className="p-2.5 text-slate-300">{sec.sizeOfRawData.toLocaleString()} B</td>
                          <td className="p-2.5">
                            <span
                              className={`px-1.5 py-0.5 rounded ${
                                sec.entropy >= 7.2
                                  ? 'bg-rose-950 text-rose-300 font-bold'
                                  : sec.entropy >= 6.5
                                  ? 'bg-amber-950 text-amber-300'
                                  : 'text-slate-300'
                              }`}
                            >
                              {sec.entropy}
                            </span>
                          </td>
                          <td className="p-2.5 text-slate-300">
                            {sec.permissions.readable && 'R '}
                            {sec.permissions.writable && 'W '}
                            {sec.permissions.executable && 'X'}
                          </td>
                          <td className="p-2.5">
                            {sec.isWritableAndExecutable && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800 mr-1">
                                W+X (Self-Modifying)
                              </span>
                            )}
                            {sec.isKnownPackerName && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800">
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
                <div className="space-y-2 pt-2 border-t border-cyber-border/70">
                  <h5 className="text-xs font-bold uppercase font-mono text-slate-400">
                    Flagged Security APIs Imported ({pe.suspiciousApis.length})
                  </h5>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {pe.suspiciousApis.map((apiItem, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-slate-900/40 border border-slate-800 text-xs font-mono flex items-center justify-between">
                        <span className="font-bold text-white">{apiItem.api}</span>
                        <span className={`text-[10px] px-1.5 py-0.2 rounded ${apiItem.severity === 'HIGH' ? 'bg-rose-950 text-rose-300' : 'bg-slate-800 text-slate-400'}`}>
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
            <div className="rounded-xl border border-cyber-border bg-cyber-surface p-5 space-y-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span>PDF Document Internal Object Hierarchy</span>
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block text-[11px]">PDF Version</span>
                  <span className="text-white font-bold">{pdf.version}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Total Objects</span>
                  <span className="text-white font-bold">{pdf.objectCount}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Streams</span>
                  <span className="text-white font-bold">{pdf.streamCount}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Stream Integrity</span>
                  <span className={pdf.isStreamMalformed ? 'text-rose-400' : 'text-emerald-400'}>
                    {pdf.isStreamMalformed ? 'Malformed Streams' : 'Normal'}
                  </span>
                </div>
              </div>

              {pdf.findings.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-cyber-border/70">
                  <h5 className="text-xs font-bold uppercase font-mono text-slate-400">
                    Structural Tags of Note
                  </h5>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    {pdf.findings.map((f, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-slate-900/50 border border-slate-800 flex items-center justify-between">
                        <span className="font-mono text-cyan-300 font-bold">{f.tag} ({f.count}x)</span>
                        <span className="text-[10px] text-slate-400">{f.name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Office Document Deep Inspection */}
          {office && office.isOffice && (
            <div className="rounded-xl border border-cyber-border bg-cyber-surface p-5 space-y-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span>Microsoft Office Package Analysis</span>
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block text-[11px]">Package Format</span>
                  <span className="text-white font-bold">{office.format}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">VBA Macros</span>
                  <span className={office.hasMacros ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                    {office.hasMacros ? 'DETECTED' : 'None'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">External Relationships</span>
                  <span className={office.hasExternalRelations ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                    {office.hasExternalRelations ? 'Remote Targets Present' : 'Internal Only'}
                  </span>
                </div>
              </div>

              {office.hasExternalRelations && office.externalTargets.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-cyber-border/70 text-xs">
                  <span className="text-slate-400 font-mono font-bold">External Relationship Targets:</span>
                  <div className="space-y-1">
                    {office.externalTargets.map((target, idx) => (
                      <div key={idx} className="p-2 rounded bg-black/40 border border-slate-800 font-mono text-cyan-300 break-all">
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
            <div className="rounded-xl border border-cyber-border bg-cyber-surface p-5 space-y-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                <Archive className="w-4 h-4 text-cyan-400" />
                <span>Archive (ZIP) Safeguard & Content Table</span>
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block text-[11px]">Total Entries</span>
                  <span className="text-white font-bold">{archive.fileCount}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Compression Ratio</span>
                  <span className={archive.isZipBomb ? 'text-rose-400 font-bold' : 'text-white'}>
                    {archive.compressionRatio} : 1
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Zip Bomb Risk</span>
                  <span className={archive.isZipBomb ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                    {archive.isZipBomb ? 'DANGEROUS' : 'Safe'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Path Traversal (Zip Slip)</span>
                  <span className={archive.hasPathTraversal ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                    {archive.hasPathTraversal ? 'EXPLOIT SEQUENCE' : 'Clean'}
                  </span>
                </div>
              </div>

              {/* Archive Entries */}
              {archive.entries.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-cyber-border/70">
                  <span className="text-xs font-mono font-bold text-slate-400">Archive Entries Preview:</span>
                  <div className="max-h-48 overflow-y-auto divide-y divide-slate-800 rounded bg-slate-900/40 border border-slate-800 text-xs font-mono">
                    {archive.entries.map((entry, idx) => (
                      <div key={idx} className="p-2 flex items-center justify-between">
                        <span className="text-slate-300 truncate max-w-md">{entry.name}</span>
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
        <div className="rounded-xl border border-cyber-border bg-cyber-surface p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border/70 pb-4">
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span>Shannon Byte Entropy Evaluation</span>
              </h4>
              <p className="text-xs text-slate-400 mt-1">
                Calculates the density of randomness across 256 byte states on a scale from 0.0 (all bytes identical) to 8.0 (completely random).
              </p>
            </div>
            <div className="text-left sm:text-right">
              <span className="text-3xl font-black font-mono text-cyan-400">
                {entropy.entropy}
              </span>
              <span className="text-xs font-mono text-slate-400 block">out of 8.000</span>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <span className="text-xs font-mono font-bold text-cyan-300 uppercase">Analysis Interpretation:</span>
            <p className="text-xs text-slate-300 leading-relaxed">
              {entropy.interpretation}
            </p>
          </div>

          {/* Visual Chunk Distribution Map */}
          {entropy.distribution && entropy.distribution.length > 0 && (
            <div className="space-y-3">
              <span className="text-xs font-mono font-bold text-slate-400 uppercase">
                Entropy Distribution Across File Offsets (32 Chunks):
              </span>
              <div className="h-28 flex items-end gap-1 bg-black/40 p-3 rounded-xl border border-slate-800">
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
                          isHigh ? 'bg-rose-500 group-hover:bg-rose-400' : 'bg-cyan-500/80 group-hover:bg-cyan-400'
                        }`}
                      />
                      {/* Tooltip on hover */}
                      <div className="absolute bottom-full mb-2 hidden group-hover:block z-20 bg-slate-900 border border-slate-700 text-[10px] font-mono text-white p-1.5 rounded shadow-lg whitespace-nowrap">
                        Chunk {chunk.index}: {chunk.entropy} H
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
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
          <div className="rounded-xl border border-cyber-border bg-cyber-surface p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
              <div className="flex items-center space-x-2">
                <Shield className="w-5 h-5 text-cyan-400" />
                <h4 className="text-sm font-bold text-white">ClamAV Malware Engine</h4>
              </div>
              <span
                className={`text-xs font-mono px-2.5 py-1 rounded-full font-bold ${
                  antivirus.detected
                    ? 'bg-rose-950 text-rose-300 border border-rose-800'
                    : antivirus.available
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                {antivirus.status}
              </span>
            </div>

            <div className="space-y-2 text-xs">
              <p className="text-slate-300 leading-relaxed">
                {antivirus.plainLanguage}
              </p>

              {antivirus.detected && (
                <div className="p-3 rounded bg-rose-950/40 border border-rose-800 text-rose-200 font-mono">
                  <span className="font-bold">Detected Threat Signature: </span>
                  {antivirus.threatName}
                </div>
              )}

              {!antivirus.available && (
                <div className="p-3.5 rounded bg-amber-950/20 border border-amber-800/40 text-amber-200 space-y-1">
                  <span className="font-bold flex items-center space-x-1.5">
                    <Info className="w-3.5 h-3.5" />
                    <span>ClamAV Setup Note for Examiners / Developers:</span>
                  </span>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    ANVESH is configured to connect to ClamAV via TCP socket on port 3310 or local clamscan binary. If ClamAV is offline or not installed, ANVESH honestly displays this state without fabricating fake scans.
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* VirusTotal External Reputation */}
          <div className="rounded-xl border border-cyber-border bg-cyber-surface p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
              <div className="flex items-center space-x-2">
                <ExternalLink className="w-5 h-5 text-cyan-400" />
                <h4 className="text-sm font-bold text-white">External Public Threat Feeds (VirusTotal v3)</h4>
              </div>
              <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 text-slate-300 font-semibold">
                {reputation.status}
              </span>
            </div>

            <p className="text-xs text-slate-300">
              {reputation.plainLanguage}
            </p>

            {reputation.configured && reputation.available && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono pt-2">
                <div className="p-2.5 rounded bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Malicious</span>
                  <span className="text-rose-400 font-bold text-base">{reputation.stats?.malicious || 0}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Suspicious</span>
                  <span className="text-amber-400 font-bold text-base">{reputation.stats?.suspicious || 0}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Harmless / Clean</span>
                  <span className="text-emerald-400 font-bold text-base">{reputation.stats?.harmless || 0}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Undetected</span>
                  <span className="text-slate-400 font-bold text-base">{reputation.stats?.undetected || 0}</span>
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
        <div className="rounded-xl border border-cyber-border bg-cyber-surface p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-cyber-border/70 pb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
              <Network className="w-4 h-4 text-cyan-400" />
              <span>Extracted Network Endpoints ({stringsAndNetwork.urls?.length || 0} URLs, {stringsAndNetwork.ips?.length || 0} IPs)</span>
            </h4>
            <span className="text-[11px] font-mono text-slate-500">
              Never contacted or resolved (SSRF safe)
            </span>
          </div>

          {/* URLs */}
          <div className="space-y-3">
            <h5 className="text-xs font-bold font-mono uppercase text-slate-400">
              Embedded Web URLs
            </h5>
            {stringsAndNetwork.urls && stringsAndNetwork.urls.length > 0 ? (
              <div className="space-y-2 max-h-72 overflow-y-auto">
                {stringsAndNetwork.urls.map((u, idx) => (
                  <div
                    key={idx}
                    className={`p-3 rounded-lg border text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                      u.isSuspicious ? 'bg-amber-950/20 border-amber-800/50' : 'bg-slate-900/40 border-slate-800'
                    }`}
                  >
                    <div className="truncate max-w-lg">
                      <span className="text-slate-200 select-all font-semibold">{u.url}</span>
                      {u.isSuspicious && (
                        <span className="text-[10px] text-amber-400 block mt-0.5">
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
            <div className="space-y-3 pt-3 border-t border-cyber-border/70">
              <h5 className="text-xs font-bold font-mono uppercase text-slate-400">
                Identified IPv4 Addresses
              </h5>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {stringsAndNetwork.ips.map((ipItem, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-slate-900/40 border border-slate-800 text-xs font-mono flex items-center justify-between">
                    <span className="text-white font-semibold">{ipItem.ip}</span>
                    <span className="text-[10px] text-slate-400">{ipItem.type}</span>
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
        <div className="rounded-xl border border-cyber-border bg-cyber-surface p-6 space-y-4">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center space-x-2 border-b border-cyber-border/70 pb-3">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span>Cryptographic Checksums & File Fingerprints</span>
          </h4>

          <div className="space-y-3 font-mono text-xs">
            {/* SHA-256 */}
            <div className="p-3 rounded bg-slate-900/50 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-bold">SHA-256 (Primary)</span>
                <span className="text-slate-200 select-all break-all">{hashes.sha256}</span>
              </div>
              <button
                onClick={() => copyToClipboard(hashes.sha256, 'sha256_tab')}
                className="self-start sm:self-auto px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] flex items-center space-x-1"
              >
                {copiedHash === 'sha256_tab' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedHash === 'sha256_tab' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* SHA-1 */}
            <div className="p-3 rounded bg-slate-900/50 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-bold">SHA-1</span>
                <span className="text-slate-200 select-all break-all">{hashes.sha1}</span>
              </div>
              <button
                onClick={() => copyToClipboard(hashes.sha1, 'sha1_tab')}
                className="self-start sm:self-auto px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] flex items-center space-x-1"
              >
                {copiedHash === 'sha1_tab' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedHash === 'sha1_tab' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* MD5 */}
            <div className="p-3 rounded bg-slate-900/50 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-bold">MD5 (Legacy)</span>
                <span className="text-slate-200 select-all break-all">{hashes.md5}</span>
              </div>
              <button
                onClick={() => copyToClipboard(hashes.md5, 'md5_tab')}
                className="self-start sm:self-auto px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] flex items-center space-x-1"
              >
                {copiedHash === 'md5_tab' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedHash === 'md5_tab' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---------------------------------------------------- */}
      {/* BOTTOM ACTION BAR */}
      {/* ---------------------------------------------------- */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-cyber-border">
        <button
          onClick={onNewScan}
          className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs transition-colors shadow-lg shadow-cyan-600/20"
        >
          <RefreshCw className="w-4 h-4" />
          <span>Analyze Another File</span>
        </button>

        <div className="flex items-center space-x-2">
          <button
            onClick={downloadJsonReport}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-cyber-surface hover:bg-cyber-surfaceHover border border-cyber-border text-slate-300 hover:text-white font-medium text-xs transition-colors"
          >
            <Download className="w-4 h-4 text-cyan-400" />
            <span>Export JSON Report</span>
          </button>

          <button
            onClick={printReport}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-cyber-surface hover:bg-cyber-surfaceHover border border-cyber-border text-slate-300 hover:text-white font-medium text-xs transition-colors"
          >
            <Printer className="w-4 h-4 text-slate-400" />
            <span>Print Report</span>
          </button>
        </div>
      </div>
    </div>
  );
}
