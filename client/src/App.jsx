import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Dropzone from './components/Dropzone';
import ScanProgress from './components/ScanProgress';
import ReportView from './components/ReportView';
import HistoryDrawer from './components/HistoryDrawer';
import PrivacyModal from './components/PrivacyModal';
import { AlertCircle, X } from 'lucide-react';

const STORAGE_KEY = 'anvesh_scan_history_v1';

export default function App() {
  const [activeReport, setActiveReport] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStageIndex, setScanStageIndex] = useState(0);
  const [currentFileMeta, setCurrentFileMeta] = useState({ name: '', size: '' });
  const [systemHealth, setSystemHealth] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [isPrivacyOpen, setIsPrivacyOpen] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);

  useEffect(() => {
    fetch('/api/health')
      .then((res) => res.json())
      .then((data) => setSystemHealth(data))
      .catch((err) => console.warn('Could not fetch system health:', err.message));

    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        setScanHistory(JSON.parse(saved));
      }
    } catch (e) {
      console.warn('Failed to parse scan history from localStorage');
    }
  }, []);

  const saveToHistory = (report) => {
    try {
      const item = {
        id: report.hashes?.sha256 || String(Date.now()),
        timestamp: report.meta?.scanTimestamp || new Date().toISOString(),
        filename: report.file?.filename,
        sizeFormatted: report.file?.sizeFormatted,
        detectedType: report.typeAnalysis?.detectedType,
        sha256: report.hashes?.sha256,
        riskLevel: report.risk?.riskLevel,
        riskScore: report.risk?.riskScore,
        reportSnapshot: report
      };

      const updated = [item, ...scanHistory.filter((h) => h.sha256 !== item.sha256)].slice(0, 30);
      setScanHistory(updated);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch (e) {
      console.warn('Could not update history in localStorage:', e);
    }
  };

  const clearHistory = () => {
    setScanHistory([]);
    localStorage.removeItem(STORAGE_KEY);
  };

  const analyzeFile = async (file) => {
    if (!file) return;

    setErrorMessage(null);
    setIsScanning(true);
    setScanStageIndex(0);
    setCurrentFileMeta({
      name: file.name,
      size: `${(file.size / (1024 * 1024)).toFixed(2)} MB`
    });

    const stageInterval = setInterval(() => {
      setScanStageIndex((prev) => (prev < 4 ? prev + 1 : prev));
    }, 600);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        body: formData
      });

      clearInterval(stageInterval);
      setScanStageIndex(5);

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.message || data.error || `Server responded with HTTP ${res.status}`);
      }

      if (data.success && data.report) {
        setTimeout(() => {
          setActiveReport(data.report);
          saveToHistory(data.report);
          setIsScanning(false);
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }, 400);
      } else {
        throw new Error('Analysis completed but did not return a valid security report.');
      }
    } catch (err) {
      clearInterval(stageInterval);
      setIsScanning(false);
      setErrorMessage(err.message || 'File analysis failed. Please try again.');
    }
  };

  const handleSelectSample = async (sampleId) => {
    setErrorMessage(null);
    try {
      const res = await fetch(`/api/samples/download/${sampleId}`);
      if (!res.ok) throw new Error('Could not download demonstration sample.');

      const blob = await res.blob();
      const contentDisposition = res.headers.get('content-disposition');
      let filename = `sample_${sampleId}`;
      if (contentDisposition) {
        const match = contentDisposition.match(/filename="?([^"]+)"?/);
        if (match && match[1]) filename = match[1];
      }

      const file = new File([blob], filename, { type: blob.type });
      analyzeFile(file);
    } catch (err) {
      setErrorMessage(`Failed to load demonstration sample: ${err.message}`);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50/70 text-slate-900 bg-grid-pattern">
      {/* Top Navigation */}
      <Navbar
        systemHealth={systemHealth}
        historyCount={scanHistory.length}
        onOpenHistory={() => setIsHistoryOpen(true)}
        onOpenPrivacy={() => setIsPrivacyOpen(true)}
        onNewScan={() => setActiveReport(null)}
        hasActiveReport={Boolean(activeReport)}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-10">
        {/* Error notification banner */}
        {errorMessage && (
          <div className="mb-6 p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-center justify-between shadow-xs animate-in fade-in">
            <div className="flex items-center space-x-2.5">
              <AlertCircle className="w-4 h-4 text-rose-600 flex-shrink-0" />
              <span className="font-medium">{errorMessage}</span>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="p-1 rounded-md hover:bg-rose-100 text-rose-600 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Dynamic Views */}
        {isScanning ? (
          <div className="py-12">
            <ScanProgress
              currentStageIndex={scanStageIndex}
              fileName={currentFileMeta.name}
              fileSize={currentFileMeta.size}
            />
          </div>
        ) : activeReport ? (
          <ReportView
            report={activeReport}
            onNewScan={() => setActiveReport(null)}
          />
        ) : (
          <Dropzone
            onFileSelected={analyzeFile}
            isScanning={isScanning}
            onSelectSample={handleSelectSample}
          />
        )}
      </main>

      {/* Modals and Drawers */}
      <HistoryDrawer
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        history={scanHistory}
        onSelectScan={(item) => {
          if (item.reportSnapshot) {
            setActiveReport(item.reportSnapshot);
          }
        }}
        onClearHistory={clearHistory}
      />

      <PrivacyModal
        isOpen={isPrivacyOpen}
        onClose={() => setIsPrivacyOpen(false)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-200/80 bg-white/70 py-6 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span className="font-medium text-slate-600">ANVESH • AI Malware Detector • v1.0.0</span>
          <span>Static malicious-file analysis & threat-risk assessment system</span>
        </div>
      </footer>
    </div>
  );
}
