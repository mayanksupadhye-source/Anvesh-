import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ANVESH UI ERROR]', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-50 text-slate-900 flex items-center justify-center p-4">
          <div className="max-w-md w-full p-6 rounded-2xl bg-white border border-rose-200 shadow-elevated space-y-4 text-center">
            <div className="w-12 h-12 rounded-full bg-rose-50 border border-rose-200 flex items-center justify-center mx-auto text-rose-600">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h2 className="text-base font-bold text-slate-900">Something Went Wrong</h2>
            <p className="text-xs text-slate-500 leading-relaxed">
              An unexpected user-interface rendering error occurred while displaying the report.
            </p>
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-[11px] font-mono text-rose-700 text-left overflow-x-auto max-h-32">
              {this.state.error?.message || 'Unknown render error'}
            </div>
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.reload();
              }}
              className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs transition-colors shadow-sm"
            >
              <RefreshCw className="w-4 h-4 text-white" />
              <span>Reload Application</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
export default ErrorBoundary;
