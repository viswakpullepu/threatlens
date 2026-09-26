import React, { Component, ErrorInfo, ReactNode } from 'react';
import { ShieldAlert, RefreshCw, RotateCcw, Bug } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[ThreatLens ErrorBoundary Caught Exception]:', error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (this.props.onReset) {
      this.props.onReset();
    } else {
      try {
        const keysToRemove = Object.keys(localStorage).filter(k => k.startsWith('threatlens_custom_emails_db'));
        keysToRemove.forEach(k => localStorage.removeItem(k));
      } catch (_) {}
      window.location.reload();
    }
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[480px] flex items-center justify-center p-6">
          <div className="max-w-xl w-full bg-white border border-red-200 rounded-3xl p-8 shadow-xl text-center space-y-5 animate-in fade-in zoom-in-95 duration-200">
            <div className="w-16 h-16 rounded-2xl bg-red-50 border border-red-200 text-red-600 flex items-center justify-center mx-auto shadow-xs">
              <ShieldAlert className="w-8 h-8 animate-pulse" />
            </div>

            <div className="space-y-2">
              <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-red-100 text-red-800 border border-red-200 font-mono">
                Fault Tolerance Interceptor Active
              </span>
              <h2 className="text-xl font-black text-slate-900">
                {this.props.fallbackTitle || 'Forensic View Safely Isolated'}
              </h2>
              <p className="text-xs text-slate-600 leading-relaxed max-w-md mx-auto">
                ThreatLens caught an unexpected rendering anomaly and contained it to prevent application failure. Your session and defense data remain secure.
              </p>
            </div>

            {this.state.error && (
              <div className="p-3.5 bg-slate-900 text-slate-200 rounded-xl font-mono text-[11px] text-left overflow-x-auto space-y-1">
                <div className="text-red-400 font-bold flex items-center gap-1.5">
                  <Bug className="w-3.5 h-3.5 shrink-0" />
                  <span>{this.state.error.name}: {this.state.error.message}</span>
                </div>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              <button
                onClick={this.handleReset}
                className="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl shadow-xs transition-all flex items-center gap-2 cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset View & Recover State</span>
              </button>
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2.5 bg-white border border-slate-200 hover:border-slate-300 text-slate-700 text-xs font-bold rounded-xl shadow-2xs transition-all flex items-center gap-2 cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reload Page</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
