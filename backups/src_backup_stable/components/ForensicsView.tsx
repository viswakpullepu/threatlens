import React, { useState, useEffect } from 'react';
import { 
  Microscope, 
  UploadCloud, 
  ClipboardPaste, 
  FileDown, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  ExternalLink, 
  FileText, 
  Clock, 
  Compass, 
  Database, 
  Crosshair, 
  X,
  Link as LinkIcon,
  Paperclip,
  Check,
  ChevronDown,
  RefreshCw,
  Radio,
  Mail,
  Lock,
  LogOut
} from 'lucide-react';
import { ForensicReportModal } from './ForensicReportModal';
import { parseEmailForensics } from '../engine/emailParser';

const STORAGE_KEY = 'threatlens_custom_emails_db';

export const ForensicsView: React.FC = () => {
  const [customEmails, setCustomEmails] = useState<any[]>(() => {
    try {
      const cached = localStorage.getItem(STORAGE_KEY);
      return cached ? JSON.parse(cached) : [];
    } catch (_) {
      return [];
    }
  });
  const [selectedEmail, setSelectedEmail] = useState<any>(null);
  const [activeDeepTab, setActiveDeepTab] = useState<'summary' | 'overview' | 'headers' | 'timeline' | 'iocs' | 'mitre'>('summary');
  const [isRawModalOpen, setIsRawModalOpen] = useState(false);
  const [rawEmailText, setRawEmailText] = useState('');
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [oauthStatus, setOauthStatus] = useState<{ connected: boolean; user?: any; provider?: string } | null>(null);
  const [isSyncing, setIsSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);

  const refreshEmailsFromBackend = async () => {
    try {
      const res = await fetch('/api/emails');
      const data = await res.json();
      if (data.emails && Array.isArray(data.emails)) {
        setCustomEmails(prev => {
          const combined = [...data.emails, ...prev];
          const uniqueMap = new Map();
          combined.forEach(e => { if (e && e.id) uniqueMap.set(e.id, e); });
          const merged = Array.from(uniqueMap.values());
          try { localStorage.setItem(STORAGE_KEY, JSON.stringify(merged)); } catch (_) {}
          return merged;
        });
        if (data.emails[0] && !selectedEmail) setSelectedEmail(data.emails[0]);
      }
    } catch (_) {}
  };

  const checkOAuthStatus = async () => {
    try {
      const res = await fetch('/api/auth/status');
      const data = await res.json();
      setOauthStatus(data);
    } catch (_) {}
  };

  // Sync with persistent backend database on load + check url params + listen for live intercept events
  useEffect(() => {
    refreshEmailsFromBackend();
    checkOAuthStatus();

    const handleRealtimeUpdate = (e: any) => {
      if (e.detail?.emails) {
        setCustomEmails(e.detail.emails);
        if (e.detail.newEmails && e.detail.newEmails[0]) {
          setSelectedEmail(e.detail.newEmails[0]);
          setSyncMessage(`⚡ [Live Ingest] Intercepted & analyzed "${e.detail.newEmails[0].metadata?.subject || 'New Email'}"`);
          setTimeout(() => setSyncMessage(null), 5000);
        }
      }
    };

    window.addEventListener('threatlens_emails_updated', handleRealtimeUpdate);

    // Check if returned from OAuth redirect
    const params = new URLSearchParams(window.location.search);
    if (params.get('connected') === 'gmail') {
      const user = params.get('user') || 'Gmail Inbox';
      const count = params.get('count') || '0';
      setSyncMessage(`🎉 Live Connected to ${user}! Synced & analyzed ${count} emails.`);
      window.history.replaceState({}, document.title, window.location.pathname);
      refreshEmailsFromBackend();
      checkOAuthStatus();
      setTimeout(() => setSyncMessage(null), 6000);
    }

    return () => {
      window.removeEventListener('threatlens_emails_updated', handleRealtimeUpdate);
    };
  }, []);

  const handleSyncGmail = async () => {
    setIsSyncing(true);
    try {
      const res = await fetch('/api/auth/google/sync', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        setSyncMessage(`✅ Synced ${data.count} new messages from ${data.user?.email || 'Gmail'}!`);
        await refreshEmailsFromBackend();
      } else {
        setSyncMessage(`⚠️ Sync Notice: ${data.error}`);
      }
    } catch (e) {
      setSyncMessage('⚠️ Could not connect to sync service');
    }
    setIsSyncing(false);
    setTimeout(() => setSyncMessage(null), 5000);
  };

  const handleDisconnect = async () => {
    if (!confirm('Disconnect live Gmail account?')) return;
    try {
      await fetch('/api/auth/disconnect', { method: 'POST' });
      setOauthStatus({ connected: false });
      setSyncMessage('Disconnected Gmail account');
      setTimeout(() => setSyncMessage(null), 3000);
    } catch (_) {}
  };

  const allEmails = customEmails;
  const currentEmail = selectedEmail || allEmails[0] || null;
  const isThreat = currentEmail?.isThreat || false;

  const saveAndSelectEmail = (email: any) => {
    setCustomEmails(prev => {
      const updated = [email, ...prev.filter(e => e.id !== email.id)];
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(updated)); } catch (_) {}
      return updated;
    });
    setSelectedEmail(email);
  };

  const handleClearAll = () => {
    if (!confirm('Clear all ingested and analyzed emails?')) return;
    setCustomEmails([]);
    setSelectedEmail(null);
    try { localStorage.removeItem(STORAGE_KEY); } catch (_) {}
  };

  const parseRawEmail = async (rawText: string, fileName: string = 'custom_uploaded.eml') => {
    // Try backend API first
    try {
      const res = await fetch('/api/analyze-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawEmail: rawText, fileName })
      });
      if (res.ok) {
        const data = await res.json();
        if (data.success && data.email) {
          saveAndSelectEmail(data.email);
          return;
        }
      }
    } catch (_) {
      // Backend offline: run client-side engine below
    }

    const parsedEmail = parseEmailForensics(rawText, fileName);
    saveAndSelectEmail(parsedEmail);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      parseRawEmail(text, file.name);
    };
    reader.readAsText(file);
  };

  const handleRawSubmit = () => {
    if (!rawEmailText.trim()) return;
    parseRawEmail(rawEmailText, 'pasted_email.eml');
    setIsRawModalOpen(false);
    setRawEmailText('');
  };

  return (
    <div className="space-y-6">
      
      {/* 1. SCENARIO SELECTOR & UPLOAD / OAUTH BAR */}
      <div className="space-y-3">
        {syncMessage && (
          <div className="p-3 bg-indigo-50 border border-indigo-200 text-indigo-900 rounded-xl text-xs font-bold flex items-center justify-between animate-in fade-in">
            <span>{syncMessage}</span>
            <button onClick={() => setSyncMessage(null)} className="text-indigo-600 hover:text-indigo-900">✕</button>
          </div>
        )}

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-indigo-600 text-white text-xs flex items-center justify-center font-bold">
                1
              </span>
              Ingest & Inspect Live Emails via OAuth
            </h2>
            <p className="text-xs text-slate-500">
              Connect your live Gmail inbox via OAuth2, upload .EML raw files, or paste email RFC-822 headers
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Live OAuth Connector */}
            {oauthStatus?.connected ? (
              <div className="flex items-center gap-2 bg-emerald-50 border border-emerald-200 rounded-xl px-3 py-1.5 shadow-2xs">
                <div className="flex items-center gap-1.5 text-xs text-emerald-800 font-bold">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="max-w-[140px] truncate">{oauthStatus.user?.email || 'Gmail Connected'}</span>
                </div>
                <button
                  onClick={handleSyncGmail}
                  disabled={isSyncing}
                  className="p-1 bg-white hover:bg-emerald-100 text-emerald-700 rounded-lg transition-all cursor-pointer"
                  title="Sync latest emails from Gmail inbox"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
                </button>
                <button
                  onClick={handleDisconnect}
                  className="p-1 text-slate-400 hover:text-red-600 rounded transition-colors cursor-pointer"
                  title="Disconnect account"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <a 
                href="/api/auth/google/login"
                className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold rounded-xl shadow-xs transition-all flex items-center gap-2 cursor-pointer"
                title="Connect Gmail inbox via OAuth2 (No passwords stored)"
              >
                <img src="https://www.google.com/favicon.ico" className="w-3.5 h-3.5 rounded-full" alt="Google" />
                <span>Connect Live Gmail</span>
              </a>
            )}

            <button 
              onClick={() => setIsRawModalOpen(true)}
              className="px-3 py-2 bg-white border border-slate-200 hover:border-slate-300 text-slate-700 text-xs font-bold rounded-xl shadow-2xs transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <ClipboardPaste className="w-3.5 h-3.5 text-indigo-600" />
              Paste Text
            </button>
            <label className="px-3 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-xl border border-indigo-200 transition-all flex items-center gap-1.5 cursor-pointer">
              <UploadCloud className="w-3.5 h-3.5" />
              Upload .EML
              <input type="file" accept=".eml,.msg,.txt" onChange={handleFileUpload} className="hidden" />
            </label>

            {allEmails.length > 0 && (
              <button
                onClick={handleClearAll}
                className="px-2.5 py-2 text-slate-400 hover:text-red-600 hover:bg-red-50 text-xs font-bold rounded-xl border border-transparent hover:border-red-200 transition-all cursor-pointer"
                title="Clear all analyzed emails"
              >
                Clear All
              </button>
            )}
          </div>
        </div>

        {/* Real Ingested Emails Grid */}
        {allEmails.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {allEmails.map((sample) => {
              const isSelected = currentEmail?.id === sample.id;
              const score = sample.threatScore ?? 0;
              const badgeClass = score > 80 
                ? 'bg-red-100 text-red-700' 
                : (score >= 50 ? 'bg-orange-100 text-orange-700' : 'bg-emerald-100 text-emerald-700');
              return (
                <div
                  key={sample.id}
                  onClick={() => setSelectedEmail(sample)}
                  className={`p-3.5 rounded-2xl border transition-all cursor-pointer flex flex-col justify-between ${
                    isSelected
                      ? 'bg-white border-indigo-600 ring-2 ring-indigo-500/20 shadow-sm'
                      : 'bg-white border-slate-200 hover:border-slate-300 hover:shadow-2xs'
                  }`}
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${badgeClass}`}>
                        {sample.shortBadge || (score > 80 ? '🚨 Critical' : (score >= 50 ? '⚠️ Mild' : '✅ Safe'))}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        Score: {sample.threatScore}
                      </span>
                    </div>
                    <h4 className="text-xs font-bold text-slate-900 line-clamp-2">
                      {sample.title || sample.metadata?.subject}
                    </h4>
                  </div>
                  <div className="pt-2 text-[10px] font-mono text-slate-400 border-t border-slate-100 mt-2 truncate">
                    {sample.sender?.email || 'email-source'}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="bg-white border border-dashed border-slate-300 rounded-3xl p-10 text-center shadow-xs">
            <div className="w-14 h-14 rounded-2xl bg-indigo-50 border border-indigo-200 text-indigo-600 flex items-center justify-center mx-auto mb-3 shadow-xs">
              <Microscope className="w-7 h-7" />
            </div>
            <h3 className="text-base font-bold text-slate-900 mb-1">No Live Emails Ingested Yet</h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto mb-5 leading-relaxed">
              Connect your live Gmail account via OAuth, upload an <code className="text-indigo-600 bg-indigo-50 px-1 py-0.5 rounded font-mono text-[11px]">.EML</code> file, or paste email text to inspect genuine SPF, DKIM, DMARC, IP geo-hops, and threat vectors.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-2.5">
              {oauthStatus?.connected ? (
                <button
                  onClick={handleSyncGmail}
                  disabled={isSyncing}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl shadow-xs transition-all flex items-center gap-2 cursor-pointer"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
                  Sync Messages from Gmail
                </button>
              ) : (
                <a
                  href="/api/auth/google/login"
                  className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold rounded-xl shadow-xs transition-all flex items-center gap-2 cursor-pointer"
                >
                  <img src="https://www.google.com/favicon.ico" className="w-3.5 h-3.5 rounded-full" alt="Google" />
                  Connect Live Gmail
                </a>
              )}
              <label className="px-4 py-2 bg-white border border-slate-200 hover:border-slate-300 text-slate-700 text-xs font-bold rounded-xl shadow-2xs transition-all flex items-center gap-2 cursor-pointer">
                <UploadCloud className="w-3.5 h-3.5 text-indigo-600" />
                Upload .EML
                <input type="file" accept=".eml,.msg,.txt" onChange={handleFileUpload} className="hidden" />
              </label>
              <button
                onClick={() => setIsRawModalOpen(true)}
                className="px-4 py-2 bg-white border border-slate-200 hover:border-slate-300 text-slate-700 text-xs font-bold rounded-xl shadow-2xs transition-all flex items-center gap-2 cursor-pointer"
              >
                <ClipboardPaste className="w-3.5 h-3.5 text-indigo-600" />
                Paste Raw Text
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 2. OVERALL THREAT RESULT BANNER & DETAILED SECTIONS */}
      {currentEmail && (() => {
        const score = currentEmail.threatScore ?? 0;
        const bannerBorder = score > 80 ? 'border-red-200' : (score >= 50 ? 'border-orange-200' : 'border-emerald-200');
        const badgeStyle = score > 80 
          ? 'bg-red-100 text-red-800 border border-red-300' 
          : (score >= 50 ? 'bg-orange-100 text-orange-800 border border-orange-300' : 'bg-emerald-100 text-emerald-800 border border-emerald-300');
        const dotColor = score > 80 ? 'bg-red-600 animate-pulse' : (score >= 50 ? 'bg-orange-500 animate-pulse' : 'bg-emerald-600');
        const scoreColor = score > 80 ? 'text-red-600' : (score >= 50 ? 'text-orange-600' : 'text-emerald-600');
        const label = score > 80 
          ? '🚨 CRITICAL THREAT (>80)' 
          : (score >= 50 ? '⚠️ MILD THREAT (50-80)' : '✅ 100% VERIFIED SAFE (<50)');

        return (
          <div className={`bg-white border ${bannerBorder} rounded-2xl p-6 shadow-xs relative overflow-hidden`}>
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${badgeStyle}`}>
                    <span className={`w-2.5 h-2.5 rounded-full ${dotColor} mr-2`} />
                    {label}: {currentEmail.userFriendlyCategory || 'INSPECTION'}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">Case ID: #{currentEmail.id}</span>
                  <span className="text-xs text-slate-400">|</span>
                  <span className="text-xs text-slate-500">{currentEmail.metadata?.date || 'Today'}</span>
                </div>
                <h2 className="text-2xl font-black text-slate-900 tracking-tight">
                  {currentEmail.metadata?.subject}
                </h2>
                <p className="text-xs text-slate-600 max-w-3xl leading-relaxed">
                  {currentEmail.simpleTakeaway || currentEmail.threatVerdict?.headline}
                </p>
              </div>

              <div className="flex items-center gap-4 shrink-0">
                <div className="text-right">
                  <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Threat Score</div>
                  <div className={`text-3xl font-black font-mono ${scoreColor}`}>
                    {currentEmail.threatScore}<span className="text-xs font-normal text-slate-400">/100</span>
                  </div>
                </div>

                <button 
                  onClick={() => setIsReportModalOpen(true)}
                  className="inline-flex items-center gap-2 px-5 py-3 bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold rounded-xl shadow-sm transition-all cursor-pointer"
                >
                  <FileDown className="w-4 h-4 text-indigo-400" />
                  Export Forensic PDF Report
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* 3. SENDER & RECIPIENT BREAKDOWN + SENDER SPOOFING CHECK */}
      {currentEmail && (
        <>
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
            <div className="flex items-center justify-between pb-4 border-b border-slate-100">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-indigo-600" />
                Sender Identity, Target & Spoofing Evaluation
              </h3>
              <span className={`text-xs font-bold px-3 py-1 rounded-full ${
                currentEmail.sender?.isSpoofed ? 'bg-red-100 text-red-800 border border-red-200' : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
              }`}>
                {currentEmail.sender?.isSpoofed ? '🚨 Spoofed Sender Masquerade' : '✅ Genuine Sender Verified'}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 text-xs font-mono">
              <div className="space-y-3">
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                  <span className="text-[10px] uppercase font-bold text-slate-400">Claimed Sender (From Header)</span>
                  <div className="font-bold text-slate-900 text-sm">{currentEmail.sender?.displayName}</div>
                  <div className="text-indigo-600">{currentEmail.sender?.email}</div>
                </div>

                <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                  <span className="text-[10px] uppercase font-bold text-slate-400">Envelope Return-Path / Reply-To</span>
                  <div className="text-slate-800">{currentEmail.sender?.replyTo || currentEmail.sender?.envelopeFrom}</div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                  <span className="text-[10px] uppercase font-bold text-slate-400">Origin Relay IP & Geo Coordinates</span>
                  <div className="font-bold text-slate-900">{currentEmail.sender?.originIp}</div>
                  <div className="text-slate-600">{currentEmail.sender?.location} • {currentEmail.sender?.asn}</div>
                </div>

                <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                  <span className="text-[10px] uppercase font-bold text-slate-400">Intended Target / Organization Host</span>
                  <div className="text-slate-900 font-bold">{currentEmail.recipient?.email}</div>
                  <div className="text-slate-500">{currentEmail.recipient?.department} ({currentEmail.recipient?.targetHost || 'mx1.enterprise.com'})</div>
                </div>
              </div>
            </div>
          </div>

          {/* 4. SEPARATE AUTHENTICATION BLOCKS: SPF, DKIM, AND DMARC */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-indigo-600" />
                  Email Authentication Verifications
                </h3>
                <p className="text-[11px] text-slate-500">
                  Individual forensic evaluation cards for SPF server authorization, DKIM cryptographic integrity, and DMARC alignment
                </p>
              </div>
              <span className="text-[11px] font-mono text-indigo-600 bg-indigo-50 px-2.5 py-0.5 rounded font-bold">
                RFC-822 / RFC-7489 Compliant
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* SPF Block */}
              <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900">SPF Verification</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                    currentEmail.auth?.spf?.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {currentEmail.auth?.spf?.status || 'FAIL'}
                  </span>
                </div>
                <div className="text-[11px] font-bold text-slate-700">{currentEmail.auth?.spf?.friendlyName}</div>
                <p className="text-[11px] text-slate-500 leading-relaxed">{currentEmail.auth?.spf?.explanation}</p>
                <div className="text-[11px] font-mono p-2 bg-slate-50 rounded border border-slate-200 text-slate-800">
                  {currentEmail.auth?.spf?.message}
                </div>
              </div>

              {/* DKIM Block */}
              <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900">DKIM Digital Seal</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                    currentEmail.auth?.dkim?.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {currentEmail.auth?.dkim?.status || 'FAIL'}
                  </span>
                </div>
                <div className="text-[11px] font-bold text-slate-700">{currentEmail.auth?.dkim?.friendlyName}</div>
                <p className="text-[11px] text-slate-500 leading-relaxed">{currentEmail.auth?.dkim?.explanation}</p>
                <div className="text-[11px] font-mono p-2 bg-slate-50 rounded border border-slate-200 text-slate-800">
                  {currentEmail.auth?.dkim?.message}
                </div>
              </div>

              {/* DMARC Block */}
              <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900">DMARC Policy</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                    currentEmail.auth?.dmarc?.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {currentEmail.auth?.dmarc?.status || 'FAIL'}
                  </span>
                </div>
                <div className="text-[11px] font-bold text-slate-700">{currentEmail.auth?.dmarc?.friendlyName}</div>
                <p className="text-[11px] text-slate-500 leading-relaxed">{currentEmail.auth?.dmarc?.explanation}</p>
                <div className="text-[11px] font-mono p-2 bg-slate-50 rounded border border-slate-200 text-slate-800">
                  {currentEmail.auth?.dmarc?.message}
                </div>
              </div>
            </div>
          </div>

          {/* 5. SEPARATE BLOCKS: SUSPICIOUS URLS AND ATTACHMENTS */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Suspicious URLs Block */}
            <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
                  <LinkIcon className="w-4 h-4 text-indigo-600" />
                  Extracted URLs & Domain Telemetry ({currentEmail.urls?.length || 0})
                </h3>
                <span className="text-[10px] font-mono text-slate-400">Sandbox Inspection</span>
              </div>

              {currentEmail.urls && currentEmail.urls.length > 0 ? (
                <div className="space-y-3">
                  {currentEmail.urls.map((urlObj: any, idx: number) => (
                    <div key={idx} className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1.5 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-900 break-all">{urlObj.domain}</span>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-100 text-red-700">
                          {urlObj.risk}
                        </span>
                      </div>
                      <div className="text-slate-600 break-all text-[11px]">{urlObj.url}</div>
                      <div className="text-[10px] text-slate-400 flex items-center gap-2 pt-1 border-t border-slate-200/60">
                        <span>VT: {urlObj.vtScore}</span> • <span>Age: {urlObj.domainAge}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-6 text-center text-slate-400 text-xs">
                  No outbound links found in email body.
                </div>
              )}
            </div>

            {/* Attachments Block */}
            <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
                  <Paperclip className="w-4 h-4 text-indigo-600" />
                  Email Attachments & File Hashes ({currentEmail.attachments?.length || 0})
                </h3>
                <span className="text-[10px] font-mono text-slate-400">Static / Dynamic Sandbox</span>
              </div>

              {currentEmail.attachments && currentEmail.attachments.length > 0 ? (
                <div className="space-y-3">
                  {currentEmail.attachments.map((att: any, idx: number) => (
                    <div key={idx} className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1.5 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-900">{att.name}</span>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-100 text-red-700">
                          {att.risk}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-600">{att.size} • {att.mime}</div>
                      <div className="text-[10px] text-slate-400 pt-1 border-t border-slate-200/60">
                        Behavior: {att.sandboxVerdict || 'Macro execution prohibited'}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-6 text-center text-slate-400 text-xs">
                  No file attachments included in this message.
                </div>
              )}
            </div>

          </div>

          {/* 6. DEEP TECHNICAL FORENSICS TABS */}
          <div className="bg-white border border-slate-200 rounded-2xl shadow-xs overflow-hidden">
            
            {/* Navigation Tabs */}
            <div className="flex border-b border-slate-200 px-6 bg-slate-50/50">
              <nav className="flex flex-wrap gap-4 sm:gap-6">
                {[
                  { id: 'summary', label: '📖 Case Summary & Findings' },
                  { id: 'overview', label: '🗺️ Origin & Geolocation' },
                  { id: 'headers', label: '📜 RFC822 Raw Headers' },
                  { id: 'timeline', label: '⏱️ Multi-Hop Timeline' },
                  { id: 'iocs', label: '🎯 Extracted IOCs' },
                  { id: 'mitre', label: '🛡️ MITRE ATT&CK Matrix' }
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveDeepTab(tab.id as any)}
                    className={`py-3 px-1 border-b-2 font-bold text-xs tracking-wider uppercase transition-colors cursor-pointer ${
                      activeDeepTab === tab.id
                        ? 'border-indigo-600 text-indigo-600'
                        : 'border-transparent text-slate-500 hover:text-slate-700'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </nav>
            </div>

            {/* Tab Content */}
            <div className="p-6">
              {activeDeepTab === 'summary' && (
                <div className="space-y-4">
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs">
                    <div className="font-bold text-slate-900">Summary Takeaway:</div>
                    <ul className="list-disc pl-5 space-y-1.5 text-slate-700 leading-relaxed">
                      {(currentEmail.whatHappened || []).map((h: string, idx: number) => (
                        <li key={idx}>{h}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="p-4 bg-indigo-50/50 border border-indigo-100 rounded-xl space-y-1 text-xs">
                    <span className="font-bold text-indigo-950 uppercase tracking-wider text-[10px]">SOC Response Protocol:</span>
                    <p className="text-indigo-900 font-medium">{currentEmail.whatToDo}</p>
                  </div>
                </div>
              )}

              {activeDeepTab === 'overview' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                    <div className="text-[10px] uppercase font-bold text-slate-400">Sending Infrastructure</div>
                    <div className="text-slate-900 font-bold">IP: {currentEmail.sender?.originIp}</div>
                    <div className="text-slate-600">Location: {currentEmail.sender?.location}</div>
                    <div className="text-slate-600">ASN: {currentEmail.sender?.asn}</div>
                    <div className="text-slate-600">Reverse DNS: {currentEmail.sender?.reverseDns || 'None'}</div>
                  </div>

                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                    <div className="text-[10px] uppercase font-bold text-slate-400">Target Envelope</div>
                    <div className="text-slate-900 font-bold">Recipient: {currentEmail.recipient?.email}</div>
                    <div className="text-slate-600">Department: {currentEmail.recipient?.department}</div>
                    <div className="text-slate-600">MX Host: {currentEmail.recipient?.targetHost}</div>
                  </div>
                </div>
              )}

              {activeDeepTab === 'headers' && (
                <div className="p-4 bg-slate-900 text-slate-200 rounded-xl font-mono text-xs overflow-x-auto space-y-1">
                  <div><span className="text-indigo-400">From:</span> {currentEmail.sender?.displayName} &lt;{currentEmail.sender?.email}&gt;</div>
                  <div><span className="text-indigo-400">To:</span> {currentEmail.recipient?.email}</div>
                  <div><span className="text-indigo-400">Subject:</span> {currentEmail.metadata?.subject}</div>
                  <div><span className="text-indigo-400">Date:</span> {currentEmail.metadata?.date}</div>
                  <div><span className="text-indigo-400">Message-ID:</span> {currentEmail.metadata?.messageId}</div>
                  <div><span className="text-indigo-400">User-Agent:</span> {currentEmail.metadata?.userAgent}</div>
                  <div><span className="text-indigo-400">X-Originating-IP:</span> [{currentEmail.sender?.originIp}]</div>
                  <div><span className="text-indigo-400">Authentication-Results:</span> spf={currentEmail.auth?.spf?.status.toLowerCase()} dkim={currentEmail.auth?.dkim?.status.toLowerCase()} dmarc={currentEmail.auth?.dmarc?.status.toLowerCase()}</div>
                </div>
              )}

              {activeDeepTab === 'timeline' && (
                <div className="space-y-3">
                  {(currentEmail.timeline || []).map((step: any, idx: number) => (
                    <div key={idx} className="flex items-start gap-3 p-3 bg-slate-50 border border-slate-200 rounded-xl">
                      <div className="font-mono text-xs font-bold text-indigo-600 shrink-0 w-16">{step.time}</div>
                      <div className="text-xs text-slate-800 font-medium">{step.event}</div>
                    </div>
                  ))}
                </div>
              )}

              {activeDeepTab === 'iocs' && (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono border border-slate-200 rounded-xl">
                    <thead className="bg-slate-100 text-slate-700">
                      <tr>
                        <th className="p-3 border-b border-slate-200">TYPE</th>
                        <th className="p-3 border-b border-slate-200">VALUE</th>
                        <th className="p-3 border-b border-slate-200">STATUS</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200">
                      <tr>
                        <td className="p-3 text-slate-500">Origin IP</td>
                        <td className="p-3 font-bold text-slate-900">{currentEmail.sender?.originIp}</td>
                        <td className="p-3 text-red-600 font-bold">{currentEmail.sender?.asn}</td>
                      </tr>
                      {currentEmail.hashes?.sha256 && (
                        <tr>
                          <td className="p-3 text-slate-500">SHA-256</td>
                          <td className="p-3 text-slate-700 break-all">{currentEmail.hashes.sha256}</td>
                          <td className="p-3 text-red-600 font-bold">Malicious Payload</td>
                        </tr>
                      )}
                      {currentEmail.urls?.map((u: any, idx: number) => (
                        <tr key={idx}>
                          <td className="p-3 text-slate-500">Phishing URL</td>
                          <td className="p-3 text-slate-700 break-all">{u.url}</td>
                          <td className="p-3 text-red-600 font-bold">{u.vtScore}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {activeDeepTab === 'mitre' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {(currentEmail.mitreAttack || []).map((m: any, idx: number) => (
                    <div key={idx} className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-xs text-indigo-600">{m.id}</span>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-200 text-slate-700">{m.tactic}</span>
                      </div>
                      <div className="text-xs font-bold text-slate-900">{m.name}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Forensic Report Printable Modal */}
          <ForensicReportModal 
            email={currentEmail}
            isOpen={isReportModalOpen}
            onClose={() => setIsReportModalOpen(false)}
          />
        </>
      )}

      {/* Raw Email Modal */}
      {isRawModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
          <div className="bg-white border border-slate-200 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <ClipboardPaste className="w-4 h-4 text-indigo-600" />
                Paste Email Text or Headers to Analyze
              </h3>
              <button onClick={() => setIsRawModalOpen(false)} className="text-slate-400 hover:text-slate-700 cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-500">
              Paste the text or raw headers of any suspicious email below to check for phishing links, fake senders, and scams:
            </p>

            <textarea 
              rows={8}
              value={rawEmailText}
              onChange={(e) => setRawEmailText(e.target.value)}
              placeholder="From: billing@micros0ft-alert.com&#10;Subject: Urgent Password Expiry&#10;&#10;Click here to verify: http://fake-login-link.com"
              className="w-full p-3 font-mono text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white text-slate-900"
            />

            <div className="flex items-center justify-end gap-2 pt-2">
              <button 
                onClick={() => setIsRawModalOpen(false)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button 
                onClick={handleRawSubmit}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl transition-all cursor-pointer"
              >
                Analyze This Email Now
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
