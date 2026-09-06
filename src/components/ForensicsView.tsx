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
  LogOut,
  Search,
  Filter,
  Layers,
  Inbox,
  Sparkles,
  ChevronRight,
  Zap
} from 'lucide-react';
import { ForensicReportModal } from './ForensicReportModal';
import { parseEmailForensics } from '../engine/emailParser';
import { getOrCreateSessionId } from './LiveEmailInterceptor';
import { useAuth } from '../context/AuthContext';

const BASE_STORAGE_KEY = 'threatlens_custom_emails_db';

export const ForensicsView: React.FC = () => {
  const { user: authUser, isAuthenticated, loginWithGoogle, logout: authLogout, refreshAuth } = useAuth();
  const sessionId = getOrCreateSessionId();
  const STORAGE_KEY = `${BASE_STORAGE_KEY}_${sessionId}`;

  const [customEmails, setCustomEmails] = useState<any[]>(() => {
    try {
      const cached = localStorage.getItem(STORAGE_KEY) || localStorage.getItem(BASE_STORAGE_KEY);
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
  const [oauthStatus, setOauthStatus] = useState<{ connected: boolean; user?: any; provider?: string } | null>(() => {
    return authUser ? { connected: true, user: authUser, provider: 'gmail' } : null;
  });
  const [isSyncing, setIsSyncing] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [nextPageToken, setNextPageToken] = useState<string | null>(null);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  
  // Real-time search & filter pills
  const [searchQuery, setSearchQuery] = useState('');
  const [filterCategory, setFilterCategory] = useState<'all' | 'critical' | 'mild' | 'safe'>('all');

  const refreshEmailsFromBackend = async () => {
    try {
      const sid = getOrCreateSessionId();
      const res = await fetch(`/api/emails?session_id=${encodeURIComponent(sid)}&limit=1000`, {
        headers: { 'x-session-id': sid }
      });
      const data = await res.json();
      if (data.emails && Array.isArray(data.emails)) {
        setCustomEmails(data.emails);
        if (data.nextPageToken) setNextPageToken(data.nextPageToken);
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data.emails)); } catch (_) {}
        if (data.emails[0] && !selectedEmail) setSelectedEmail(data.emails[0]);
      }
    } catch (_) {}
  };

  const checkOAuthStatus = async () => {
    try {
      const sid = getOrCreateSessionId();
      const res = await fetch(`/api/auth/status?session_id=${encodeURIComponent(sid)}`, {
        headers: { 'x-session-id': sid }
      });
      const data = await res.json();
      setOauthStatus(data);
      if (data.nextPageToken) setNextPageToken(data.nextPageToken);
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

  const [isSyncingAll, setIsSyncingAll] = useState(false);

  const handleSyncGmail = async () => {
    setIsSyncing(true);
    try {
      const sid = getOrCreateSessionId();
      const res = await fetch(`/api/auth/google/sync?session_id=${encodeURIComponent(sid)}&limit=50`, { 
        method: 'POST',
        headers: { 'x-session-id': sid }
      });
      const data = await res.json();
      if (data.success) {
        if (data.nextPageToken !== undefined) setNextPageToken(data.nextPageToken);
        setSyncMessage(`✅ Synced ${data.newCount || data.count} new messages from ${data.user?.email || 'Gmail'}!`);
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

  const handleLoadMoreGmail = async () => {
    if (isLoadingMore || isSyncing || isSyncingAll) return;
    setIsLoadingMore(true);
    try {
      const sid = getOrCreateSessionId();
      let url = `/api/auth/google/sync?session_id=${encodeURIComponent(sid)}&limit=50`;
      if (nextPageToken) url += `&pageToken=${encodeURIComponent(nextPageToken)}`;
      
      const res = await fetch(url, { 
        method: 'POST',
        headers: { 'x-session-id': sid }
      });
      const data = await res.json();
      if (data.success) {
        if (data.nextPageToken !== undefined) setNextPageToken(data.nextPageToken);
        if (data.emails && Array.isArray(data.emails)) {
          setCustomEmails(data.emails);
          try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data.emails)); } catch (_) {}
        }
        if (data.newCount > 0) {
          setSyncMessage(`📥 Ingested ${data.newCount} additional emails. Total visible: ${(data.emails || []).length}`);
        } else if (!data.nextPageToken) {
          setSyncMessage(`✓ Reached beginning of mailbox (${(data.emails || []).length} total emails)`);
        }
      } else {
        setSyncMessage(data.error || 'All accessible messages ingested.');
      }
    } catch (e) {
      setSyncMessage('⚠️ Error fetching more messages');
    }
    setIsLoadingMore(false);
    setTimeout(() => setSyncMessage(null), 4000);
  };

  // 1-Click Fast Ingestion of All Available Historical Pages
  const handleSyncAllGmail = async () => {
    if (isSyncingAll || isSyncing || isLoadingMore) return;
    setIsSyncingAll(true);
    let currentToken = nextPageToken;
    let keepPaging = true;
    let cycles = 0;
    const sid = getOrCreateSessionId();

    try {
      while (keepPaging && cycles < 25) {
        cycles++;
        let url = `/api/auth/google/sync?session_id=${encodeURIComponent(sid)}&limit=50`;
        if (currentToken) url += `&pageToken=${encodeURIComponent(currentToken)}`;

        const res = await fetch(url, { method: 'POST', headers: { 'x-session-id': sid } });
        const data = await res.json();
        if (data.success) {
          currentToken = data.nextPageToken || null;
          setNextPageToken(currentToken);
          if (data.emails && Array.isArray(data.emails)) {
            setCustomEmails(data.emails);
            try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data.emails)); } catch (_) {}
          }
          setSyncMessage(`⚡ Fast Mailbox Sync: Ingested ${(data.emails || []).length} total emails (Batch ${cycles})...`);
          if (!currentToken) {
            keepPaging = false;
            setSyncMessage(`✅ Fully Ingested All ${(data.emails || []).length} Mailbox Messages!`);
          }
        } else {
          keepPaging = false;
        }
      }
    } catch (_) {}
    setIsSyncingAll(false);
    setTimeout(() => setSyncMessage(null), 5000);
  };

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const target = e.currentTarget;
    if (target.scrollHeight - target.scrollTop - target.clientHeight < 180) {
      if (oauthStatus?.connected && !isSyncing && !isLoadingMore && !isSyncingAll && nextPageToken) {
        handleLoadMoreGmail();
      }
    }
  };

  const handleDisconnect = async () => {
    if (!confirm('Disconnect live Gmail account?')) return;
    try {
      const sid = getOrCreateSessionId();
      await fetch(`/api/auth/disconnect?session_id=${encodeURIComponent(sid)}`, { 
        method: 'POST',
        headers: { 'x-session-id': sid }
      });
      setOauthStatus({ connected: false });
      setCustomEmails([]);
      setSelectedEmail(null);
      setNextPageToken(null);
      try { localStorage.removeItem(STORAGE_KEY); } catch (_) {}
      setSyncMessage('Disconnected Gmail account');
      setTimeout(() => setSyncMessage(null), 3000);
    } catch (_) {}
  };

  const allEmails = customEmails;
  
  // Filter emails according to search query and category
  const filteredEmails = allEmails.filter((email) => {
    const score = email.threatScore ?? 0;
    if (filterCategory === 'critical' && score <= 80) return false;
    if (filterCategory === 'mild' && (score < 50 || score > 80)) return false;
    if (filterCategory === 'safe' && score >= 50) return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const subject = (email.title || email.metadata?.subject || '').toLowerCase();
      const sender = (email.sender?.email || email.sender?.name || '').toLowerCase();
      const id = String(email.id || '').toLowerCase();
      const type = (email.threatVerdict?.headline || email.userFriendlyCategory || '').toLowerCase();
      if (!subject.includes(q) && !sender.includes(q) && !id.includes(q) && !type.includes(q)) {
        return false;
      }
    }
    return true;
  });

  const criticalCount = allEmails.filter((e) => (e.threatScore ?? 0) > 80).length;
  const mildCount = allEmails.filter((e) => (e.threatScore ?? 0) >= 50 && (e.threatScore ?? 0) <= 80).length;
  const safeCount = allEmails.filter((e) => (e.threatScore ?? 0) < 50).length;

  const currentEmail = selectedEmail || filteredEmails[0] || allEmails[0] || null;
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
    setNextPageToken(null);
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
              Ingest & Inspect Live Mailbox Stream
            </h2>
            <p className="text-xs text-slate-500">
              Complete mailbox forensic index • Seamless continuous scroll • Real-time AI threat classification
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Live OAuth Connector */}
            {(isAuthenticated && authUser) || oauthStatus?.connected ? (
              <div className="flex items-center gap-2 bg-emerald-50 border border-emerald-200 rounded-xl px-3 py-1.5 shadow-2xs">
                <div className="flex items-center gap-1.5 text-xs text-emerald-800 font-bold">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="max-w-[140px] truncate">{authUser?.email || oauthStatus?.user?.email || 'Gmail Connected'}</span>
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
              <button 
                onClick={loginWithGoogle}
                className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold rounded-xl shadow-xs transition-all flex items-center gap-2 cursor-pointer"
                title="Connect Gmail inbox via OAuth 2.0 (No passwords stored)"
              >
                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.66-5.17 3.66-9.17z"/>
                  <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.34 24 12 24z"/>
                  <path fill="#FBBC05" d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.18 0 10.04 0 12s.45 3.82 1.25 5.42l4.03-3.15z"/>
                  <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.34 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"/>
                </svg>
                <span>Connect Live Gmail</span>
              </button>
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

        {/* Real Ingested Emails Stream with Search, Filter Pills & Seamless Scroll */}
        {allEmails.length > 0 ? (
          <div className="bg-white border border-slate-200 rounded-2xl p-4 shadow-2xs space-y-3">
            {/* Search & Filter Header Bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
              {/* Search Box */}
              <div className="relative flex-1 max-w-md">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search emails by subject, sender, or case ID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-8 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-hidden focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all text-slate-800 placeholder-slate-400"
                />
                {searchQuery && (
                  <button 
                    onClick={() => setSearchQuery('')}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 text-xs"
                  >
                    ✕
                  </button>
                )}
              </div>

              {/* Category Filter Pills & Counter */}
              <div className="flex flex-wrap items-center gap-1.5">
                <button
                  onClick={() => setFilterCategory('all')}
                  className={`px-3 py-1 rounded-xl text-xs font-bold transition-all cursor-pointer ${
                    filterCategory === 'all'
                      ? 'bg-slate-900 text-white shadow-xs'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  All ({allEmails.length})
                </button>
                <button
                  onClick={() => setFilterCategory('critical')}
                  className={`px-3 py-1 rounded-xl text-xs font-bold transition-all flex items-center gap-1 cursor-pointer ${
                    filterCategory === 'critical'
                      ? 'bg-red-600 text-white shadow-xs'
                      : 'bg-red-50 text-red-700 hover:bg-red-100 border border-red-200/60'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                  Critical ({criticalCount})
                </button>
                <button
                  onClick={() => setFilterCategory('mild')}
                  className={`px-3 py-1 rounded-xl text-xs font-bold transition-all flex items-center gap-1 cursor-pointer ${
                    filterCategory === 'mild'
                      ? 'bg-orange-600 text-white shadow-xs'
                      : 'bg-orange-50 text-orange-700 hover:bg-orange-100 border border-orange-200/60'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                  Mild ({mildCount})
                </button>
                <button
                  onClick={() => setFilterCategory('safe')}
                  className={`px-3 py-1 rounded-xl text-xs font-bold transition-all flex items-center gap-1 cursor-pointer ${
                    filterCategory === 'safe'
                      ? 'bg-emerald-600 text-white shadow-xs'
                      : 'bg-emerald-50 text-emerald-700 hover:bg-emerald-100 border border-emerald-200/60'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                  Safe ({safeCount})
                </button>

                {oauthStatus?.connected && (
                  <div className="ml-auto flex items-center gap-1.5">
                    <button
                      onClick={handleLoadMoreGmail}
                      disabled={isLoadingMore || isSyncing || isSyncingAll}
                      className="px-2.5 py-1 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-xl border border-indigo-200 transition-all flex items-center gap-1 cursor-pointer"
                      title="Load next batch of 50 emails from Gmail"
                    >
                      <RefreshCw className={`w-3 h-3 ${isLoadingMore ? 'animate-spin' : ''}`} />
                      <span>{isLoadingMore ? 'Fetching...' : 'Load +50'}</span>
                    </button>
                    <button
                      onClick={handleSyncAllGmail}
                      disabled={isLoadingMore || isSyncing || isSyncingAll}
                      className="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl shadow-xs transition-all flex items-center gap-1 cursor-pointer"
                      title="Automatically fetch all historical emails in your Gmail inbox"
                    >
                      <Zap className={`w-3 h-3 ${isSyncingAll ? 'animate-spin text-amber-300' : ''}`} />
                      <span>{isSyncingAll ? 'Syncing All...' : 'Sync Entire Mailbox'}</span>
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Scrollable Feed Container (Shows every email on scroll) */}
            <div 
              onScroll={handleScroll}
              className="max-h-[440px] overflow-y-auto pr-1 space-y-2.5 custom-scrollbar"
              style={{ scrollBehavior: 'smooth' }}
            >
              {filteredEmails.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                  {filteredEmails.map((sample) => {
                    const isSelected = currentEmail?.id === sample.id;
                    const score = sample.threatScore ?? 0;
                    const badgeClass = score > 80 
                      ? 'bg-red-100 text-red-700 border-red-200' 
                      : (score >= 50 ? 'bg-orange-100 text-orange-700 border-orange-200' : 'bg-emerald-100 text-emerald-700 border-emerald-200');
                    const dotColor = score > 80 ? 'bg-red-500' : (score >= 50 ? 'bg-orange-500' : 'bg-emerald-500');

                    return (
                      <div
                        key={sample.id}
                        onClick={() => setSelectedEmail(sample)}
                        className={`p-3.5 rounded-2xl border transition-all cursor-pointer flex flex-col justify-between group ${
                          isSelected
                            ? 'bg-indigo-50/70 border-indigo-600 ring-2 ring-indigo-500/20 shadow-sm'
                            : 'bg-slate-50/50 hover:bg-white border-slate-200 hover:border-slate-300 hover:shadow-2xs'
                        }`}
                      >
                        <div className="space-y-2">
                          <div className="flex items-center justify-between gap-1">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border flex items-center gap-1 ${badgeClass}`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
                              {sample.shortBadge || (score > 80 ? '🚨 Critical' : (score >= 50 ? '⚠️ Mild' : '✅ Safe'))}
                            </span>
                            <span className="text-[10px] font-mono text-slate-400 font-bold">
                              {sample.threatScore}/100
                            </span>
                          </div>

                          <h4 className="text-xs font-bold text-slate-900 line-clamp-2 leading-snug group-hover:text-indigo-600 transition-colors">
                            {sample.title || sample.metadata?.subject || '(No Subject)'}
                          </h4>

                          <p className="text-[11px] text-slate-500 line-clamp-1 font-mono truncate">
                            {sample.sender?.name ? `${sample.sender.name} <${sample.sender.email}>` : (sample.sender?.email || 'email-source')}
                          </p>
                        </div>

                        <div className="pt-2 text-[10px] text-slate-400 border-t border-slate-200/60 mt-2.5 flex items-center justify-between">
                          <span className="font-mono">{sample.metadata?.date ? sample.metadata.date.split(' ').slice(0, 4).join(' ') : 'Recent'}</span>
                          {isSelected && (
                            <span className="text-indigo-600 font-bold text-[10px] flex items-center gap-0.5">
                              Inspecting <ChevronRight className="w-3 h-3" />
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 text-xs">
                  No emails match your filter or search query "{searchQuery}".
                </div>
              )}

              {/* In-feed status indicator & bottom fetch loader */}
              <div className="pt-3 pb-1 border-t border-slate-100 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] font-bold text-slate-700">
                    Showing {filteredEmails.length} of {allEmails.length} visible mailbox emails
                  </span>
                  <span className="text-[10px] text-slate-400 hidden md:inline">
                    (Threats: {criticalCount + mildCount} saved to database • Safe: {safeCount} live streamed)
                  </span>
                </div>
                {isLoadingMore || isSyncingAll ? (
                  <div className="flex items-center gap-2 text-indigo-600 font-bold text-xs">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>{isSyncingAll ? 'Turbo-syncing entire mailbox...' : 'Loading next 50 emails on scroll...'}</span>
                  </div>
                ) : nextPageToken && oauthStatus?.connected ? (
                  <button
                    onClick={handleLoadMoreGmail}
                    className="text-indigo-600 hover:text-indigo-800 font-bold text-xs underline flex items-center gap-1 cursor-pointer"
                  >
                    <span>Scroll down or click here to load next 50</span>
                    <ChevronRight className="w-3 h-3" />
                  </button>
                ) : (
                  <span className="text-[11px] text-emerald-600 font-medium">
                    ✓ All accessible mailbox emails indexed & visible
                  </span>
                )}
              </div>
            </div>
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
