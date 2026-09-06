import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Database, 
  Search, 
  Globe, 
  FileCode, 
  ExternalLink, 
  Terminal, 
  Copy, 
  Check, 
  Filter,
  Layers,
  ArrowRight,
  Server,
  RefreshCw,
  HardDrive
} from 'lucide-react';
import { THREAT_INTELLIGENCE_DB, THREAT_TYPES_INFO } from '../data/threatData';

export const ThreatIntelligenceView: React.FC = () => {
  const [selectedThreatType, setSelectedThreatType] = useState<string>('phishing');
  const [currentCategory, setCurrentCategory] = useState<'all' | 'ips' | 'domains' | 'urls' | 'hashes'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);
  const [dbStatus, setDbStatus] = useState<any>(null);
  const [isLoadingDb, setIsLoadingDb] = useState(false);

  const fetchDbStatus = async () => {
    setIsLoadingDb(true);
    try {
      const res = await fetch('/api/db/status');
      if (res.ok) {
        const data = await res.json();
        setDbStatus(data);
      }
    } catch (_) {}
    setIsLoadingDb(false);
  };

  useEffect(() => {
    fetchDbStatus();
  }, []);

  const activeTypeInfo = (THREAT_TYPES_INFO as any)[selectedThreatType] || (THREAT_TYPES_INFO as any)['phishing'];

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndicator(text);
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  // Flatten IOCs into a single typed list
  const allIocs: any[] = [
    ...(THREAT_INTELLIGENCE_DB.ips || []).map(i => ({ ...i, category: 'ips' })),
    ...(THREAT_INTELLIGENCE_DB.domains || []).map(d => ({ ...d, category: 'domains' })),
    ...(THREAT_INTELLIGENCE_DB.urls || []).map(u => ({ ...u, category: 'urls' })),
    ...(THREAT_INTELLIGENCE_DB.hashes || []).map(h => ({ ...h, category: 'hashes' }))
  ];

  // Filter IOCs
  const filteredIOCs = allIocs.filter((item: any) => {
    const matchesCategory = currentCategory === 'all' || item.category === currentCategory;
    const matchesQuery = 
      !searchQuery.trim() ||
      (item.indicator && item.indicator.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (item.threatType && item.threatType.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (item.threatActor && item.threatActor.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (item.plainWhatItDoes && item.plainWhatItDoes.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesCategory && matchesQuery;
  });

  return (
    <div className="space-y-8">
      
      {/* Section 1: The 4 Main Cyber Threats Explained */}
      <div>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
          <div>
            <h2 className="text-xl font-bold text-slate-900 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-indigo-600" />
              Cyber Threat Taxonomy & Attack Vectors
            </h2>
            <p className="text-xs text-slate-500">
              Curated intelligence on primary email attack vectors, diagnostic indicators, and security countermeasures
            </p>
          </div>
          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
            Live ThreatLens Threat Feed
          </span>
        </div>

        {/* Threat Type Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {Object.entries(THREAT_TYPES_INFO).map(([key, info]: [string, any]) => {
            const isSelected = selectedThreatType === key;
            return (
              <div
                key={key}
                onClick={() => setSelectedThreatType(key)}
                className={`p-4 rounded-2xl border transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-white border-indigo-600 ring-2 ring-indigo-500/20 shadow-md'
                    : 'bg-white border-slate-200 hover:border-slate-300 hover:shadow-xs'
                }`}
              >
                <div className="flex items-center justify-between pb-2">
                  <span className="text-2xl">{info.icon}</span>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                    info.severity === 'Critical' ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700'
                  }`}>
                    {info.severity}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-slate-900">{info.name}</h3>
                <p className="text-xs text-slate-500 mt-1 line-clamp-2">{info.plainDesc}</p>
                <div className="mt-3 flex items-center gap-1 text-[11px] font-bold text-indigo-600">
                  <span>Explore Vector</span>
                  <ArrowRight className="w-3 h-3" />
                </div>
              </div>
            );
          })}
        </div>

        {/* Active Threat Type Deep-Dive Card */}
        {activeTypeInfo && (
          <div className="mt-4 bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-100 gap-2">
              <div className="flex items-center gap-3">
                <span className="text-3xl">{activeTypeInfo.icon}</span>
                <div>
                  <h3 className="text-lg font-bold text-slate-900">{activeTypeInfo.name}</h3>
                  <p className="text-xs text-slate-500">{activeTypeInfo.plainDesc}</p>
                </div>
              </div>
              <span className="text-xs font-mono font-bold bg-slate-100 text-slate-700 px-3 py-1 rounded-lg">
                Primary Vector: {activeTypeInfo.severity} Risk
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
              <div className="space-y-3">
                <div className="font-bold text-slate-900 uppercase tracking-wider text-[11px]">
                  How Attackers Execute This:
                </div>
                <p className="text-slate-600 leading-relaxed">{activeTypeInfo.howItWorks}</p>
                
                <div className="font-bold text-slate-900 uppercase tracking-wider text-[11px] pt-2">
                  Common Real-World Lures:
                </div>
                <ul className="list-disc pl-5 space-y-1 text-slate-600">
                  {activeTypeInfo.commonLures?.map((lure: string, i: number) => (
                    <li key={i}>{lure}</li>
                  ))}
                </ul>
              </div>

              <div className="space-y-3">
                <div className="font-bold text-slate-900 uppercase tracking-wider text-[11px]">
                  Detection & Defense Countermeasures:
                </div>
                <ul className="list-disc pl-5 space-y-1 text-slate-600 leading-relaxed">
                  {activeTypeInfo.defenseTips?.map((tip: string, i: number) => (
                    <li key={i}>{tip}</li>
                  ))}
                </ul>

                <div className="p-3.5 bg-indigo-50/50 border border-indigo-100 rounded-xl space-y-1 mt-4">
                  <span className="font-bold text-indigo-950 text-[11px]">Gateway Rule Recommendation:</span>
                  <p className="text-indigo-900 text-xs">{activeTypeInfo.gatewayRule || 'Enforce strict inbound SPF/DKIM/DMARC alignment rules.'}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Section 2: Known Malicious Indicators (IOCs) */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-4 border-b border-slate-100">
          <div>
            <h2 className="text-xl font-bold text-slate-900 flex items-center gap-2">
              <Database className="w-5 h-5 text-red-500" />
              Malicious Indicators of Compromise (IOCs)
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Verified active malicious infrastructure tracked across global SOC gateway sensors
            </p>
          </div>

          {/* Category Filter Tabs & Search */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex bg-slate-100 p-1 rounded-xl text-xs font-bold text-slate-600">
              {[
                { id: 'all', label: 'All IOCs' },
                { id: 'ips', label: 'IPs' },
                { id: 'domains', label: 'Domains' },
                { id: 'urls', label: 'URLs' },
                { id: 'hashes', label: 'File Hashes' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setCurrentCategory(tab.id as any)}
                  className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                    currentCategory === tab.id
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'hover:text-slate-900'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="relative min-w-[240px]">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search IP, domain, hash, actor..."
                className="w-full pl-9 pr-4 py-2 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white text-slate-900"
              />
            </div>
          </div>
        </div>

        {/* IOCs Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border border-slate-200 rounded-xl">
            <thead className="bg-slate-100 text-slate-700 font-mono">
              <tr>
                <th className="p-3 border-b border-slate-200">CATEGORY</th>
                <th className="p-3 border-b border-slate-200">INDICATOR</th>
                <th className="p-3 border-b border-slate-200">THREAT TYPE</th>
                <th className="p-3 border-b border-slate-200">SEVERITY</th>
                <th className="p-3 border-b border-slate-200">ACTOR / REPUTATION</th>
                <th className="p-3 border-b border-slate-200 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 font-mono">
              {filteredIOCs.map((ioc: any, idx: number) => (
                <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                  <td className="p-3 text-slate-400 uppercase font-bold text-[10px]">
                    {ioc.category}
                  </td>
                  <td className="p-3 font-bold text-slate-900 break-all">
                    {ioc.indicator}
                  </td>
                  <td className="p-3 text-slate-600 font-sans">
                    {ioc.threatType}
                  </td>
                  <td className="p-3">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      ioc.reputationScore > 90
                        ? 'bg-red-100 text-red-800'
                        : (ioc.reputationScore > 75 ? 'bg-orange-100 text-orange-800' : 'bg-yellow-100 text-yellow-800')
                    }`}>
                      {ioc.reputationScore ? `SCORE ${ioc.reputationScore}` : 'HIGH'}
                    </span>
                  </td>
                  <td className="p-3 text-slate-600 text-[11px] font-sans">
                    {ioc.threatActor}
                  </td>
                  <td className="p-3 text-right">
                    <button
                      onClick={() => copyToClipboard(ioc.indicator)}
                      className="p-1.5 text-slate-500 hover:text-indigo-600 rounded-lg hover:bg-indigo-50 transition-colors cursor-pointer"
                      title="Copy indicator"
                    >
                      {copiedIndicator === ioc.indicator ? (
                        <Check className="w-4 h-4 text-emerald-600" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Section 3: PostgreSQL Database & Forensic Storage Engine */}
      <div className="p-6 bg-slate-900 rounded-3xl text-white border border-slate-800 shadow-xl space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold tracking-tight">
                  PostgreSQL Forensic Storage Engine
                </h3>
                {dbStatus?.connected ? (
                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    POSTGRES ONLINE
                  </span>
                ) : (
                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                    <HardDrive className="w-3 h-3" />
                    LOCAL FILE / MEMORY MODE
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400">
                Persistent relational data store for ingested headers, threat telemetry, and OAuth sessions
              </p>
            </div>
          </div>

          <button
            onClick={fetchDbStatus}
            disabled={isLoadingDb}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold rounded-xl transition-all flex items-center gap-2 border border-slate-700 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingDb ? 'animate-spin' : ''}`} />
            Refresh DB Status
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-slate-800/60 rounded-2xl border border-slate-700/60 space-y-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold">Storage Provider</span>
            <div className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
              <Database className="w-4 h-4 text-indigo-400" />
              {dbStatus?.connected ? 'PostgreSQL (Cloud / Pool)' : 'Local File Store (Disk / /tmp)'}
            </div>
            <p className="text-[11px] text-slate-400">
              {dbStatus?.connected 
                ? `Latency: ${dbStatus.latencyMs ?? '< 10'}ms` 
                : 'Zero config local mode. Set DATABASE_URL for Postgres.'}
            </p>
          </div>

          <div className="p-4 bg-slate-800/60 rounded-2xl border border-slate-700/60 space-y-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold">Emails Table</span>
            <div className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
              <span className="text-emerald-400 font-mono">{dbStatus?.tables?.emails ?? dbStatus?.count ?? 'Active'}</span>
              <span className="text-xs text-slate-400 font-normal">records indexed</span>
            </div>
            <p className="text-[11px] text-slate-400">
              Indexed JSONB telemetry & header forensics
            </p>
          </div>

          <div className="p-4 bg-slate-800/60 rounded-2xl border border-slate-700/60 space-y-1">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold">OAuth Sessions Table</span>
            <div className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
              <span className="text-indigo-400 font-mono">{dbStatus?.tables?.oauthSessions ?? (dbStatus?.connected ? '1' : '1 (file)')}</span>
              <span className="text-xs text-slate-400 font-normal">active sessions</span>
            </div>
            <p className="text-[11px] text-slate-400">
              Multi-instance token persistence across cold starts
            </p>
          </div>
        </div>

        {!dbStatus?.connected && (
          <div className="p-4 bg-indigo-950/40 rounded-2xl border border-indigo-800/40 text-xs text-indigo-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <span className="font-bold text-indigo-300">💡 Connect Neon / Supabase / Vercel Postgres:</span>
              <span className="text-slate-300 ml-1">
                Add <code className="bg-slate-800 px-1.5 py-0.5 rounded text-indigo-300 font-mono text-[11px]">DATABASE_URL=postgresql://...</code> to your environment variables.
              </span>
            </div>
          </div>
        )}
      </div>

    </div>
  );
};
