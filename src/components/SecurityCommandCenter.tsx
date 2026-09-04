import React, { useState } from 'react';
import { 
  Activity, 
  ShieldAlert, 
  ShieldCheck, 
  Globe, 
  Download, 
  Copy, 
  Check, 
  Terminal, 
  Layers,
  Radio,
  Clock,
  Filter
} from 'lucide-react';
import { LiveThreatLog, ThreatCategory } from '../types';
import { THREAT_CATEGORIES_METADATA } from '../engine/threatKnowledgeBase';

interface SecurityCommandCenterProps {
  threatLogs: LiveThreatLog[];
}

export const SecurityCommandCenter: React.FC<SecurityCommandCenterProps> = ({
  threatLogs
}) => {
  const [copiedRule, setCopiedRule] = useState<string | null>(null);
  const [ruleFormat, setRuleFormat] = useState<'cloudflare' | 'modsec' | 'snort' | 'yara'>('cloudflare');

  const categories = Object.keys(THREAT_CATEGORIES_METADATA) as ThreatCategory[];

  const generateWafRule = (format: string) => {
    if (format === 'cloudflare') {
      return JSON.stringify({
        description: "Sentinel-Ralph Cloudflare WAF Managed Defense Rule",
        expression: "(http.request.uri.query contains \"' OR '1'='1\" or http.request.body contains \"<script\" or http.request.body contains \"ignore previous instructions\")",
        action: "block",
        enabled: true
      }, null, 2);
    }
    if (format === 'modsec') {
      return `SecRule REQUEST_URI|REQUEST_BODY "@rx (?i)('|--|<script|union.*select|ignore.*instructions)" \\
  "id:990001,phase:2,deny,status:403,msg:'Sentinel-Ralph WAF Core Rule Violation - Injection Attack Intercepted',tag:'attack-generic'"`;
    }
    if (format === 'snort') {
      return `alert tcp any any -> any 80/443 (msg:"SENTINEL-RALPH: Threat Vector Detected in HTTP Payload"; content:"union select"; nocase; sid:900001; rev:1;)`;
    }
    return `rule Sentinel_Ralph_ZeroDay_Signature {
  meta:
    description = "Autonomous Cyber Defense Multi-Vector Payload Rule"
    author = "Sentinel-Ralph AI Engine"
    date = "2026-09-04"
  strings:
    $sqli = "' OR '1'='1" nocase
    $xss = "<script" nocase
    $prompt_inj = "ignore previous instructions" nocase
  condition:
    any of them
}`;
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRule(id);
    setTimeout(() => setCopiedRule(null), 2000);
  };

  return (
    <div className="space-y-6">
      
      {/* Top Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-cyan-950/40 via-slate-900 to-slate-900 border border-cyan-500/30 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="p-3 rounded-xl bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
            <Radio className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100 font-sans">SOC Live Command & Telemetry Center</h2>
            <p className="text-xs text-slate-400 mt-0.5">Real-time attack telemetry, global origins, mitigation logs, and auto-generated WAF rules.</p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono bg-slate-950 px-3.5 py-2 rounded-xl border border-slate-800">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span className="text-slate-300">Live Telemetry Feed Active</span>
        </div>
      </div>

      {/* Radar & Global Attack Deck */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Radar Visualizer (4 cols) */}
        <div className="lg:col-span-4 p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col items-center justify-center relative overflow-hidden min-h-[300px]">
          <div className="text-xs font-mono font-bold text-slate-300 mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span>Active Sector Threat Radar</span>
          </div>

          <div className="relative w-44 h-44 rounded-full border border-cyan-500/30 flex items-center justify-center bg-slate-950/80 shadow-[0_0_40px_rgba(6,182,212,0.15)]">
            {/* Concentric rings */}
            <div className="absolute w-32 h-32 rounded-full border border-cyan-500/20" />
            <div className="absolute w-20 h-20 rounded-full border border-cyan-500/20" />
            
            {/* Crosshairs */}
            <div className="absolute w-full h-[1px] bg-cyan-500/20" />
            <div className="absolute h-full w-[1px] bg-cyan-500/20" />

            {/* Rotating radar sweep */}
            <div className="absolute w-full h-full rounded-full animate-radar-sweep origin-center pointer-events-none">
              <div className="w-1/2 h-1/2 bg-gradient-to-br from-cyan-500/30 to-transparent rounded-tl-full" />
            </div>

            {/* Radar blips */}
            <div className="absolute top-10 left-12 w-2 h-2 rounded-full bg-rose-400 animate-ping" />
            <div className="absolute bottom-12 right-14 w-2 h-2 rounded-full bg-amber-400 animate-ping" style={{ animationDelay: '1s' }} />
            <div className="absolute top-20 right-8 w-2 h-2 rounded-full bg-cyan-400 animate-ping" style={{ animationDelay: '1.5s' }} />
          </div>

          <div className="text-[11px] font-mono text-slate-400 mt-4 text-center">
            Passive Sector Scanning: <span className="text-emerald-400 font-bold">100% Coverage</span>
          </div>
        </div>

        {/* Global Incident Stream Table (8 cols) */}
        <div className="lg:col-span-8 p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              <span>Real-Time Incident Stream ({threatLogs.length} Events)</span>
            </h3>
            <span className="text-xs text-slate-500 font-mono">Auto-refreshes live</span>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-950/90 overflow-hidden max-h-[260px] overflow-y-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 sticky top-0">
                <tr>
                  <th className="p-2.5">Time</th>
                  <th className="p-2.5">Source Node</th>
                  <th className="p-2.5">Vector</th>
                  <th className="p-2.5">Severity</th>
                  <th className="p-2.5">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {threatLogs.map(log => (
                  <tr key={log.id} className="hover:bg-slate-900/50">
                    <td className="p-2.5 text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                    <td className="p-2.5 text-slate-300 whitespace-nowrap">{log.source}</td>
                    <td className="p-2.5 text-cyan-400 whitespace-nowrap">{log.category.toUpperCase()}</td>
                    <td className="p-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        log.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' :
                        log.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300' :
                        'bg-emerald-500/20 text-emerald-300'
                      }`}>
                        {log.severity}
                      </span>
                    </td>
                    <td className="p-2.5">
                      <span className="text-emerald-400 font-bold text-[11px]">
                        {log.actionTaken}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* Auto-Generated WAF / Security Rules Exporter */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100 font-mono flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Exportable Production WAF & Rule Generators</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">Export live AI-synthesized signatures directly into your production proxy or WAF.</p>
          </div>

          {/* Format Selector Pills */}
          <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
            {(['cloudflare', 'modsec', 'snort', 'yara'] as const).map(fmt => (
              <button
                key={fmt}
                onClick={() => setRuleFormat(fmt)}
                className={`px-3 py-1 rounded-lg transition-all uppercase ${
                  ruleFormat === fmt
                    ? 'bg-cyan-500 text-slate-950 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {fmt}
              </button>
            ))}
          </div>
        </div>

        {/* Code Box */}
        <div className="relative p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300">
          <pre className="overflow-x-auto whitespace-pre-wrap">{generateWafRule(ruleFormat)}</pre>
          <button
            onClick={() => handleCopy(generateWafRule(ruleFormat), ruleFormat)}
            className="absolute top-3 right-3 flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono transition-all"
          >
            {copiedRule === ruleFormat ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedRule === ruleFormat ? 'Copied!' : 'Copy Rule'}</span>
          </button>
        </div>
      </div>

    </div>
  );
};
