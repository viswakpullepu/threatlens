import React, { useState } from 'react';
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
  ChevronDown
} from 'lucide-react';
import { SAMPLE_EMAILS } from '../data/threatData';
import { ForensicReportModal } from './ForensicReportModal';
import { parseEmailForensics } from '../engine/emailParser';

export const ForensicsView: React.FC = () => {
  const [selectedEmail, setSelectedEmail] = useState<any>(SAMPLE_EMAILS[0]);
  const [activeDeepTab, setActiveDeepTab] = useState<'summary' | 'overview' | 'headers' | 'timeline' | 'iocs' | 'mitre'>('summary');
  const [isRawModalOpen, setIsRawModalOpen] = useState(false);
  const [rawEmailText, setRawEmailText] = useState('');
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [customEmails, setCustomEmails] = useState<any[]>([]);

  const allEmails = [...customEmails, ...SAMPLE_EMAILS];
  const isThreat = selectedEmail.isThreat;

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
          setCustomEmails(prev => [data.email, ...prev]);
          setSelectedEmail(data.email);
          return;
        }
      }
    } catch (_) {
      // Backend offline: run client-side engine below
    }

    const parsedEmail = parseEmailForensics(rawText, fileName);
    setCustomEmails(prev => [parsedEmail, ...prev]);
    setSelectedEmail(parsedEmail);
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
      
      {/* 1. SCENARIO SELECTOR & UPLOAD BAR */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-indigo-600 text-white text-xs flex items-center justify-center font-bold">
                1
              </span>
              Select Scenario or Upload Email for Forensic Analysis
            </h2>
            <p className="text-xs text-slate-500">
              Pick any pre-loaded scenario or drag-and-drop your own email to analyze SPF/DKIM/DMARC, spoofing, URLs, and headers
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button 
              onClick={() => setIsRawModalOpen(true)}
              className="px-3.5 py-2 bg-white border border-slate-200 hover:border-slate-300 text-slate-700 text-xs font-bold rounded-xl shadow-2xs transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <ClipboardPaste className="w-3.5 h-3.5 text-indigo-600" />
              Paste Raw Email Text
            </button>
            <label className="px-3.5 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-xl border border-indigo-200 transition-all flex items-center gap-1.5 cursor-pointer">
              <UploadCloud className="w-3.5 h-3.5" />
              Upload .EML File
              <input type="file" accept=".eml,.msg,.txt" onChange={handleFileUpload} className="hidden" />
            </label>
          </div>
        </div>

        {/* 5 Sample Emails Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {allEmails.map((sample) => {
            const isSelected = selectedEmail.id === sample.id;
            const sampleIsThreat = sample.isThreat;
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
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      sampleIsThreat ? 'bg-red-100 text-red-700' : 'bg-emerald-100 text-emerald-700'
                    }`}>
                      {sample.shortBadge || (sampleIsThreat ? '🚨 Threat' : '✅ Clean')}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      Score: {sample.threatScore}
                    </span>
                  </div>
                  <h4 className="text-xs font-bold text-slate-900 line-clamp-2">
                    {sample.title}
                  </h4>
                </div>
                <div className="pt-2 text-[10px] font-mono text-slate-400 border-t border-slate-100 mt-2 truncate">
                  {sample.sender?.email || 'email-source'}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 2. OVERALL THREAT RESULT BANNER */}
      <div className={`bg-white border ${
        isThreat ? 'border-red-200' : 'border-emerald-200'
      } rounded-2xl p-6 shadow-xs relative overflow-hidden`}>
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${
                isThreat ? 'bg-red-100 text-red-800 border border-red-300' : 'bg-emerald-100 text-emerald-800 border border-emerald-300'
              }`}>
                <span className={`w-2.5 h-2.5 rounded-full ${isThreat ? 'bg-red-600 animate-pulse' : 'bg-emerald-600'} mr-2`} />
                {isThreat ? '⚠️ THREAT CONFIRMED: ' + (selectedEmail.userFriendlyCategory || selectedEmail.category || 'MALICIOUS').toUpperCase() : '✅ 100% VERIFIED SAFE EMAIL'}
              </span>
              <span className="text-xs text-slate-400 font-mono">Case ID: #{selectedEmail.id}</span>
              <span className="text-xs text-slate-400">|</span>
              <span className="text-xs text-slate-500">{selectedEmail.metadata?.date || 'Today'}</span>
            </div>
            <h2 className="text-2xl font-black text-slate-900 tracking-tight">
              {selectedEmail.metadata?.subject}
            </h2>
            <p className="text-xs text-slate-600 max-w-3xl leading-relaxed">
              {selectedEmail.simpleTakeaway || selectedEmail.threatVerdict?.headline}
            </p>
          </div>

          <div className="flex items-center gap-4 shrink-0">
            <div className="text-right">
              <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Threat Score</div>
              <div className={`text-3xl font-black font-mono ${isThreat ? 'text-red-600' : 'text-emerald-600'}`}>
                {selectedEmail.threatScore}<span className="text-xs font-normal text-slate-400">/100</span>
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

      {/* 3. SENDER & RECIPIENT BREAKDOWN + SENDER SPOOFING CHECK */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
        <div className="flex items-center justify-between pb-4 border-b border-slate-100">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-indigo-600" />
            Sender Identity, Target & Spoofing Evaluation
          </h3>
          <span className={`text-xs font-bold px-3 py-1 rounded-full ${
            selectedEmail.sender?.isSpoofed ? 'bg-red-100 text-red-800 border border-red-200' : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
          }`}>
            {selectedEmail.sender?.isSpoofed ? '🚨 Spoofed Sender Masquerade' : '✅ Genuine Sender Verified'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 text-xs font-mono">
          <div className="space-y-3">
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Claimed Sender (From Header)</span>
              <div className="font-bold text-slate-900 text-sm">{selectedEmail.sender?.displayName}</div>
              <div className="text-indigo-600">{selectedEmail.sender?.email}</div>
            </div>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Envelope Return-Path / Reply-To</span>
              <div className="text-slate-800">{selectedEmail.sender?.replyTo || selectedEmail.sender?.envelopeFrom}</div>
            </div>
          </div>

          <div className="space-y-3">
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Origin Relay IP & Geo Coordinates</span>
              <div className="font-bold text-slate-900">{selectedEmail.sender?.originIp}</div>
              <div className="text-slate-600">{selectedEmail.sender?.location} • {selectedEmail.sender?.asn}</div>
            </div>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400">Intended Target / Organization Host</span>
              <div className="text-slate-900 font-bold">{selectedEmail.recipient?.email}</div>
              <div className="text-slate-500">{selectedEmail.recipient?.department} ({selectedEmail.recipient?.targetHost || 'mx1.enterprise.com'})</div>
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
                selectedEmail.auth?.spf?.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
              }`}>
                {selectedEmail.auth?.spf?.status || 'FAIL'}
              </span>
            </div>
            <div className="text-[11px] font-bold text-slate-700">{selectedEmail.auth?.spf?.friendlyName}</div>
            <p className="text-[11px] text-slate-500 leading-relaxed">{selectedEmail.auth?.spf?.explanation}</p>
            <div className="text-[11px] font-mono p-2 bg-slate-50 rounded border border-slate-200 text-slate-800">
              {selectedEmail.auth?.spf?.message}
            </div>
          </div>

          {/* DKIM Block */}
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">DKIM Digital Seal</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                selectedEmail.auth?.dkim?.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
              }`}>
                {selectedEmail.auth?.dkim?.status || 'FAIL'}
              </span>
            </div>
            <div className="text-[11px] font-bold text-slate-700">{selectedEmail.auth?.dkim?.friendlyName}</div>
            <p className="text-[11px] text-slate-500 leading-relaxed">{selectedEmail.auth?.dkim?.explanation}</p>
            <div className="text-[11px] font-mono p-2 bg-slate-50 rounded border border-slate-200 text-slate-800">
              {selectedEmail.auth?.dkim?.message}
            </div>
          </div>

          {/* DMARC Block */}
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900">DMARC Policy</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                selectedEmail.auth?.dmarc?.status === 'PASS' ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
              }`}>
                {selectedEmail.auth?.dmarc?.status || 'FAIL'}
              </span>
            </div>
            <div className="text-[11px] font-bold text-slate-700">{selectedEmail.auth?.dmarc?.friendlyName}</div>
            <p className="text-[11px] text-slate-500 leading-relaxed">{selectedEmail.auth?.dmarc?.explanation}</p>
            <div className="text-[11px] font-mono p-2 bg-slate-50 rounded border border-slate-200 text-slate-800">
              {selectedEmail.auth?.dmarc?.message}
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
              Extracted URLs & Domain Telemetry ({selectedEmail.urls?.length || 0})
            </h3>
            <span className="text-[10px] font-mono text-slate-400">Sandbox Inspection</span>
          </div>

          {selectedEmail.urls && selectedEmail.urls.length > 0 ? (
            <div className="space-y-3">
              {selectedEmail.urls.map((urlObj: any, idx: number) => (
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
              Email Attachments & File Hashes ({selectedEmail.attachments?.length || 0})
            </h3>
            <span className="text-[10px] font-mono text-slate-400">Static / Dynamic Sandbox</span>
          </div>

          {selectedEmail.attachments && selectedEmail.attachments.length > 0 ? (
            <div className="space-y-3">
              {selectedEmail.attachments.map((att: any, idx: number) => (
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
                  {(selectedEmail.whatHappened || []).map((h: string, idx: number) => (
                    <li key={idx}>{h}</li>
                  ))}
                </ul>
              </div>
              <div className="p-4 bg-indigo-50/50 border border-indigo-100 rounded-xl space-y-1 text-xs">
                <span className="font-bold text-indigo-950 uppercase tracking-wider text-[10px]">SOC Response Protocol:</span>
                <p className="text-indigo-900 font-medium">{selectedEmail.whatToDo}</p>
              </div>
            </div>
          )}

          {activeDeepTab === 'overview' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                <div className="text-[10px] uppercase font-bold text-slate-400">Sending Infrastructure</div>
                <div className="text-slate-900 font-bold">IP: {selectedEmail.sender?.originIp}</div>
                <div className="text-slate-600">Location: {selectedEmail.sender?.location}</div>
                <div className="text-slate-600">ASN: {selectedEmail.sender?.asn}</div>
                <div className="text-slate-600">Reverse DNS: {selectedEmail.sender?.reverseDns || 'None'}</div>
              </div>

              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                <div className="text-[10px] uppercase font-bold text-slate-400">Target Envelope</div>
                <div className="text-slate-900 font-bold">Recipient: {selectedEmail.recipient?.email}</div>
                <div className="text-slate-600">Department: {selectedEmail.recipient?.department}</div>
                <div className="text-slate-600">MX Host: {selectedEmail.recipient?.targetHost}</div>
              </div>
            </div>
          )}

          {activeDeepTab === 'headers' && (
            <div className="p-4 bg-slate-900 text-slate-200 rounded-xl font-mono text-xs overflow-x-auto space-y-1">
              <div><span className="text-indigo-400">From:</span> {selectedEmail.sender?.displayName} &lt;{selectedEmail.sender?.email}&gt;</div>
              <div><span className="text-indigo-400">To:</span> {selectedEmail.recipient?.email}</div>
              <div><span className="text-indigo-400">Subject:</span> {selectedEmail.metadata?.subject}</div>
              <div><span className="text-indigo-400">Date:</span> {selectedEmail.metadata?.date}</div>
              <div><span className="text-indigo-400">Message-ID:</span> {selectedEmail.metadata?.messageId}</div>
              <div><span className="text-indigo-400">User-Agent:</span> {selectedEmail.metadata?.userAgent}</div>
              <div><span className="text-indigo-400">X-Originating-IP:</span> [{selectedEmail.sender?.originIp}]</div>
              <div><span className="text-indigo-400">Authentication-Results:</span> spf={selectedEmail.auth?.spf?.status.toLowerCase()} dkim={selectedEmail.auth?.dkim?.status.toLowerCase()} dmarc={selectedEmail.auth?.dmarc?.status.toLowerCase()}</div>
            </div>
          )}

          {activeDeepTab === 'timeline' && (
            <div className="space-y-3">
              {(selectedEmail.timeline || []).map((step: any, idx: number) => (
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
                    <td className="p-3 font-bold text-slate-900">{selectedEmail.sender?.originIp}</td>
                    <td className="p-3 text-red-600 font-bold">{selectedEmail.sender?.asn}</td>
                  </tr>
                  {selectedEmail.hashes?.sha256 && (
                    <tr>
                      <td className="p-3 text-slate-500">SHA-256</td>
                      <td className="p-3 text-slate-700 break-all">{selectedEmail.hashes.sha256}</td>
                      <td className="p-3 text-red-600 font-bold">Malicious Payload</td>
                    </tr>
                  )}
                  {selectedEmail.urls?.map((u: any, idx: number) => (
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
              {(selectedEmail.mitreAttack || []).map((m: any, idx: number) => (
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

      {/* Forensic Report Printable Modal */}
      <ForensicReportModal 
        email={selectedEmail}
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
      />

    </div>
  );
};
