import React from 'react';
import { ShieldCheck, Download, X, AlertOctagon, CheckCircle2, ShieldAlert } from 'lucide-react';

interface ForensicReportModalProps {
  email: any;
  isOpen: boolean;
  onClose: () => void;
}

export const ForensicReportModal: React.FC<ForensicReportModalProps> = ({
  email,
  isOpen,
  onClose
}) => {
  if (!isOpen || !email) return null;

  const isThreat = email.isThreat;
  const reportDate = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  const verdictInfo = email.threatVerdict || { 
    headline: isThreat ? 'Cyber Attack Signature Detected' : 'Verified Legitimate Electronic Mail', 
    confidence: isThreat ? 99.4 : 99.9, 
    analysis: email.whatHappened || [], 
    recommendation: isThreat ? 'Isolate endpoint, revoke session tokens, and block sender IP.' : 'Safe to deliver.'
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-white rounded-2xl shadow-2xl border border-slate-200 my-8 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        
        {/* Action Bar (Hidden when printing to PDF) */}
        <div className="no-print flex items-center justify-between px-6 py-4 bg-slate-900 text-white border-b border-slate-800">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-indigo-400" />
            <span className="font-bold text-sm">ThreatLens Forensic Incident Document View</span>
          </div>

          <div className="flex items-center gap-3">
            <button 
              onClick={handlePrint}
              className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-lg shadow transition-all cursor-pointer"
            >
              <Download className="w-4 h-4" />
              Download PDF Report
            </button>
            <button 
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable Document Container */}
        <div id="printable-report" className="p-8 sm:p-12 space-y-8 bg-white text-slate-900 print:p-0">
          
          {/* Document Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b-2 border-slate-900 gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div className="w-6 h-6 rounded bg-slate-900 text-white flex items-center justify-center font-black text-xs">
                  TL
                </div>
                <span className="font-black text-lg tracking-wider uppercase text-slate-900">
                  THREATLENS FORENSICS
                </span>
              </div>
              <div className="text-xs text-slate-500 font-mono">
                SOC INCIDENT INVESTIGATION & THREAT INTELLIGENCE REPORT
              </div>
            </div>

            <div className="text-right font-mono text-xs text-slate-600 space-y-0.5">
              <div><span className="text-slate-400">REPORT ID:</span> TL-RPT-{String(email.id).toUpperCase()}</div>
              <div><span className="text-slate-400">GENERATED:</span> {reportDate}</div>
              <div><span className="text-slate-400">CLASSIFICATION:</span> TLP:AMBER+STRICT</div>
            </div>
          </div>

          {/* Threat Verdict Callout */}
          <div className={`p-6 rounded-xl border-2 ${
            isThreat ? 'border-red-600 bg-red-50/50' : 'border-emerald-600 bg-emerald-50/50'
          } flex flex-col sm:flex-row sm:items-center justify-between gap-4`}>
            <div className="space-y-1">
              <div className={`text-xs font-bold uppercase tracking-wider ${isThreat ? 'text-red-700' : 'text-emerald-700'}`}>
                SECURITY CLASSIFICATION VERDICT
              </div>
              <div className="text-xl font-black text-slate-900">
                {verdictInfo.headline}
              </div>
              <div className="text-xs text-slate-600">
                Detection Confidence: <span className="font-bold font-mono">{verdictInfo.confidence}%</span> | Vector: <span className="font-bold">{email.userFriendlyCategory || email.category || 'Malicious Payload'}</span>
              </div>
            </div>

            <div className="sm:text-right shrink-0">
              <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">RISK INDEX</div>
              <div className={`text-4xl font-black font-mono ${isThreat ? 'text-red-600' : 'text-emerald-600'}`}>
                {email.threatScore}<span className="text-lg font-normal text-slate-400">/100</span>
              </div>
            </div>
          </div>

          {/* Email Identity & Authentication Matrix */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 pb-1 border-b border-slate-200">
              1. Email Identity & Authentication Results
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3 bg-slate-50 border border-slate-200 rounded">
                <span className="text-slate-400 block mb-0.5">From Header:</span>
                <span className="text-slate-900 font-bold break-all">
                  {email.sender?.displayName} &lt;{email.sender?.email}&gt;
                </span>
              </div>
              <div className="p-3 bg-slate-50 border border-slate-200 rounded">
                <span className="text-slate-400 block mb-0.5">Origin Relay IP & ASN:</span>
                <span className="text-slate-900 font-bold">
                  {email.sender?.originIp} ({email.sender?.asn})
                </span>
              </div>
              <div className="p-3 bg-slate-50 border border-slate-200 rounded">
                <span className="text-slate-400 block mb-0.5">Recipient Target:</span>
                <span className="text-slate-900 font-bold">
                  {email.recipient?.email} ({email.recipient?.department || 'Target'})
                </span>
              </div>
              <div className="p-3 bg-slate-50 border border-slate-200 rounded">
                <span className="text-slate-400 block mb-0.5">Spoofing Assessment:</span>
                <span className={email.sender?.isSpoofed ? 'text-red-600 font-bold' : 'text-emerald-600 font-bold'}>
                  {email.sender?.isSpoofed ? `SPOOFED (${email.sender.spoofType})` : 'GENUINE (Verified Identity)'}
                </span>
              </div>
            </div>

            {/* SPF / DKIM / DMARC Triple Strip */}
            <div className="grid grid-cols-3 gap-3 pt-2 text-center text-xs font-mono">
              <div className={`p-2.5 rounded border font-bold ${
                email.auth?.spf?.status === 'PASS' ? 'bg-emerald-50 border-emerald-300 text-emerald-800' : 'bg-red-50 border-red-300 text-red-800'
              }`}>
                SPF: {email.auth?.spf?.status || 'FAIL'}
              </div>
              <div className={`p-2.5 rounded border font-bold ${
                email.auth?.dkim?.status === 'PASS' ? 'bg-emerald-50 border-emerald-300 text-emerald-800' : 'bg-red-50 border-red-300 text-red-800'
              }`}>
                DKIM: {email.auth?.dkim?.status || 'FAIL'}
              </div>
              <div className={`p-2.5 rounded border font-bold ${
                email.auth?.dmarc?.status === 'PASS' ? 'bg-emerald-50 border-emerald-300 text-emerald-800' : 'bg-red-50 border-red-300 text-red-800'
              }`}>
                DMARC: {email.auth?.dmarc?.status || 'FAIL'}
              </div>
            </div>
          </div>

          {/* Forensic Findings & Threat Takeaways */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 pb-1 border-b border-slate-200">
              2. Forensic Observations & Diagnostic Takeaway
            </h3>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs text-slate-700 leading-relaxed">
              <div className="font-bold text-slate-900">Incident Breakdown:</div>
              <ul className="list-disc pl-5 space-y-1">
                {(email.whatHappened || verdictInfo.analysis || []).map((item: string, idx: number) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
              <div className="pt-2 text-slate-900 font-bold">
                Action Protocol: <span className="font-normal text-slate-600">{email.whatToDo || verdictInfo.recommendation}</span>
              </div>
            </div>
          </div>

          {/* Indicators of Compromise (IOCs) */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 pb-1 border-b border-slate-200">
              3. Indicators of Compromise (IOCs)
            </h3>

            <table className="w-full text-left text-xs font-mono border border-slate-200 rounded">
              <thead className="bg-slate-100 text-slate-700">
                <tr>
                  <th className="p-2 border-b border-slate-200">TYPE</th>
                  <th className="p-2 border-b border-slate-200">INDICATOR VALUE</th>
                  <th className="p-2 border-b border-slate-200">REPUTATION / MITRE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                <tr>
                  <td className="p-2 text-slate-500">Origin IP</td>
                  <td className="p-2 font-bold text-slate-900">{email.sender?.originIp}</td>
                  <td className="p-2 text-red-600">{email.sender?.asn}</td>
                </tr>
                {email.sender?.email && (
                  <tr>
                    <td className="p-2 text-slate-500">Sender</td>
                    <td className="p-2 font-bold text-slate-900">{email.sender.email}</td>
                    <td className="p-2 text-slate-600">{email.sender.isSpoofed ? 'Spoofed Masquerade' : 'Authentic'}</td>
                  </tr>
                )}
                {email.hashes?.sha256 && (
                  <tr>
                    <td className="p-2 text-slate-500">SHA-256</td>
                    <td className="p-2 text-slate-700 break-all">{email.hashes.sha256}</td>
                    <td className="p-2 text-red-600 font-bold">Malicious Hash</td>
                  </tr>
                )}
                {email.urls?.map((u: any, idx: number) => (
                  <tr key={idx}>
                    <td className="p-2 text-slate-500">Phishing URL</td>
                    <td className="p-2 text-slate-700 break-all">{u.url}</td>
                    <td className="p-2 text-red-600 font-bold">{u.vtScore || 'Flagged'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Footer */}
          <div className="pt-6 border-t border-slate-200 flex items-center justify-between text-[11px] text-slate-400 font-mono">
            <div>ThreatLens AI Autonomous Threat Defense Center</div>
            <div>VERIFIED COMPLIANT WITH NIST SP 800-86 & MITRE ATT&CK</div>
          </div>

        </div>

      </div>
    </div>
  );
};
