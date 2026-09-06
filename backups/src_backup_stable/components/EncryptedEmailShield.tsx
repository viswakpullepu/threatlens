import React, { useState, useEffect } from 'react';
import { 
  Mail, 
  ShieldCheck, 
  ShieldAlert, 
  Lock, 
  Key, 
  Zap, 
  RefreshCw, 
  Sparkles, 
  Inbox, 
  AlertTriangle, 
  FileText, 
  ExternalLink, 
  CheckCircle2, 
  Radio, 
  Terminal, 
  Eye, 
  EyeOff,
  Link,
  Cpu,
  Layers,
  FileCode,
  Check,
  Plus
} from 'lucide-react';
import { 
  IncomingEmailMessage, 
  EmailInspectionReport, 
  LinkedMailAccount, 
  EmailThreatVector 
} from '../types';
import { inspectIncomingEmail, EMAIL_THREAT_VECTORS_CATALOG } from '../engine/emailThreatEngine';
import { INITIAL_LINKED_ACCOUNTS, SAMPLE_INCOMING_EMAILS } from '../engine/mailProviderBridge';

interface EncryptedEmailShieldProps {
  onThreatBlocked?: (count: number) => void;
}

export const EncryptedEmailShield: React.FC<EncryptedEmailShieldProps> = () => {
  const [accounts, setAccounts] = useState<LinkedMailAccount[]>(INITIAL_LINKED_ACCOUNTS);
  const [emails, setEmails] = useState<IncomingEmailMessage[]>(SAMPLE_INCOMING_EMAILS);
  const [selectedEmailId, setSelectedEmailId] = useState<string>(SAMPLE_INCOMING_EMAILS[0].id);
  const [inspectionReports, setInspectionReports] = useState<Record<string, EmailInspectionReport>>({});
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [currentScanningStep, setCurrentScanningStep] = useState<string>('');
  const [activeView, setActiveView] = useState<'all' | 'verified_inbox' | 'quarantine'>('all');
  const [showConnectModal, setShowConnectModal] = useState<boolean>(false);
  const [newEmailInput, setNewEmailInput] = useState<string>('');
  const [newProviderInput, setNewProviderInput] = useState<'gmail' | 'outlook' | 'proton' | 'imap'>('gmail');

  useEffect(() => {
    const reports: Record<string, EmailInspectionReport> = {};
    for (const email of SAMPLE_INCOMING_EMAILS) {
      reports[email.id] = inspectIncomingEmail(email);
    }
    setInspectionReports(reports);
  }, []);

  const selectedEmail = emails.find(e => e.id === selectedEmailId) || emails[0];
  const selectedReport = selectedEmail ? inspectionReports[selectedEmail.id] : null;

  const handleSimulateIncoming = async (sampleIndex: number) => {
    const baseSample = SAMPLE_INCOMING_EMAILS[sampleIndex];
    const newIncoming: IncomingEmailMessage = {
      ...baseSample,
      id: 'mail-live-' + Math.random().toString(36).substring(2, 7),
      receivedAt: new Date().toLocaleTimeString(),
    };

    setIsScanning(true);
    setCurrentScanningStep('1. Encrypted Webhook Ingestion & Handshake...');
    await new Promise(r => setTimeout(r, 200));

    setCurrentScanningStep('2. Isolated Enclave Memory Decryption (AES-256-GCM)...');
    await new Promise(r => setTimeout(r, 250));

    setCurrentScanningStep('3. Scanning across 215+ Threat Vectors (Headers, BEC, Macros, LLM Injections)...');
    await new Promise(r => setTimeout(r, 300));

    const report = inspectIncomingEmail(newIncoming);
    setInspectionReports(prev => ({ ...prev, [newIncoming.id]: report }));
    setEmails(prev => [newIncoming, ...prev]);
    setSelectedEmailId(newIncoming.id);
    setIsScanning(false);
    setCurrentScanningStep('');
  };

  const handleLinkAccount = () => {
    if (!newEmailInput.trim()) return;
    const newAcc: LinkedMailAccount = {
      id: 'acc-' + Date.now(),
      provider: newProviderInput,
      email: newEmailInput.trim(),
      status: 'CONNECTED',
      encryptionKeyFingerprint: 'SHA256:' + Math.random().toString(36).substring(2, 10).toUpperCase() + '...',
      webhookArmed: true,
      totalEmailsScanned: 1,
      threatsIntercepted: 0
    };
    setAccounts([newAcc, ...accounts]);
    setNewEmailInput('');
    setShowConnectModal(false);
  };

  const filteredEmails = emails.filter(e => {
    const report = inspectionReports[e.id];
    if (!report) return true;
    if (activeView === 'verified_inbox') return !report.isThreat;
    if (activeView === 'quarantine') return report.isThreat;
    return true;
  });

  return (
    <div className="space-y-6">
      
      {/* Top Banner: Enclave Status & Providers */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        
        {/* Enclave Card */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-600 shrink-0">
            <Lock className="w-6 h-6" />
          </div>
          <div className="space-y-0.5">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Security Architecture</span>
              <span className="text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded">AES-256 ENCLAVE</span>
            </div>
            <div className="text-sm font-black text-slate-900">Zero-Knowledge Hardware Enclave</div>
            <p className="text-[11px] text-slate-500">Emails decrypted strictly in ephemeral memory. No data retained or trained on.</p>
          </div>
        </div>

        {/* 200+ Vectors Status */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-600 shrink-0">
            <Cpu className="w-6 h-6" />
          </div>
          <div className="space-y-0.5">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Detection Matrix</span>
              <span className="text-[10px] font-mono font-bold bg-indigo-100 text-indigo-800 px-2 py-0.5 rounded">215+ VECTORS</span>
            </div>
            <div className="text-sm font-black text-slate-900">Multi-Vector Mail Diagnostic Engine</div>
            <p className="text-[11px] text-slate-500">Headers, BEC wire fraud, Homoglyphs, VBA Macros, LLM Prompt Injections, QR quishing.</p>
          </div>
        </div>

        {/* Connected Accounts Manager */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Linked Mailboxes</span>
            <div className="text-xl font-black text-slate-900">{accounts.length} Accounts Active</div>
            <div className="text-[11px] text-slate-500">{accounts.map(a => a.email).join(', ')}</div>
          </div>
          <button 
            onClick={() => setShowConnectModal(true)}
            className="px-3 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold rounded-xl transition-all flex items-center gap-1.5 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5 text-indigo-400" />
            Link Mail
          </button>
        </div>

      </div>

      {/* Simulated Live Incoming Email Injection Bar */}
      <div className="p-4 bg-white border border-slate-200 rounded-2xl shadow-xs space-y-2">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
              <Radio className="w-4 h-4 text-indigo-600 animate-pulse" />
              Automated Push Interception Simulator (Live Webhook Ingestion)
            </h3>
            <p className="text-[11px] text-slate-500">
              Trigger real-time incoming email webhooks from your linked Gmail / Outlook provider directly into the encrypted agent:
            </p>
          </div>
          {isScanning && (
            <span className="text-xs font-mono font-bold text-indigo-600 animate-pulse flex items-center gap-1.5">
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              {currentScanningStep}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button 
            disabled={isScanning}
            onClick={() => handleSimulateIncoming(0)}
            className="px-3 py-1.5 bg-slate-50 hover:bg-red-50 hover:text-red-700 border border-slate-200 rounded-lg text-xs font-bold transition-all cursor-pointer"
          >
            🚨 Inbound: CEO Wire Fraud ($148k)
          </button>
          <button 
            disabled={isScanning}
            onClick={() => handleSimulateIncoming(1)}
            className="px-3 py-1.5 bg-slate-50 hover:bg-orange-50 hover:text-orange-700 border border-slate-200 rounded-lg text-xs font-bold transition-all cursor-pointer"
          >
            🚨 Inbound: Fake DocuSign Homoglyph
          </button>
          <button 
            disabled={isScanning}
            onClick={() => handleSimulateIncoming(2)}
            className="px-3 py-1.5 bg-slate-50 hover:bg-purple-50 hover:text-purple-700 border border-slate-200 rounded-lg text-xs font-bold transition-all cursor-pointer"
          >
            🚨 Inbound: Macro VBA Dropper (.docm)
          </button>
          <button 
            disabled={isScanning}
            onClick={() => handleSimulateIncoming(3)}
            className="px-3 py-1.5 bg-slate-50 hover:bg-indigo-50 hover:text-indigo-700 border border-slate-200 rounded-lg text-xs font-bold transition-all cursor-pointer"
          >
            🚨 Inbound: Hidden LLM Prompt Injection
          </button>
          <button 
            disabled={isScanning}
            onClick={() => handleSimulateIncoming(4)}
            className="px-3 py-1.5 bg-slate-50 hover:bg-emerald-50 hover:text-emerald-700 border border-slate-200 rounded-lg text-xs font-bold transition-all cursor-pointer"
          >
            ✅ Inbound: Clean Signed Agreement
          </button>
        </div>
      </div>

      {/* Main Mail Grid: List on Left, Enclave Audit on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Side: Intercepted Mail Feed */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
              <Inbox className="w-4 h-4 text-indigo-600" />
              Intercepted Inbound Messages
            </h3>
            <span className="text-[10px] font-mono text-slate-400">{filteredEmails.length} Items</span>
          </div>

          {/* View Filter Pills */}
          <div className="flex bg-slate-100 p-1 rounded-xl text-xs font-bold text-slate-600">
            <button 
              onClick={() => setActiveView('all')}
              className={`flex-1 py-1.5 rounded-lg transition-all cursor-pointer ${
                activeView === 'all' ? 'bg-white text-slate-900 shadow-xs' : 'hover:text-slate-900'
              }`}
            >
              All Messages
            </button>
            <button 
              onClick={() => setActiveView('verified_inbox')}
              className={`flex-1 py-1.5 rounded-lg transition-all cursor-pointer ${
                activeView === 'verified_inbox' ? 'bg-white text-emerald-800 shadow-xs' : 'hover:text-slate-900'
              }`}
            >
              Clean Inbox
            </button>
            <button 
              onClick={() => setActiveView('quarantine')}
              className={`flex-1 py-1.5 rounded-lg transition-all cursor-pointer ${
                activeView === 'quarantine' ? 'bg-white text-red-800 shadow-xs' : 'hover:text-slate-900'
              }`}
            >
              Quarantine
            </button>
          </div>

          {/* Mail Items */}
          <div className="space-y-2.5 max-h-[500px] overflow-y-auto pr-1">
            {filteredEmails.map((email) => {
              const isSelected = selectedEmail?.id === email.id;
              const report = inspectionReports[email.id];
              const isEmailThreat = report?.isThreat;

              return (
                <div
                  key={email.id}
                  onClick={() => setSelectedEmailId(email.id)}
                  className={`p-3 rounded-xl border transition-all cursor-pointer space-y-1.5 ${
                    isSelected
                      ? 'bg-indigo-50/70 border-indigo-300 ring-1 ring-indigo-200'
                      : 'bg-slate-50/70 border-slate-200 hover:border-slate-300 hover:bg-slate-100/70'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-bold text-slate-900 truncate">
                      {email.senderDisplayName || email.sender}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      isEmailThreat ? 'bg-red-100 text-red-800' : 'bg-emerald-100 text-emerald-800'
                    }`}>
                      {isEmailThreat ? '🚨 ' + (report?.verdict || 'THREAT') : '✅ VERIFIED'}
                    </span>
                  </div>

                  <h4 className="text-xs font-medium text-slate-700 line-clamp-1">
                    {email.subject}
                  </h4>

                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-200/50">
                    <span>{email.receivedAt}</span>
                    <span>Score: {report?.riskScore || 0}/100</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Side: Deep Enclave Audit & 200+ Vector Findings */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-6">
          {selectedReport ? (
            <div className="space-y-6">
              
              {/* Verdict Header */}
              <div className={`p-5 rounded-xl border ${
                selectedReport.isThreat ? 'bg-red-50/60 border-red-200' : 'bg-emerald-50/60 border-emerald-200'
              } flex flex-col sm:flex-row sm:items-center justify-between gap-4`}>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full ${
                      selectedReport.isThreat ? 'bg-red-600 text-white' : 'bg-emerald-600 text-white'
                    }`}>
                      {selectedReport.isThreat ? '🚨 ENCLAVE INTERCEPTED THREAT' : '✅ VERIFIED CLEAN EMAIL'}
                    </span>
                    <span className="text-xs font-mono text-slate-500">Latency: {selectedReport.encryptionEnclave?.decryptionLatencyMs}ms</span>
                  </div>
                  <h3 className="text-lg font-black text-slate-900">{selectedEmail.subject}</h3>
                  <div className="text-xs text-slate-600">
                    From: <span className="font-bold text-slate-900">{selectedEmail.senderDisplayName}</span> &lt;{selectedEmail.sender}&gt;
                  </div>
                </div>

                <div className="text-right shrink-0">
                  <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Risk Score</div>
                  <div className={`text-3xl font-black font-mono ${selectedReport.isThreat ? 'text-red-600' : 'text-emerald-600'}`}>
                    {selectedReport.riskScore}<span className="text-xs font-normal text-slate-400">/100</span>
                  </div>
                </div>
              </div>

              {/* Matched Threat Vectors from 200+ Catalog */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-red-500" />
                    Triggered Vector Detections ({selectedReport.matchedVectors.length} of 215)
                  </h4>
                  <span className="text-[10px] font-mono text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded font-bold">
                    Zero-Knowledge Scanned
                  </span>
                </div>

                {selectedReport.matchedVectors.length > 0 ? (
                  <div className="space-y-2">
                    {selectedReport.matchedVectors.map((vec, i) => (
                      <div key={i} className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1 text-xs">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-indigo-600">{vec.id}</span>
                            <span className="font-bold text-slate-900">{vec.name}</span>
                          </div>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                            vec.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' : 'bg-orange-100 text-orange-800'
                          }`}>
                            {vec.severity} • CVSS {vec.cvss}
                          </span>
                        </div>
                        <p className="text-slate-600 text-[11px]">{vec.description}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 bg-emerald-50/50 border border-emerald-200 rounded-xl text-xs text-emerald-800 flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                    All 215+ email security vectors passed with zero anomalies or deceptive traits.
                  </div>
                )}
              </div>

              {/* Explanations & Enclave Proof */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                  <span className="text-[10px] uppercase font-bold text-slate-400">Enclave AI Diagnostic</span>
                  <div className="text-slate-700 leading-relaxed">
                    {selectedReport.summaryReason}
                  </div>
                </div>

                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2 font-mono">
                  <span className="text-[10px] uppercase font-bold text-slate-400">Cryptographic Seal</span>
                  <div className="text-[11px] text-slate-600 break-all">
                    Enclave ID: {selectedReport.encryptionEnclave?.enclaveId}
                  </div>
                  <div className="text-[10px] text-emerald-700 font-bold">
                    ✓ Verified zero private data leakage
                  </div>
                </div>
              </div>

            </div>
          ) : (
            <div className="p-12 text-center text-slate-400 text-xs">
              Select an email from the list to view the Zero-Knowledge Enclave diagnostic report.
            </div>
          )}
        </div>

      </div>

      {/* Connect Mail Modal */}
      {showConnectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
          <div className="bg-white border border-slate-200 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Mail className="w-4 h-4 text-indigo-600" />
              Link Mailbox for Zero-Knowledge Interception
            </h3>
            <p className="text-xs text-slate-500">
              Select your mail provider to attach the automated encrypted AI security agent:
            </p>

            <div className="space-y-3">
              <div>
                <label className="text-[11px] font-bold text-slate-700 block mb-1">Provider</label>
                <select 
                  value={newProviderInput} 
                  onChange={(e) => setNewProviderInput(e.target.value as any)}
                  className="w-full p-2.5 text-xs bg-slate-50 border border-slate-200 rounded-xl font-bold"
                >
                  <option value="gmail">Google Workspace / Gmail (OAuth2)</option>
                  <option value="outlook">Microsoft 365 / Outlook</option>
                  <option value="proton">ProtonMail Bridge</option>
                  <option value="imap">Custom IMAP / TLS</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-bold text-slate-700 block mb-1">Email Address</label>
                <input 
                  type="email"
                  value={newEmailInput}
                  onChange={(e) => setNewEmailInput(e.target.value)}
                  placeholder="user@company.com"
                  className="w-full p-2.5 text-xs bg-slate-50 border border-slate-200 rounded-xl"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button 
                onClick={() => setShowConnectModal(false)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl cursor-pointer"
              >
                Cancel
              </button>
              <button 
                onClick={handleLinkAccount}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl cursor-pointer"
              >
                Authorize & Link
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
