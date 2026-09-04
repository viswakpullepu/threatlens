import React, { useState } from 'react';
import { Header, ActiveTab } from './components/Header';
import { GlobeView } from './components/GlobeView';
import { ForensicsView } from './components/ForensicsView';
import { ThreatIntelligenceView } from './components/ThreatIntelligenceView';
import { EncryptedEmailShield } from './components/EncryptedEmailShield';
import { AmbientBrowserShield } from './components/AmbientBrowserShield';
import { AITrainingStudio } from './components/AITrainingStudio';
import { ThreatInspector } from './components/ThreatInspector';
import { AdversarialLab } from './components/AdversarialLab';
import { ThreatAnalysisResult, ModelMetrics, LiveThreatLog } from './types';
import { trainingEngineInstance } from './engine/trainingEngine';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [metrics, setMetrics] = useState<ModelMetrics>(trainingEngineInstance.getMetrics());
  const [ambientProtectionEnabled, setAmbientProtectionEnabled] = useState<boolean>(true);
  const [threatsBlockedCount, setThreatsBlockedCount] = useState<number>(185);

  const [threatLogs, setThreatLogs] = useState<LiveThreatLog[]>([
    {
      id: 'log-01',
      timestamp: '23:02:15',
      source: 'Gmail Encrypted Agent',
      targetUrl: 'alex.vance@workcorp.io',
      payloadSummary: "CEO Wire Transfer BEC Fraud ($148,500.00)",
      category: 'phishing_url',
      severity: 'CRITICAL',
      actionTaken: 'QUARANTINED',
      latencyMs: 0.18
    },
    {
      id: 'log-02',
      timestamp: '22:58:40',
      source: 'Gmail Encrypted Agent',
      targetUrl: 'alex.vance@workcorp.io',
      payloadSummary: "Fake DocuSign Phishing (auth.docusign-login.top)",
      category: 'phishing_url',
      severity: 'HIGH',
      actionTaken: 'SANITIZED',
      latencyMs: 0.21
    },
    {
      id: 'log-03',
      timestamp: '22:51:10',
      source: 'Outlook Encrypted Agent',
      targetUrl: 'alex.security@apexenterprise.com',
      payloadSummary: "Macro VBA Shellcode Dropper (Invoice_849182.docm)",
      category: 'obfuscated_code',
      severity: 'CRITICAL',
      actionTaken: 'QUARANTINED',
      latencyMs: 0.24
    },
    {
      id: 'log-04',
      timestamp: '22:45:00',
      source: 'Gmail Encrypted Agent',
      targetUrl: 'alex.vance@workcorp.io',
      payloadSummary: "Hidden LLM Prompt Injection targeting AI Summarizer",
      category: 'prompt_injection',
      severity: 'HIGH',
      actionTaken: 'SANITIZED',
      latencyMs: 0.19
    },
    {
      id: 'log-05',
      timestamp: '22:30:12',
      source: 'Ambient Browser Shield',
      targetUrl: 'https://apexbank.internal/auth/login',
      payloadSummary: "' OR '1'='1' -- Bypass Attempt",
      category: 'sqli',
      severity: 'CRITICAL',
      actionTaken: 'SANITIZED',
      latencyMs: 0.12
    }
  ]);

  const handleThreatDetected = (
    result: ThreatAnalysisResult,
    source: string,
    action: 'BLOCKED' | 'SANITIZED' | 'ALLOWED'
  ) => {
    if (result.isThreat) {
      setThreatsBlockedCount(c => c + 1);
    }
    const newLog: LiveThreatLog = {
      id: 'log-' + Date.now(),
      timestamp: new Date().toLocaleTimeString(),
      source,
      targetUrl: source,
      payloadSummary: result.input.length > 50 ? result.input.slice(0, 50) + '...' : result.input,
      category: result.primaryCategory,
      severity: result.severity,
      actionTaken: action,
      latencyMs: 0.15
    };
    setThreatLogs(prev => [newLog, ...prev.slice(0, 49)]);
  };

  return (
    <div className="min-h-screen flex flex-col font-sans bg-slate-50 text-slate-900 antialiased selection:bg-indigo-500 selection:text-white">
      
      {/* Top Navigation Header & Guided Status Banner */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        ambientProtectionEnabled={ambientProtectionEnabled}
        setAmbientProtectionEnabled={setAmbientProtectionEnabled}
      />

      {/* Main Dynamic View Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {/* VIEW 1: 3D Global Dashboard */}
        {activeTab === 'dashboard' && (
          <GlobeView 
            onSelectThreat={(id) => {}}
            onOpenForensics={() => setActiveTab('forensics')}
          />
        )}

        {/* VIEW 2: Forensics Suite */}
        {activeTab === 'forensics' && (
          <ForensicsView />
        )}

        {/* VIEW 3: Threat Intelligence */}
        {activeTab === 'intel' && (
          <ThreatIntelligenceView />
        )}

        {/* VIEW 4: Encrypted Mail Shield */}
        {activeTab === 'email' && (
          <EncryptedEmailShield 
            onThreatBlocked={(cnt) => setThreatsBlockedCount(c => c + cnt)}
          />
        )}

        {/* VIEW 5: Ambient Browser Shield */}
        {activeTab === 'ambient' && (
          <AmbientBrowserShield 
            onThreatDetected={handleThreatDetected}
            ambientProtectionEnabled={ambientProtectionEnabled}
          />
        )}

        {/* VIEW 6: AI Training Matrix */}
        {activeTab === 'training' && (
          <AITrainingStudio 
            onMetricsUpdated={(m: ModelMetrics) => setMetrics(m)}
          />
        )}

        {/* VIEW 7: Diagnostic Inspector */}
        {activeTab === 'inspector' && (
          <ThreatInspector />
        )}

        {/* VIEW 8: Adversarial Lab */}
        {activeTab === 'adversarial' && (
          <AdversarialLab />
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-6 mt-12 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-extrabold text-slate-900">ThreatLens AI</span>
            <span>• Multi-Vector Autonomous Threat Defense & Forensics</span>
          </div>
          <div className="text-[11px] text-slate-400">
            Compliant with NIST SP 800-86 & MITRE ATT&CK Framework
          </div>
        </div>
      </footer>

    </div>
  );
};
