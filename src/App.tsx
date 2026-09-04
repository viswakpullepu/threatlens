import React, { useState } from 'react';
import { Header, ActiveTab } from './components/Header';
import { GlobeView } from './components/GlobeView';
import { ForensicsView } from './components/ForensicsView';
import { ThreatIntelligenceView } from './components/ThreatIntelligenceView';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');

  return (
    <div className="min-h-screen flex flex-col font-sans bg-slate-50 text-slate-900 antialiased selection:bg-indigo-500 selection:text-white">
      
      {/* Top Navigation Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      {/* Main Dynamic View Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {/* VIEW 1: Dashboard (3D Global Map) */}
        {activeTab === 'dashboard' && (
          <GlobeView 
            onSelectThreat={(id) => {}}
            onOpenForensics={() => setActiveTab('forensics')}
          />
        )}

        {/* VIEW 2: Forensics Investigation Suite */}
        {activeTab === 'forensics' && (
          <ForensicsView />
        )}

        {/* VIEW 3: Threat Intelligence & IOC Database */}
        {activeTab === 'intel' && (
          <ThreatIntelligenceView />
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
