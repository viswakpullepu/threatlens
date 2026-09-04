import React from 'react';
import { 
  ShieldCheck, 
  Globe, 
  Microscope, 
  Database, 
  Mail, 
  Compass, 
  Cpu, 
  Search, 
  TerminalSquare, 
  Sparkles 
} from 'lucide-react';

export type ActiveTab = 
  | 'dashboard' 
  | 'forensics' 
  | 'intel' 
  | 'email' 
  | 'ambient' 
  | 'training' 
  | 'inspector' 
  | 'adversarial';

interface HeaderProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  ambientProtectionEnabled: boolean;
  setAmbientProtectionEnabled: (enabled: boolean) => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab
}) => {
  const tabs: { id: ActiveTab; label: string; icon: React.ReactNode; badge?: string }[] = [
    { id: 'dashboard', label: '3D Globe Dashboard', icon: <Globe className="w-4 h-4" /> },
    { id: 'forensics', label: 'Forensics', icon: <Microscope className="w-4 h-4" /> },
    { id: 'intel', label: 'Threat Intel', icon: <Database className="w-4 h-4" /> },
    { id: 'email', label: 'Encrypted Mail Shield', icon: <Mail className="w-4 h-4" />, badge: '200+ Vectors' },
    { id: 'ambient', label: 'Ambient Browser', icon: <Compass className="w-4 h-4" />, badge: '0.1ms' },
    { id: 'training', label: 'AI Training Matrix', icon: <Cpu className="w-4 h-4" /> },
    { id: 'inspector', label: 'Diagnostic Inspector', icon: <Search className="w-4 h-4" /> },
    { id: 'adversarial', label: 'Adversarial Lab', icon: <TerminalSquare className="w-4 h-4" /> }
  ];

  return (
    <>
      {/* Top Navigation Header */}
      <header className="sticky top-0 z-40 bg-white/95 backdrop-blur-md border-b border-slate-200 shadow-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          
          {/* Brand Logo & Platform Title */}
          <div className="flex items-center gap-3 shrink-0 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <div className="w-9 h-9 rounded-xl bg-indigo-600 flex items-center justify-center text-white shadow-md ring-1 ring-indigo-500">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base tracking-tight text-slate-950">
                  ThreatLens <span className="text-indigo-600 font-black">AI</span>
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                  ● AI ENGINE ACTIVE
                </span>
              </div>
              <p className="text-[11px] text-slate-500 hidden sm:block">
                AI-Powered Threat Detection, Geolocation & Forensic Intelligence
              </p>
            </div>
          </div>

          {/* Navigation Tabs (Scrollable on smaller screens) */}
          <nav className="flex items-center gap-1.5 p-1 bg-slate-100 rounded-2xl border border-slate-200 overflow-x-auto max-w-2xl py-1 px-1">
            {tabs.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-3.5 py-2 text-xs font-bold rounded-xl whitespace-nowrap transition-all ${
                    isActive
                      ? 'bg-slate-900 text-white shadow-md'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
                  }`}
                >
                  {tab.icon}
                  <span>{tab.label}</span>
                  {tab.badge && (
                    <span className={`text-[9px] px-1.5 py-0.2 rounded font-mono font-bold ${
                      isActive ? 'bg-indigo-500 text-white' : 'bg-indigo-100 text-indigo-700'
                    }`}>
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Quick Action CTA */}
          <div className="hidden lg:flex items-center gap-3 shrink-0">
            <button 
              onClick={() => setActiveTab('forensics')}
              className="px-3.5 py-2 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-bold rounded-xl transition-all flex items-center gap-1.5 shadow-2xs border border-indigo-200/60"
            >
              <Sparkles className="w-3.5 h-3.5 text-indigo-600" />
              Analyze with AI
            </button>
          </div>
        </div>
      </header>

      {/* Guided Status Banner */}
      <div className="bg-indigo-600 text-white text-xs py-2 px-4 shadow-inner">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="bg-white text-indigo-900 font-extrabold px-2 py-0.5 rounded text-[10px] uppercase tracking-wider">
              AI Platform
            </span>
            <span className="truncate">
              ThreatLens AI combines neural email NLP, real-time geolocation telemetry, and automated forensic intelligence.
            </span>
          </div>
          <span className="hidden md:inline font-mono opacity-80 text-[11px] shrink-0">
            AI Model: ThreatLens-v4.2 • Geolocation Online
          </span>
        </div>
      </div>
    </>
  );
};
