import React, { useEffect, useState, useRef } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  RefreshCw, 
  Radio, 
  ExternalLink, 
  X, 
  Zap, 
  Mail,
  Volume2,
  VolumeX
} from 'lucide-react';
import { playRadarPingSound, playThreatAlarmSound, playSafeChimeSound } from '../engine/soundEffects';

interface LiveEmailInterceptorProps {
  onSelectEmailForForensics?: (email: any) => void;
}

export const LiveEmailInterceptor: React.FC<LiveEmailInterceptorProps> = ({
  onSelectEmailForForensics
}) => {
  const [isConnected, setIsConnected] = useState(false);
  const [connectedUser, setConnectedUser] = useState<string | null>(null);
  const [isSyncing, setIsSyncing] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [activeNotification, setActiveNotification] = useState<{
    email: any;
    timestamp: string;
  } | null>(null);

  const isPollingRef = useRef(false);
  const knownIdsRef = useRef<Set<string>>(new Set());

  // Initialize known IDs from existing localStorage
  useEffect(() => {
    try {
      const cached = localStorage.getItem('threatlens_custom_emails_db');
      if (cached) {
        const list = JSON.parse(cached);
        if (Array.isArray(list)) {
          list.forEach((e: any) => { if (e && e.id) knownIdsRef.current.add(e.id); });
        }
      }
    } catch (_) {}
  }, []);

  // Check OAuth status & run continuous active sync polling every 8 seconds
  useEffect(() => {
    let intervalId: any = null;

    const runSyncCycle = async () => {
      if (isPollingRef.current) return;
      isPollingRef.current = true;

      try {
        // 1. Check if OAuth account is active
        const statusRes = await fetch('/api/auth/status');
        if (!statusRes.ok) return;
        const statusData = await statusRes.json();
        
        setIsConnected(!!statusData.connected);
        setConnectedUser(statusData.user?.email || null);

        if (statusData.connected) {
          setIsSyncing(true);
          const syncRes = await fetch('/api/auth/google/sync', { method: 'POST' });
          if (syncRes.ok) {
            const syncData = await syncRes.json();
            if (syncData.success && syncData.emails) {
              const allEmails = syncData.emails;
              const newIncoming: any[] = [];

              // Check for genuinely new incoming messages
              allEmails.forEach((email: any) => {
                if (email && email.id && !knownIdsRef.current.has(email.id)) {
                  knownIdsRef.current.add(email.id);
                  newIncoming.push(email);
                }
              });

              if (newIncoming.length > 0) {
                // Save updated list to localStorage
                try {
                  localStorage.setItem('threatlens_custom_emails_db', JSON.stringify(allEmails));
                } catch (_) {}

                // Broadcast live update event to all views
                window.dispatchEvent(new CustomEvent('threatlens_emails_updated', {
                  detail: { emails: allEmails, newEmails: newIncoming }
                }));

                // Pick the most critical new email to alert the user
                newIncoming.sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0));
                const topEmail = newIncoming[0];

                // Play audio alert
                if (soundEnabled) {
                  const score = topEmail.threatScore ?? 0;
                  if (score > 80) {
                    playThreatAlarmSound(true);
                  } else if (score >= 50) {
                    playThreatAlarmSound(false);
                  } else {
                    playSafeChimeSound();
                  }
                }

                // Show floating real-time interception HUD
                setActiveNotification({
                  email: topEmail,
                  timestamp: new Date().toLocaleTimeString()
                });
              }
            }
          }
        }
      } catch (_) {
      } finally {
        setIsSyncing(false);
        isPollingRef.current = false;
      }
    };

    // Run first check immediately, then poll every 8 seconds
    runSyncCycle();
    intervalId = setInterval(runSyncCycle, 8000);

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [soundEnabled]);

  // Handle clicking on the notification toast
  const handleInspect = () => {
    if (activeNotification?.email && onSelectEmailForForensics) {
      onSelectEmailForForensics(activeNotification.email);
    }
    setActiveNotification(null);
  };

  return (
    <>
      {/* Floating Active Intercept Notification Banner */}
      {activeNotification && (() => {
        const email = activeNotification.email;
        const score = email.threatScore ?? 0;
        const isCritical = score > 80;
        const isMild = score >= 50 && score <= 80;
        
        const bgColor = isCritical ? 'bg-red-950/95 border-red-500' : (isMild ? 'bg-orange-950/95 border-orange-500' : 'bg-emerald-950/95 border-emerald-500');
        const badgeColor = isCritical ? 'bg-red-500 text-white' : (isMild ? 'bg-orange-500 text-white' : 'bg-emerald-500 text-white');
        const titleColor = isCritical ? 'text-red-300' : (isMild ? 'text-orange-300' : 'text-emerald-300');

        return (
          <div className="fixed bottom-6 right-6 z-50 max-w-md w-full animate-in slide-in-from-bottom-5 fade-in duration-300 pointer-events-auto">
            <div className={`border-2 rounded-2xl p-4 shadow-2xl backdrop-blur-xl text-white ${bgColor} space-y-3`}>
              <div className="flex items-center justify-between pb-2 border-b border-white/10">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-3 w-3">
                    <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${isCritical ? 'bg-red-400' : (isMild ? 'bg-orange-400' : 'bg-emerald-400')}`}></span>
                    <span className={`relative inline-flex rounded-full h-3 w-3 ${isCritical ? 'bg-red-500' : (isMild ? 'bg-orange-500' : 'bg-emerald-500')}`}></span>
                  </span>
                  <span className="text-xs font-mono font-black uppercase tracking-wider text-white">
                    {isCritical ? '🚨 CRITICAL THREAT INTERCEPTED' : (isMild ? '⚠️ SUSPICIOUS EMAIL FLAGGED' : '✅ CLEAN MESSAGE VERIFIED')}
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  <button 
                    onClick={() => setSoundEnabled(!soundEnabled)} 
                    className="p-1 text-white/60 hover:text-white rounded"
                    title={soundEnabled ? 'Mute Alert Sounds' : 'Unmute Alert Sounds'}
                  >
                    {soundEnabled ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5" />}
                  </button>
                  <button 
                    onClick={() => setActiveNotification(null)}
                    className="p-1 text-white/60 hover:text-white rounded"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className="space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold text-white truncate">{email.metadata?.subject || email.title}</span>
                  <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full shrink-0 ${badgeColor}`}>
                    Score: {score}/100
                  </span>
                </div>
                <div className="text-[11px] font-mono text-white/70 truncate">
                  From: {email.sender?.email || 'Unknown'} • Origin: {email.sender?.location || 'Direct IP'}
                </div>
                <p className={`text-xs ${titleColor} font-medium line-clamp-2 pt-0.5`}>
                  {email.simpleTakeaway || email.threatVerdict?.headline || 'Live email analyzed.'}
                </p>
              </div>

              <div className="flex items-center justify-between gap-2 pt-1">
                <span className="text-[10px] font-mono text-white/50">
                  {activeNotification.timestamp} • Live Ingest
                </span>
                <button
                  onClick={handleInspect}
                  className={`px-3.5 py-1.5 rounded-xl font-bold text-xs shadow-md transition-all flex items-center gap-1.5 cursor-pointer ${
                    isCritical 
                      ? 'bg-red-600 hover:bg-red-500 text-white' 
                      : (isMild ? 'bg-orange-600 hover:bg-orange-500 text-white' : 'bg-emerald-600 hover:bg-emerald-500 text-white')
                  }`}
                >
                  <Zap className="w-3.5 h-3.5" />
                  Inspect Forensic Breakdown
                </button>
              </div>
            </div>
          </div>
        );
      })()}
    </>
  );
};
