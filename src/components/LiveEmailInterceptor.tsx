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
  VolumeX,
  Bell
} from 'lucide-react';
import { playRadarPingSound, playThreatAlarmSound, playSafeChimeSound } from '../engine/soundEffects';

interface LiveEmailInterceptorProps {
  onSelectEmailForForensics?: (email: any) => void;
}

// Helper to get or generate persistent device session ID
export function getOrCreateSessionId(): string {
  if (typeof window === 'undefined') return 'ssr_client_session';
  
  // Check URL query param first
  const params = new URLSearchParams(window.location.search);
  const urlSession = params.get('session_id') || params.get('sessionId');
  if (urlSession && urlSession.length > 5 && urlSession !== 'default_client_session') {
    try {
      localStorage.setItem('threatlens_device_session_id', urlSession);
      document.cookie = `tl_session=${encodeURIComponent(urlSession)}; path=/; max-age=2592000; SameSite=Lax`;
    } catch (_) {}
    return urlSession;
  }

  // Check localStorage
  let sid = '';
  try {
    sid = localStorage.getItem('threatlens_device_session_id') || '';
    if (sid === 'default_client_session') {
      sid = '';
      localStorage.removeItem('threatlens_device_session_id');
    }
  } catch (_) {}

  if (!sid) {
    sid = 'tl_sess_' + (typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36));
    try {
      localStorage.setItem('threatlens_device_session_id', sid);
      document.cookie = `tl_session=${encodeURIComponent(sid)}; path=/; max-age=2592000; SameSite=Lax`;
    } catch (_) {}
  }

  return sid;
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
  const isInitialSyncRef = useRef(true);
  const knownIdsRef = useRef<Set<string>>(new Set());
  const notifiedIdsRef = useRef<Set<string>>(new Set());
  const sessionIdRef = useRef<string>(typeof window !== 'undefined' ? getOrCreateSessionId() : 'ssr_client_session');

  // Initialize session ID and known IDs from scoped localStorage
  useEffect(() => {
    sessionIdRef.current = getOrCreateSessionId();

    // Request desktop notification permission quietly on mount
    if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'default') {
      try {
        Notification.requestPermission().catch(() => {});
      } catch (_) {}
    }

    try {
      const cached = localStorage.getItem(`threatlens_custom_emails_db_${sessionIdRef.current}`);
      if (cached) {
        const list = JSON.parse(cached);
        if (Array.isArray(list)) {
          list.forEach((e: any) => { 
            if (e && e.id) knownIdsRef.current.add(e.id); 
          });
        }
      }
    } catch (_) {}
  }, []);

  // Check OAuth status & run continuous active sync polling every 5 seconds
  useEffect(() => {
    let intervalId: any = null;

    const runSyncCycle = async () => {
      if (isPollingRef.current) return;
      isPollingRef.current = true;

      try {
        const sid = sessionIdRef.current || getOrCreateSessionId();

        // 1. Check if OAuth account is active for this session
        const statusRes = await fetch(`/api/auth/status?session_id=${encodeURIComponent(sid)}`, {
          headers: { 'x-session-id': sid }
        });
        if (!statusRes.ok) return;
        const statusData = await statusRes.json();
        
        setIsConnected(!!statusData.connected);
        setConnectedUser(statusData.user?.email || null);

        if (statusData.connected) {
          setIsSyncing(true);
          const syncRes = await fetch(`/api/auth/google/sync?session_id=${encodeURIComponent(sid)}&limit=10`, { 
            method: 'POST',
            headers: { 'x-session-id': sid }
          });
          if (syncRes.ok) {
            const syncData = await syncRes.json();
            if (syncData.success && syncData.emails) {
              // Filter out any internal alert spam
              const allEmails = (syncData.emails || []).filter((e: any) => {
                const s = e?.metadata?.subject || e?.title || e?.subject || '';
                return !s.includes('[THREATLENS ALERT]');
              });

              // Initial sync after sign-in: silently establish baseline without blasting alarms for historical mailbox emails
              if (isInitialSyncRef.current || knownIdsRef.current.size === 0) {
                isInitialSyncRef.current = false;
                allEmails.forEach((email: any) => {
                  if (email && email.id) knownIdsRef.current.add(email.id);
                });
                try {
                  localStorage.setItem(`threatlens_custom_emails_db_${sid}`, JSON.stringify(allEmails));
                } catch (_) {}
                window.dispatchEvent(new CustomEvent('threatlens_emails_updated', {
                  detail: { emails: allEmails, newEmails: [], sessionId: sid }
                }));
                return;
              }

              // Subsequent polling: identify genuine new incoming messages
              const newIncoming: any[] = [];
              allEmails.forEach((email: any) => {
                if (email && email.id && !knownIdsRef.current.has(email.id)) {
                  knownIdsRef.current.add(email.id);
                  newIncoming.push(email);
                }
              });

              if (newIncoming.length > 0) {
                // Save updated list to session-scoped localStorage
                try {
                  localStorage.setItem(`threatlens_custom_emails_db_${sid}`, JSON.stringify(allEmails));
                } catch (_) {}

                // Broadcast live update event to all views
                window.dispatchEvent(new CustomEvent('threatlens_emails_updated', {
                  detail: { emails: allEmails, newEmails: newIncoming, sessionId: sid }
                }));

                // ONLY trigger loud sirens & floating intercept HUD for genuine critical attacks (score >= 80)
                const highRiskIncoming = newIncoming.filter(e => 
                  (e.threatScore || 0) >= 80 && 
                  e.isThreat && 
                  e.id && 
                  !notifiedIdsRef.current.has(e.id)
                );

                if (highRiskIncoming.length > 0) {
                  highRiskIncoming.sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0));
                  const topEmail = highRiskIncoming[0];
                  notifiedIdsRef.current.add(topEmail.id);
                  const score = topEmail.threatScore ?? 0;
                  const emailSubject = topEmail.metadata?.subject || topEmail.title || 'Inbound Message';

                  // 1. Native Desktop Notification for high-threat (>80)
                  if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'granted') {
                    try {
                      new Notification(
                        '🚨 CRITICAL THREAT INTERCEPTED',
                        {
                          body: `Threat Score: ${score}/100 [CRITICAL] - "${emailSubject}". High-risk attack vector flagged.`,
                          icon: '/favicon.ico',
                          tag: topEmail.id
                        }
                      );
                    } catch (_) {}
                  }

                  // 2. Play synthesized audio alert for confirmed critical threat
                  if (soundEnabled) {
                    playThreatAlarmSound(true);
                  }

                  // 3. Show floating real-time interception HUD
                  setActiveNotification({
                    email: topEmail,
                    timestamp: new Date().toLocaleTimeString()
                  });
                }
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

    // Run first check immediately, then poll every 20 seconds
    runSyncCycle();
    intervalId = setInterval(runSyncCycle, 20000);

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
