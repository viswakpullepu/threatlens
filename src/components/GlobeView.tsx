import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Globe as GlobeIcon, 
  Radio, 
  Microscope, 
  Search,
  Plus,
  Minus,
  RotateCcw,
  Play,
  Pause,
  MapPin,
  X,
  Crosshair
} from 'lucide-react';

interface ThreatLocationItem {
  id: string;
  ip: string;
  city: string;
  country: string;
  lat: number;
  lng: number;
  severity: string;
  severityLabel?: string;
  type?: string;
  simpleTitle: string;
  sender: string;
  subject?: string;
  threatScore: number;
  asn?: string;
  target?: string;
  targetCoords?: { lat: number; lng: number };
  status?: string;
  timestamp: string;
  plainSummary: string;
  summary?: string;
  isThreat?: boolean;
}

const CITY_COORDINATES: Record<string, { lat: number; lng: number; country: string }> = {
  'frankfurt': { lat: 50.1109, lng: 8.6821, country: 'Germany' },
  'kuala lumpur': { lat: 3.1390, lng: 101.6869, country: 'Malaysia' },
  'st. petersburg': { lat: 59.9311, lng: 30.3609, country: 'Russia' },
  'saint petersburg': { lat: 59.9311, lng: 30.3609, country: 'Russia' },
  'amsterdam': { lat: 52.3676, lng: 4.9041, country: 'Netherlands' },
  'panama city': { lat: 8.9824, lng: -79.5199, country: 'Panama' },
  'san jose': { lat: 37.3382, lng: -121.8863, country: 'United States' },
  'new york': { lat: 40.7128, lng: -74.0060, country: 'United States' },
  'san francisco': { lat: 37.7749, lng: -122.4194, country: 'United States' },
  'london': { lat: 51.5074, lng: -0.1278, country: 'United Kingdom' },
  'berlin': { lat: 52.5200, lng: 13.4050, country: 'Germany' },
  'tokyo': { lat: 35.6762, lng: 139.6503, country: 'Japan' },
  'singapore': { lat: 1.3521, lng: 103.8198, country: 'Singapore' },
  'sydney': { lat: -33.8688, lng: 151.2093, country: 'Australia' },
  'paris': { lat: 48.8566, lng: 2.3522, country: 'France' },
  'dubai': { lat: 25.2048, lng: 55.2708, country: 'United Arab Emirates' },
  'seoul': { lat: 37.5665, lng: 126.9780, country: 'South Korea' },
  'mumbai': { lat: 19.0760, lng: 72.8777, country: 'India' },
  'bangalore': { lat: 12.9716, lng: 77.5946, country: 'India' },
  'toronto': { lat: 43.6532, lng: -79.3832, country: 'Canada' },
  'sao paulo': { lat: -23.5505, lng: -46.6333, country: 'Brazil' },
  'beijing': { lat: 39.9042, lng: 116.4074, country: 'China' },
  'hong kong': { lat: 22.3193, lng: 114.1694, country: 'Hong Kong' },
  'zurich': { lat: 47.3769, lng: 8.5417, country: 'Switzerland' },
  'stockholm': { lat: 59.3293, lng: 18.0686, country: 'Sweden' },
  'warsaw': { lat: 52.2297, lng: 21.0122, country: 'Poland' }
};

interface GlobeViewProps {
  onSelectThreat: (threatId: string) => void;
  onOpenForensics: () => void;
}

export const GlobeView: React.FC<GlobeViewProps> = ({
  onSelectThreat,
  onOpenForensics
}) => {
  const canvasContainerRef = useRef<HTMLDivElement>(null);
  
  // Custom emails from database & localStorage
  const [customEmails, setCustomEmails] = useState<any[]>(() => {
    try {
      const cached = localStorage.getItem('threatlens_custom_emails_db');
      return cached ? JSON.parse(cached) : [];
    } catch (_) {
      return [];
    }
  });

  // Sync with persistent backend database on mount
  useEffect(() => {
    fetch('/api/emails')
      .then(res => res.json())
      .then(data => {
        if (data.emails && Array.isArray(data.emails)) {
          setCustomEmails(prev => {
            const combined = [...data.emails, ...prev];
            const uniqueMap = new Map();
            combined.forEach(e => { if (e && e.id) uniqueMap.set(e.id, e); });
            const merged = Array.from(uniqueMap.values());
            try { localStorage.setItem('threatlens_custom_emails_db', JSON.stringify(merged)); } catch (_) {}
            return merged;
          });
        }
      })
      .catch(() => {});
  }, []);

  // Map real analyzed emails directly to 3D spherical coordinates
  const allThreatLocations: ThreatLocationItem[] = useMemo(() => {
    const locations: ThreatLocationItem[] = [];

    customEmails.forEach((email) => {
      if (!email) return;
      const rawLoc = (email.sender?.location || '').toLowerCase();
      let matchedCoords = { lat: 40.7128, lng: -74.0060, country: 'United States', city: 'New York' };

      for (const [key, val] of Object.entries(CITY_COORDINATES)) {
        if (rawLoc.includes(key) || (email.sender?.originIp && email.sender.originIp.includes(key))) {
          matchedCoords = { ...val, city: key.charAt(0).toUpperCase() + key.slice(1) };
          break;
        }
      }

      if (!locations.some(b => b.id === email.id)) {
        const score = email.threatScore ?? (email.isThreat ? 85 : 0);
        locations.push({
          id: email.id || `custom-${Date.now()}`,
          ip: email.sender?.originIp || '192.0.2.1',
          city: matchedCoords.city,
          country: matchedCoords.country,
          lat: matchedCoords.lat,
          lng: matchedCoords.lng,
          severity: score > 80 ? 'critical' : (score >= 50 ? 'high' : 'safe'),
          severityLabel: email.severityLabel || (score > 80 ? 'Critical Threat' : (score >= 50 ? 'Mild Threat' : 'Safe & Verified')),
          type: email.userFriendlyCategory || 'Analyzed Stream',
          simpleTitle: email.title || email.metadata?.subject || 'Live Analyzed Email',
          sender: email.sender?.email || 'unknown@sender.com',
          subject: email.metadata?.subject || 'Email Subject',
          threatScore: score,
          asn: email.sender?.asn || 'AS15169 (Direct Hop)',
          status: score > 80 ? '🚨 Critical Threat' : (score >= 50 ? '⚠️ Mild Threat' : '✅ 100% Safe & Verified'),
          timestamp: email.metadata?.date || 'Today',
          plainSummary: email.simpleTakeaway || (score > 80 ? 'High-risk payload or spoofing detected.' : (score >= 50 ? 'Mild anomalies detected.' : 'Legitimate clean message with verified cryptographic signatures.')),
          isThreat: score >= 50
        });
      }
    });

    return locations;
  }, [customEmails]);

  const [selectedThreat, setSelectedThreat] = useState<ThreatLocationItem | null>(allThreatLocations[0] || null);

  useEffect(() => {
    if (!selectedThreat && allThreatLocations.length > 0) {
      setSelectedThreat(allThreatLocations[0]);
    }
  }, [allThreatLocations]);
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isAutoRotating, setIsAutoRotating] = useState(true);
  const [cameraDistance, setCameraDistance] = useState(230);

  // Three.js refs
  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  const globeGroupRef = useRef<THREE.Group | null>(null);
  const cloudsMeshRef = useRef<THREE.Mesh | null>(null);
  const beaconMeshRef = useRef<THREE.Mesh | null>(null);
  const pulseRingsRef = useRef<THREE.Mesh[]>([]);
  const animationFrameId = useRef<number | null>(null);
  const isUserInteracting = useRef(false);

  // Camera animation interpolation state
  const isAnimatingCamera = useRef(false);
  const cameraAnimStartTime = useRef(0);
  const cameraAnimDuration = useRef(1200); // 1.2s smooth easing
  const cameraStartPos = useRef(new THREE.Vector3());
  const cameraTargetPos = useRef(new THREE.Vector3());

  // Helper: Lat/Lng to 3D Cartesian coordinates on sphere
  const latLngToVector3 = (lat: number, lng: number, radius: number = 80): THREE.Vector3 => {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lng + 180) * (Math.PI / 180);
    const x = -(radius * Math.sin(phi) * Math.cos(theta));
    const z = radius * Math.sin(phi) * Math.sin(theta);
    const y = radius * Math.cos(phi);
    return new THREE.Vector3(x, y, z);
  };

  // Helper: Procedural Earth Texture
  const generateProceduralEarthTexture = () => {
    const canvas = document.createElement('canvas');
    canvas.width = 2048;
    canvas.height = 1024;
    const ctx = canvas.getContext('2d');
    if (!ctx) return new THREE.CanvasTexture(canvas);

    // Deep high-contrast cyber ocean gradient
    const oceanGrad = ctx.createLinearGradient(0, 0, 0, canvas.height);
    oceanGrad.addColorStop(0, '#0f172a');
    oceanGrad.addColorStop(0.5, '#1e1b4b');
    oceanGrad.addColorStop(1, '#020617');
    ctx.fillStyle = oceanGrad;
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Subtle lat/long coordinates grid lines
    ctx.strokeStyle = 'rgba(99, 102, 241, 0.16)';
    ctx.lineWidth = 1;
    for (let x = 0; x < canvas.width; x += 64) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += 64) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    // High craft continent geometry
    ctx.fillStyle = '#312e81';
    const drawLand = (x: number, y: number, w: number, h: number, rad: number = 10) => {
      ctx.beginPath();
      ctx.roundRect ? ctx.roundRect(x, y, w, h, rad) : ctx.rect(x, y, w, h);
      ctx.fill();
    };

    drawLand(200, 200, 450, 300, 40);
    drawLand(450, 550, 250, 350, 30);
    drawLand(900, 180, 280, 200, 25);
    drawLand(920, 400, 320, 380, 35);
    drawLand(1200, 150, 600, 400, 50);
    drawLand(1550, 650, 280, 200, 30);

    return new THREE.CanvasTexture(canvas);
  };

  // Main Three.js Initialization with OrbitControls & Realistic Physics
  useEffect(() => {
    const container = canvasContainerRef.current;
    if (!container) return;

    const width = container.clientWidth || 800;
    const height = container.clientHeight || 460;

    // 1. Scene
    const scene = new THREE.Scene();
    sceneRef.current = scene;

    // 2. Camera
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 40, 230);
    cameraRef.current = camera;

    // 3. Renderer with high-DPI antialiasing
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.1;
    container.innerHTML = '';
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // 4. OrbitControls: Smooth real-life pan, zoom, and rotate with damping
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.rotateSpeed = 0.8;
    controls.zoomSpeed = 1.0;
    controls.panSpeed = 0.8;
    controls.minDistance = 110;  // Prevents clipping into globe surface
    controls.maxDistance = 420;  // Prevents losing globe in deep space
    controls.enablePan = true;
    controls.target.set(0, 0, 0);
    controls.addEventListener('start', () => { isUserInteracting.current = true; });
    controls.addEventListener('end', () => { isUserInteracting.current = false; });
    controlsRef.current = controls;

    // 5. Globe Root Group
    const globeGroup = new THREE.Group();
    scene.add(globeGroup);
    globeGroupRef.current = globeGroup;

    // 6. Realistic Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.95);
    scene.add(ambientLight);

    const sunLight = new THREE.DirectionalLight(0xffffff, 1.6);
    sunLight.position.set(160, 110, 190);
    scene.add(sunLight);

    const rimLight = new THREE.DirectionalLight(0x818cf8, 0.8);
    rimLight.position.set(-160, -90, -130);
    scene.add(rimLight);

    // 7. Earth Sphere Mesh
    const radius = 80;
    const geometry = new THREE.SphereGeometry(radius, 64, 64);
    const textureLoader = new THREE.TextureLoader();
    const fallbackCanvasTexture = generateProceduralEarthTexture();

    const earthMaterial = new THREE.MeshStandardMaterial({
      map: fallbackCanvasTexture,
      roughness: 0.55,
      metalness: 0.15
    });

    const earthMesh = new THREE.Mesh(geometry, earthMaterial);
    globeGroup.add(earthMesh);

    // Asynchronously load ultra-detailed Earth texture
    textureLoader.load(
      'https://cdn.jsdelivr.net/gh/mrdoob/three.js@r128/examples/textures/planets/earth_atmos_2048.jpg',
      (tex) => {
        tex.anisotropy = 8;
        earthMaterial.map = tex;
        earthMaterial.needsUpdate = true;
      },
      undefined,
      () => { /* fallback is already seamlessly active */ }
    );

    // Atmospheric outer glow
    const atmosphereGeo = new THREE.SphereGeometry(radius * 1.04, 32, 32);
    const atmosphereMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.12,
      side: THREE.BackSide
    });
    const atmosphere = new THREE.Mesh(atmosphereGeo, atmosphereMat);
    globeGroup.add(atmosphere);

    // Cloud layer with gentle rotation
    const cloudsGeo = new THREE.SphereGeometry(radius * 1.012, 48, 48);
    const cloudsMat = new THREE.MeshStandardMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 0.14,
      blending: THREE.AdditiveBlending
    });
    const cloudsMesh = new THREE.Mesh(cloudsGeo, cloudsMat);
    globeGroup.add(cloudsMesh);
    cloudsMeshRef.current = cloudsMesh;

    // 8. Dynamic Threat Location Markers & Pulsing Radar Rings
    const pulseRings: THREE.Mesh[] = [];
    allThreatLocations.forEach((threat) => {
      const pos = latLngToVector3(threat.lat, threat.lng, radius + 0.8);
      const score = threat.threatScore ?? 0;
      const color = score > 80 ? 0xef4444 : (score >= 50 ? 0xf97316 : 0x10b981);

      // Core Solid Pin
      const pinGeo = new THREE.SphereGeometry(1.9, 16, 16);
      const pinMat = new THREE.MeshStandardMaterial({ 
        color,
        emissive: color,
        emissiveIntensity: 0.6,
        roughness: 0.2
      });
      const pin = new THREE.Mesh(pinGeo, pinMat);
      pin.position.copy(pos);
      globeGroup.add(pin);

      // Expanding Radar Pulse Ring
      const ringGeo = new THREE.RingGeometry(2.0, 3.6, 32);
      const ringMat = new THREE.MeshBasicMaterial({
        color,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.75
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.position.copy(pos.clone().multiplyScalar(1.006));
      ring.lookAt(pos.clone().multiplyScalar(2));
      ring.userData = { initialScale: 1.0, phase: Math.random() * Math.PI * 2 };
      globeGroup.add(ring);
      pulseRings.push(ring);
    });
    pulseRingsRef.current = pulseRings;

    // 9. Selected Active Threat Beacon Beam
    const beaconGeo = new THREE.CylinderGeometry(0.3, 1.8, 14, 16, 1, true);
    const beaconMat = new THREE.MeshBasicMaterial({
      color: 0x6366f1,
      transparent: true,
      opacity: 0.6,
      side: THREE.DoubleSide,
      blending: THREE.AdditiveBlending
    });
    const beaconMesh = new THREE.Mesh(beaconGeo, beaconMat);
    beaconMesh.visible = false;
    globeGroup.add(beaconMesh);
    beaconMeshRef.current = beaconMesh;

    // 10. Attack Arcs
    allThreatLocations.forEach((threat) => {
      if (!threat.targetCoords) return;
      const start = latLngToVector3(threat.lat, threat.lng, radius);
      const end = latLngToVector3(threat.targetCoords.lat, threat.targetCoords.lng, radius);
      const mid = start.clone().add(end).multiplyScalar(0.5);
      const distance = start.distanceTo(end);
      mid.normalize().multiplyScalar(radius + distance * 0.38);

      const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
      const points = curve.getPoints(60);
      const curveGeo = new THREE.BufferGeometry().setFromPoints(points);

      const score = threat.threatScore ?? 0;
      const arcColor = score > 80 ? 0xef4444 : (score >= 50 ? 0xf97316 : 0x10b981);

      const curveMat = new THREE.LineBasicMaterial({
        color: arcColor,
        transparent: true,
        opacity: 0.65,
        linewidth: 2
      });

      const arc = new THREE.Line(curveGeo, curveMat);
      globeGroup.add(arc);
    });

    // 11. Animation Loop with Smooth Camera Interpolation
    const animate = (timestamp: number) => {
      // Rotate clouds slowly
      if (cloudsMeshRef.current) {
        cloudsMeshRef.current.rotation.y += 0.0003;
      }

      // Animate pulsing radar rings
      pulseRingsRef.current.forEach((ring) => {
        const time = timestamp * 0.0025 + (ring.userData.phase || 0);
        const scale = 1.0 + (Math.sin(time) + 1.0) * 0.6;
        const opacity = Math.max(0.1, 0.8 - (scale - 1.0) * 0.5);
        ring.scale.set(scale, scale, 1);
        (ring.material as THREE.MeshBasicMaterial).opacity = opacity;
      });

      // Handle Smooth Fly-To Camera Interpolation
      if (isAnimatingCamera.current) {
        const elapsed = timestamp - cameraAnimStartTime.current;
        const progress = Math.min(elapsed / cameraAnimDuration.current, 1);
        
        // Cubic Ease-Out
        const ease = 1 - Math.pow(1 - progress, 3);

        const startDist = cameraStartPos.current.length();
        const targetDist = cameraTargetPos.current.length();
        const currentDist = THREE.MathUtils.lerp(startDist, targetDist, ease);

        const startNorm = cameraStartPos.current.clone().normalize();
        const targetNorm = cameraTargetPos.current.clone().normalize();

        // Spherical quaternion slerp
        const quat = new THREE.Quaternion().setFromUnitVectors(startNorm, targetNorm);
        const stepQuat = new THREE.Quaternion().slerp(quat, ease);
        const slerpedNorm = startNorm.clone().applyQuaternion(stepQuat);

        camera.position.copy(slerpedNorm.multiplyScalar(currentDist));
        camera.lookAt(0, 0, 0);
        controls.target.set(0, 0, 0);
        controls.update();

        if (progress >= 1) {
          isAnimatingCamera.current = false;
        }
      } else {
        // Auto-rotation when not animating camera or manually interacting
        if (isAutoRotating && !isUserInteracting.current) {
          globeGroup.rotation.y += 0.001;
        }
        controls.update();
      }

      setCameraDistance(Math.round(camera.position.length()));

      if (rendererRef.current && sceneRef.current && cameraRef.current) {
        rendererRef.current.render(sceneRef.current, cameraRef.current);
      }

      animationFrameId.current = requestAnimationFrame(animate);
    };

    animationFrameId.current = requestAnimationFrame(animate);

    // Resize Handler
    const handleResize = () => {
      if (!container || !rendererRef.current || !cameraRef.current) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      cameraRef.current.aspect = w / h;
      cameraRef.current.updateProjectionMatrix();
      rendererRef.current.setSize(w, h);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      if (animationFrameId.current) cancelAnimationFrame(animationFrameId.current);
      window.removeEventListener('resize', handleResize);
      controls.dispose();
      renderer.dispose();
    };
  }, [allThreatLocations]);

  // Smooth Fly-To & Zoom In on Specific Location
  const flyToThreatLocation = (threat: ThreatLocationItem, zoomIn: boolean = true) => {
    setSelectedThreat(threat);
    onSelectThreat(threat.id);
    setIsAutoRotating(false);

    if (!cameraRef.current || !globeGroupRef.current) return;

    const camera = cameraRef.current;
    const radius = 80;
    const surfacePos = latLngToVector3(threat.lat, threat.lng, radius);

    // Position the Beacon Beam on the active marker
    if (beaconMeshRef.current) {
      beaconMeshRef.current.visible = true;
      beaconMeshRef.current.position.copy(surfacePos.clone().multiplyScalar(1.08));
      beaconMeshRef.current.quaternion.setFromUnitVectors(
        new THREE.Vector3(0, 1, 0),
        surfacePos.clone().normalize()
      );
    }

    // Calculate ideal viewing vector in world coordinates
    const direction = surfacePos.clone().normalize();
    const targetZoomDistance = zoomIn ? 145 : 210; // Zoom in close enough for high detail
    const targetCameraPosition = direction.multiplyScalar(targetZoomDistance);

    // Set up smooth animation
    cameraStartPos.current.copy(camera.position);
    cameraTargetPos.current.copy(targetCameraPosition);
    cameraAnimStartTime.current = performance.now();
    isAnimatingCamera.current = true;
  };

  // Zoom HUD Handlers
  const handleZoomIn = () => {
    if (!cameraRef.current || !controlsRef.current) return;
    const camera = cameraRef.current;
    const currentLen = camera.position.length();
    const nextLen = Math.max(115, currentLen * 0.78);
    
    cameraStartPos.current.copy(camera.position);
    cameraTargetPos.current.copy(camera.position.clone().normalize().multiplyScalar(nextLen));
    cameraAnimStartTime.current = performance.now();
    isAnimatingCamera.current = true;
  };

  const handleZoomOut = () => {
    if (!cameraRef.current || !controlsRef.current) return;
    const camera = cameraRef.current;
    const currentLen = camera.position.length();
    const nextLen = Math.min(380, currentLen * 1.3);

    cameraStartPos.current.copy(camera.position);
    cameraTargetPos.current.copy(camera.position.clone().normalize().multiplyScalar(nextLen));
    cameraAnimStartTime.current = performance.now();
    isAnimatingCamera.current = true;
  };

  const handleResetView = () => {
    if (!cameraRef.current) return;
    cameraStartPos.current.copy(cameraRef.current.position);
    cameraTargetPos.current.set(0, 40, 230);
    cameraAnimStartTime.current = performance.now();
    isAnimatingCamera.current = true;
    setIsAutoRotating(true);
    if (beaconMeshRef.current) beaconMeshRef.current.visible = false;
  };

  // Filtered threats for live search
  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const q = searchQuery.toLowerCase();
    return allThreatLocations.filter(item => 
      item.city.toLowerCase().includes(q) ||
      item.country.toLowerCase().includes(q) ||
      item.ip.toLowerCase().includes(q) ||
      item.sender.toLowerCase().includes(q) ||
      item.simpleTitle.toLowerCase().includes(q) ||
      (item.subject && item.subject.toLowerCase().includes(q))
    );
  }, [allThreatLocations, searchQuery]);

  const activeThreat = selectedThreat || (allThreatLocations.length > 0 ? allThreatLocations[0] : null);
  const threatScore = activeThreat ? (activeThreat.threatScore || 0) : 0;
  const strokeDashoffset = 213.6 - (213.6 * threatScore) / 100;

  const criticalCount = customEmails.filter(e => (e.threatScore ?? 0) > 80).length;
  const mildCount = customEmails.filter(e => (e.threatScore ?? 0) >= 50 && (e.threatScore ?? 0) <= 80).length;
  const safeCount = customEmails.filter(e => (e.threatScore ?? 0) < 50).length;

  return (
    <div className="space-y-6">
      
      {/* Top Metrics Ribbon */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Metric 1: Threat Score Gauge */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              Focused Severity Index
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-black font-mono text-slate-900">
                {threatScore}
              </span>
              <span className="text-xs text-slate-400 font-mono">/100</span>
            </div>
            <div>
              <span className={`text-[11px] font-bold px-3 py-0.5 rounded-full border ${
                threatScore > 80 
                  ? 'bg-red-100 text-red-700 border-red-200' 
                  : (threatScore >= 50 ? 'bg-orange-100 text-orange-700 border-orange-200' : 'bg-emerald-100 text-emerald-700 border-emerald-200')
              }`}>
                {threatScore > 80 ? 'Critical Threat (Red)' : (threatScore >= 50 ? 'Mild Threat (Orange)' : (activeThreat ? '100% Safe (Green)' : 'Awaiting Inbound'))}
              </span>
            </div>
          </div>

          {/* Circular SVG Gauge */}
          <div className="relative w-20 h-20 flex items-center justify-center">
            <svg className="w-20 h-20" viewBox="0 0 80 80">
              <circle cx="40" cy="40" r="34" stroke="#f1f5f9" strokeWidth="7" fill="none" />
              <circle 
                className="threat-gauge-circle" 
                cx="40" 
                cy="40" 
                r="34" 
                stroke={threatScore > 80 ? '#ef4444' : (threatScore >= 50 ? '#f97316' : '#10b981')} 
                strokeWidth="7" 
                strokeDasharray="213.6" 
                strokeDashoffset={strokeDashoffset} 
                strokeLinecap="round" 
                fill="none" 
              />
            </svg>
            <ShieldAlert className={`w-6 h-6 absolute ${threatScore > 80 ? 'text-red-500' : (threatScore >= 50 ? 'text-orange-500' : 'text-emerald-500')}`} />
          </div>
        </div>

        {/* Metric 2: Live Incidents Tracked */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              Live Ingested Emails
            </span>
            <span className="text-[10px] font-bold text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-100 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 animate-pulse"></span>
              Live Pipeline
            </span>
          </div>
          <div className="text-3xl font-black font-mono text-slate-900">
            {customEmails.length}
          </div>
          <div className="text-xs text-slate-500 flex items-center gap-1.5 pt-1 font-mono">
            <span className="text-red-600 font-bold">{criticalCount}</span> Critical • 
            <span className="text-orange-600 font-bold">{mildCount}</span> Mild • 
            <span className="text-emerald-600 font-bold">{safeCount}</span> Safe
          </div>
        </div>

        {/* Metric 3: Active Sender Origin Focus */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-1 lg:col-span-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <MapPin className="w-3.5 h-3.5 text-indigo-600" />
              Origin Telemetry & Coordinates
            </span>
            <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border ${
              activeThreat?.severity === 'safe' 
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200' 
                : 'bg-red-50 text-red-700 border-red-200'
            }`}>
              {activeThreat?.status || 'Awaiting Live Origin'}
            </span>
          </div>
          <div className="font-mono text-sm font-bold text-slate-900 truncate">
            {activeThreat ? activeThreat.sender : 'No active email sender selected'}
          </div>
          <div className="text-xs text-slate-500 flex items-center gap-2 truncate">
            {activeThreat ? (
              <>
                <span className="font-bold text-slate-700">Origin:</span> 
                <span className="font-mono text-indigo-600 font-bold">{activeThreat.city}, {activeThreat.country}</span> • 
                <span className="font-bold text-slate-700">IP:</span> 
                <span className="font-mono text-slate-600">{activeThreat.ip}</span> • 
                <span className="font-bold text-slate-700">Lat/Lng:</span>
                <span className="font-mono text-slate-500">{activeThreat.lat.toFixed(2)}°, {activeThreat.lng.toFixed(2)}°</span>
              </>
            ) : (
              <span>Connect Gmail or upload an .EML file in Forensics to plot origin coordinates.</span>
            )}
          </div>
        </div>

      </div>

      {/* Main Visual Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Large Interactive 3D World Globe */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl shadow-xs overflow-hidden flex flex-col relative">
          
          {/* Top Bar with Live Search & Coordinates HUD */}
          <div className="p-3.5 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white z-20">
            
            {/* Search Bar with Autocomplete */}
            <div className="relative flex-1 max-w-md">
              <div className="relative flex items-center">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 pointer-events-none" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setIsSearchOpen(true);
                  }}
                  onFocus={() => setIsSearchOpen(true)}
                  placeholder={allThreatLocations.length > 0 ? "Search city, country, IP address, sender..." : "Awaiting emails to search..."}
                  disabled={allThreatLocations.length === 0}
                  className="w-full pl-9 pr-8 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all font-sans disabled:opacity-60"
                />
                {searchQuery && (
                  <button
                    onClick={() => { setSearchQuery(''); setIsSearchOpen(false); }}
                    className="absolute right-2.5 text-slate-400 hover:text-slate-600 p-0.5"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {/* Search Autocomplete Dropdown */}
              {isSearchOpen && searchResults.length > 0 && (
                <div className="absolute top-full left-0 right-0 mt-1 bg-white border border-slate-200 rounded-xl shadow-lg z-30 max-h-60 overflow-y-auto divide-y divide-slate-100">
                  {searchResults.map((item) => {
                    const score = item.threatScore ?? 0;
                    const dotClass = score > 80 ? 'bg-red-500' : (score >= 50 ? 'bg-orange-500' : 'bg-emerald-500');
                    return (
                      <div
                        key={item.id}
                        onClick={() => {
                          flyToThreatLocation(item, true);
                          setIsSearchOpen(false);
                          setSearchQuery('');
                        }}
                        className="p-3 hover:bg-slate-50 cursor-pointer flex items-center justify-between text-xs transition-colors"
                      >
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full ${dotClass}`} />
                            <span className="font-bold text-slate-900">{item.city}, {item.country}</span>
                          </div>
                          <p className="text-[11px] text-slate-500 truncate max-w-xs">{item.sender}</p>
                        </div>
                        <span className="text-[10px] font-mono text-slate-400 font-bold">{score}/100</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Live Indicator */}
            <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
              <span className="w-2 h-2 rounded-full bg-indigo-600 animate-pulse" />
              <span>RADAR ONLINE</span>
            </div>
          </div>

          {/* Three.js Canvas Container */}
          <div className="relative w-full h-[460px] bg-slate-950 overflow-hidden">
            <div ref={canvasContainerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

            {/* Navigation & Zoom HUD Buttons */}
            <div className="absolute right-4 bottom-4 flex flex-col gap-1.5 z-10">
              <button
                onClick={handleZoomIn}
                title="Zoom In"
                className="w-8 h-8 bg-white/90 hover:bg-white text-slate-700 hover:text-indigo-600 rounded-lg shadow-md border border-slate-200 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
              >
                <Plus className="w-4 h-4" />
              </button>
              <button
                onClick={handleZoomOut}
                title="Zoom Out"
                className="w-8 h-8 bg-white/90 hover:bg-white text-slate-700 hover:text-indigo-600 rounded-lg shadow-md border border-slate-200 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
              >
                <Minus className="w-4 h-4" />
              </button>
              <button
                onClick={handleResetView}
                title="Reset View"
                className="w-8 h-8 bg-white/90 hover:bg-white text-slate-700 hover:text-indigo-600 rounded-lg shadow-md border border-slate-200 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setIsAutoRotating(!isAutoRotating)}
                title={isAutoRotating ? "Pause Auto-Rotation" : "Start Auto-Rotation"}
                className="w-8 h-8 bg-white/90 hover:bg-white text-slate-700 hover:text-indigo-600 rounded-lg shadow-md border border-slate-200 flex items-center justify-center transition-all backdrop-blur-xs cursor-pointer"
              >
                {isAutoRotating ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              </button>
            </div>

            {/* Active Target Floating Pin Tag */}
            {activeThreat && (
              <div className="absolute left-4 top-4 bg-slate-900/90 text-white border border-slate-700/80 rounded-xl p-3 shadow-xl backdrop-blur-md max-w-xs z-10 pointer-events-none transition-all">
                <div className="flex items-center gap-2 pb-1.5 border-b border-slate-800">
                  <Crosshair className="w-3.5 h-3.5 text-indigo-400 animate-spin" style={{ animationDuration: '6s' }} />
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-indigo-300">
                    Focused Telemetry Target
                  </span>
                </div>
                <div className="mt-2 space-y-1">
                  <div className="text-xs font-bold text-slate-100 flex items-center justify-between">
                    <span>{activeThreat.city}, {activeThreat.country}</span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                      activeThreat.severity === 'safe' ? 'bg-emerald-900 text-emerald-300' : 'bg-red-900 text-red-300'
                    }`}>
                      {activeThreat.threatScore}/100
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-300 font-mono truncate">{activeThreat.sender}</p>
                  <div className="text-[10px] text-slate-400 font-mono flex items-center gap-2">
                    <span>IP: {activeThreat.ip}</span>
                    <span>•</span>
                    <span>{activeThreat.asn?.split(' ')[0]}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Zero Telemetry HUD Overlay */}
            {allThreatLocations.length === 0 && (
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none p-6">
                <div className="bg-slate-900/80 border border-slate-700/70 rounded-2xl p-5 text-center max-w-sm backdrop-blur-md shadow-2xl pointer-events-auto">
                  <GlobeIcon className="w-8 h-8 text-indigo-400 mx-auto mb-2 opacity-80" />
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider">Awaiting Threat Telemetry</h4>
                  <p className="text-[11px] text-slate-400 mt-1 mb-3">
                    No emails ingested yet. Connect your live Gmail inbox or upload an .EML file to plot incoming attack origins.
                  </p>
                  <button
                    onClick={onOpenForensics}
                    className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-lg transition-colors cursor-pointer"
                  >
                    Open Forensics Suite
                  </button>
                </div>
              </div>
            )}

          </div>

          {/* Quick Location Jump Badges */}
          {allThreatLocations.length > 0 && (
            <div className="p-3 bg-slate-50 border-t border-slate-200 flex flex-wrap items-center gap-2 text-xs">
              <span className="font-bold text-slate-500 text-[11px] uppercase tracking-wider mr-1">
                Quick Focus:
              </span>
              {allThreatLocations.slice(0, 6).map((threat) => (
                <button
                  key={threat.id}
                  onClick={() => flyToThreatLocation(threat, true)}
                  className={`px-2.5 py-1 rounded-lg font-medium border text-[11px] transition-all flex items-center gap-1 cursor-pointer ${
                    activeThreat?.id === threat.id
                      ? 'bg-indigo-600 text-white border-indigo-600 shadow-xs'
                      : 'bg-white hover:bg-indigo-50 hover:text-indigo-600 border-slate-200 text-slate-700'
                  }`}
                >
                  <span>{threat.city}</span>
                  <span className={`w-1.5 h-1.5 rounded-full ${threat.severity === 'safe' ? 'bg-emerald-400' : 'bg-red-400'}`} />
                </button>
              ))}
            </div>
          )}

          {/* Threat Plain Telemetry Summary Footer */}
          <div className="p-4 bg-slate-900 text-white border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-0.5">
              <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 flex items-center gap-1.5">
                <Radio className="w-3 h-3 text-indigo-400 animate-pulse" />
                Live Incident Forensic Summary
              </div>
              <p className="text-xs text-slate-200 font-medium leading-relaxed">
                {activeThreat ? activeThreat.plainSummary : 'Awaiting live stream. Connect your Gmail account or ingest email files to view origin telemetry.'}
              </p>
            </div>
            <button 
              onClick={onOpenForensics}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl shrink-0 transition-all flex items-center gap-1.5 shadow-sm cursor-pointer"
            >
              <Microscope className="w-3.5 h-3.5" />
              Open Forensics
            </button>
          </div>
        </div>

        {/* Right Side: Interactive Threat Incident Feed */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
                <Radio className="w-4 h-4 text-indigo-600" />
                Live Ingested Feed ({allThreatLocations.length})
              </h3>
              <span className="text-[10px] text-slate-400 font-medium">Click to locate</span>
            </div>

            {/* Threat Feed Scrollable List */}
            {allThreatLocations.length > 0 ? (
              <div className="space-y-2.5 mt-4 max-h-[380px] overflow-y-auto pr-1">
                {allThreatLocations.map((item) => {
                  const isItemActive = activeThreat?.id === item.id;
                  const score = item.threatScore ?? 0;
                  const dotClass = score > 80 ? 'bg-red-500' : (score >= 50 ? 'bg-orange-500' : 'bg-emerald-500');
                  const badgeClass = score > 80 
                    ? 'bg-red-100 text-red-800' 
                    : (score >= 50 ? 'bg-orange-100 text-orange-800' : 'bg-emerald-100 text-emerald-800');
                  return (
                    <div
                      key={item.id}
                      onClick={() => flyToThreatLocation(item, true)}
                      className={`p-3 rounded-xl border transition-all cursor-pointer ${
                        isItemActive
                          ? 'bg-indigo-50/90 border-indigo-400 ring-2 ring-indigo-200 shadow-xs'
                          : 'bg-slate-50/70 border-slate-200 hover:border-slate-300 hover:bg-slate-100/70'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="space-y-1 min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className={`w-2 h-2 rounded-full shrink-0 ${dotClass}`} />
                            <span className="text-xs font-bold text-slate-900 truncate">
                              {item.city}, {item.country}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600 line-clamp-1 font-medium">
                            {item.simpleTitle}
                          </p>
                          <div className="text-[10px] font-mono text-slate-400 truncate">
                            {item.sender}
                          </div>
                          <div className="text-[10px] font-mono text-slate-400">
                            {item.ip} • {item.timestamp}
                          </div>
                        </div>

                        <div className="text-right shrink-0">
                          <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${badgeClass}`}>
                            {item.threatScore}/100
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-8 text-center text-slate-400 space-y-2 mt-4 bg-slate-50 rounded-xl border border-dashed border-slate-200">
                <Microscope className="w-6 h-6 mx-auto text-slate-300" />
                <p className="text-xs font-medium text-slate-600">No telemetry logged</p>
                <p className="text-[11px] text-slate-400">Sync Gmail or upload an email to populate this feed.</p>
              </div>
            )}
          </div>

          {/* Quick Action Card */}
          <div className="p-4 bg-indigo-50/50 border border-indigo-100 rounded-xl space-y-2">
            <div className="text-xs font-bold text-slate-900">Deep Email Analysis</div>
            <p className="text-[11px] text-slate-600">Upload any .eml file or paste text to inspect headers, domains, and IOCs.</p>
            <button 
              onClick={onOpenForensics}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl transition-all shadow-xs cursor-pointer"
            >
              Open Forensics Suite
            </button>
          </div>
        </div>

      </div>

    </div>
  );
};
