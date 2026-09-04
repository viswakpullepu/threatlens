import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Globe as GlobeIcon, 
  Radio, 
  Microscope, 
  ShieldCheck, 
  ExternalLink,
  ChevronRight,
  Send
} from 'lucide-react';
import { THREAT_LOCATIONS } from '../data/threatData';

interface GlobeViewProps {
  onSelectThreat: (threatId: string) => void;
  onOpenForensics: () => void;
}

export const GlobeView: React.FC<GlobeViewProps> = ({
  onSelectThreat,
  onOpenForensics
}) => {
  const canvasContainerRef = useRef<HTMLDivElement>(null);
  const [selectedThreat, setSelectedThreat] = useState(THREAT_LOCATIONS[0]);

  // Three.js refs
  const sceneRef = useRef<THREE.Scene | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const globeGroupRef = useRef<THREE.Group | null>(null);
  const earthMeshRef = useRef<THREE.Mesh | null>(null);
  const cloudsMeshRef = useRef<THREE.Mesh | null>(null);
  const targetRotation = useRef({ x: 0.25, y: 0.8 });
  const currentRotation = useRef({ x: 0.25, y: 0.8 });
  const isDragging = useRef(false);
  const previousMousePosition = useRef({ x: 0, y: 0 });
  const animationFrameId = useRef<number | null>(null);

  // Helper: Lat/Lng to Vector3
  const latLngToVector3 = (lat: number, lng: number, radius: number = 80): THREE.Vector3 => {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lng + 180) * (Math.PI / 180);
    const x = -(radius * Math.sin(phi) * Math.cos(theta));
    const z = radius * Math.sin(phi) * Math.sin(theta);
    const y = radius * Math.cos(phi);
    return new THREE.Vector3(x, y, z);
  };

  // Helper: Create Procedural Earth Canvas
  const generateProceduralEarthTexture = () => {
    const canvas = document.createElement('canvas');
    canvas.width = 2048;
    canvas.height = 1024;
    const ctx = canvas.getContext('2d');
    if (!ctx) return new THREE.CanvasTexture(canvas);

    // Ocean gradient
    const oceanGrad = ctx.createLinearGradient(0, 0, 0, canvas.height);
    oceanGrad.addColorStop(0, '#0f172a');
    oceanGrad.addColorStop(0.5, '#1e1b4b');
    oceanGrad.addColorStop(1, '#020617');
    ctx.fillStyle = oceanGrad;
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Grid lines
    ctx.strokeStyle = 'rgba(99, 102, 241, 0.15)';
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

    // Procedural continents drawing
    ctx.fillStyle = '#312e81';
    const drawLand = (x: number, y: number, w: number, h: number, rad: number = 10) => {
      ctx.beginPath();
      ctx.roundRect ? ctx.roundRect(x, y, w, h, rad) : ctx.rect(x, y, w, h);
      ctx.fill();
    };

    // North America
    drawLand(200, 200, 450, 300, 40);
    // South America
    drawLand(450, 550, 250, 350, 30);
    // Europe
    drawLand(900, 180, 280, 200, 25);
    // Africa
    drawLand(920, 400, 320, 380, 35);
    // Asia
    drawLand(1200, 150, 600, 400, 50);
    // Australia
    drawLand(1550, 650, 280, 200, 30);

    const texture = new THREE.CanvasTexture(canvas);
    return texture;
  };

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
    camera.position.z = 230;
    cameraRef.current = camera;

    // 3. Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.innerHTML = '';
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // 4. Globe Root Group
    const globeGroup = new THREE.Group();
    scene.add(globeGroup);
    globeGroupRef.current = globeGroup;

    // 5. Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.9);
    scene.add(ambientLight);

    const sunLight = new THREE.DirectionalLight(0xffffff, 1.4);
    sunLight.position.set(150, 100, 180);
    scene.add(sunLight);

    const blueBackLight = new THREE.DirectionalLight(0x818cf8, 0.6);
    blueBackLight.position.set(-150, -80, -120);
    scene.add(blueBackLight);

    // 6. Earth Mesh
    const radius = 80;
    const geometry = new THREE.SphereGeometry(radius, 64, 64);
    const textureLoader = new THREE.TextureLoader();
    const fallbackCanvasTexture = generateProceduralEarthTexture();

    const earthMaterial = new THREE.MeshStandardMaterial({
      map: fallbackCanvasTexture,
      roughness: 0.6,
      metalness: 0.1
    });

    const earthMesh = new THREE.Mesh(geometry, earthMaterial);
    globeGroup.add(earthMesh);
    earthMeshRef.current = earthMesh;

    // Load actual Earth texture asynchronously
    textureLoader.load(
      'https://cdn.jsdelivr.net/gh/mrdoob/three.js@r128/examples/textures/planets/earth_atmos_2048.jpg',
      (tex) => {
        tex.anisotropy = 8;
        earthMaterial.map = tex;
        earthMaterial.needsUpdate = true;
      },
      undefined,
      () => { /* procedural fallback is already active */ }
    );

    // Atmosphere Glow
    const atmosphereGeo = new THREE.SphereGeometry(radius * 1.04, 32, 32);
    const atmosphereMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.12,
      side: THREE.BackSide
    });
    const atmosphere = new THREE.Mesh(atmosphereGeo, atmosphereMat);
    globeGroup.add(atmosphere);

    // Cloud Layer
    const cloudsGeo = new THREE.SphereGeometry(radius * 1.01, 48, 48);
    const cloudsMat = new THREE.MeshStandardMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 0.15,
      blending: THREE.AdditiveBlending
    });
    const cloudsMesh = new THREE.Mesh(cloudsGeo, cloudsMat);
    globeGroup.add(cloudsMesh);
    cloudsMeshRef.current = cloudsMesh;

    // 7. Threat Markers
    THREAT_LOCATIONS.forEach((threat) => {
      const pos = latLngToVector3(threat.lat, threat.lng, radius + 1);
      const isCritical = threat.severity === 'critical';
      const isSafe = threat.severity === 'safe';
      const color = isSafe ? 0x10b981 : (isCritical ? 0xef4444 : 0xf97316);

      // Dot Pin
      const pinGeo = new THREE.SphereGeometry(1.8, 16, 16);
      const pinMat = new THREE.MeshBasicMaterial({ color });
      const pin = new THREE.Mesh(pinGeo, pinMat);
      pin.position.copy(pos);
      globeGroup.add(pin);

      // Radar Pulse Ring
      const ringGeo = new THREE.RingGeometry(2.2, 3.4, 24);
      const ringMat = new THREE.MeshBasicMaterial({
        color,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.7
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.position.copy(pos.clone().multiplyScalar(1.005));
      ring.lookAt(pos.clone().multiplyScalar(2));
      globeGroup.add(ring);
    });

    // 8. Attack Arcs
    THREAT_LOCATIONS.forEach((threat) => {
      if (!threat.targetCoords) return;
      const start = latLngToVector3(threat.lat, threat.lng, radius);
      const end = latLngToVector3(threat.targetCoords.lat, threat.targetCoords.lng, radius);
      const mid = start.clone().add(end).multiplyScalar(0.5);
      const distance = start.distanceTo(end);
      mid.normalize().multiplyScalar(radius + distance * 0.35);

      const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
      const points = curve.getPoints(50);
      const curveGeo = new THREE.BufferGeometry().setFromPoints(points);

      const isSafe = threat.severity === 'safe';
      const isCritical = threat.severity === 'critical';
      const arcColor = isSafe ? 0x10b981 : (isCritical ? 0xef4444 : 0xf97316);

      const curveMat = new THREE.LineBasicMaterial({
        color: arcColor,
        transparent: true,
        opacity: 0.65,
        linewidth: 2
      });

      const arc = new THREE.Line(curveGeo, curveMat);
      globeGroup.add(arc);
    });

    // 9. Interaction listeners
    const onMouseDown = (e: MouseEvent) => {
      isDragging.current = true;
      previousMousePosition.current = { x: e.clientX, y: e.clientY };
    };

    const onMouseMove = (e: MouseEvent) => {
      if (!isDragging.current) return;
      const deltaX = e.clientX - previousMousePosition.current.x;
      const deltaY = e.clientY - previousMousePosition.current.y;
      targetRotation.current.y += deltaX * 0.005;
      targetRotation.current.x += deltaY * 0.005;
      targetRotation.current.x = Math.max(-Math.PI / 2.2, Math.min(Math.PI / 2.2, targetRotation.current.x));
      previousMousePosition.current = { x: e.clientX, y: e.clientY };
    };

    const onMouseUp = () => {
      isDragging.current = false;
    };

    container.addEventListener('mousedown', onMouseDown);
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);

    // Animation Loop
    const animate = () => {
      if (!isDragging.current) {
        targetRotation.current.y += 0.0012;
      }
      currentRotation.current.x += (targetRotation.current.x - currentRotation.current.x) * 0.08;
      currentRotation.current.y += (targetRotation.current.y - currentRotation.current.y) * 0.08;

      if (globeGroupRef.current) {
        globeGroupRef.current.rotation.x = currentRotation.current.x;
        globeGroupRef.current.rotation.y = currentRotation.current.y;
      }

      if (cloudsMeshRef.current) {
        cloudsMeshRef.current.rotation.y += 0.0004;
      }

      if (rendererRef.current && sceneRef.current && cameraRef.current) {
        rendererRef.current.render(sceneRef.current, cameraRef.current);
      }

      animationFrameId.current = requestAnimationFrame(animate);
    };

    animate();

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
      container.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  const flyToThreat = (threat: typeof THREAT_LOCATIONS[0]) => {
    setSelectedThreat(threat);
    onSelectThreat(threat.id);
    const targetY = -(threat.lng * Math.PI) / 180 + Math.PI / 2;
    const targetX = (threat.lat * Math.PI) / 180;
    targetRotation.current.x = targetX * 0.6;
    targetRotation.current.y = targetY;
  };

  const threatScore = selectedThreat.threatScore || 94;
  const strokeDashoffset = 213.6 - (213.6 * threatScore) / 100;

  return (
    <div className="space-y-6">
      
      {/* Top Metrics Ribbon */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Metric 1: Overall Threat Score Gauge */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              Overall Threat Score
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-black font-mono text-slate-900">
                {threatScore}
              </span>
              <span className="text-xs text-slate-400 font-mono">/100</span>
            </div>
            <div>
              <span className={`text-[11px] font-bold px-3 py-0.5 rounded-full border ${
                threatScore > 75 
                  ? 'bg-red-100 text-red-700 border-red-200' 
                  : (threatScore > 40 ? 'bg-amber-100 text-amber-700 border-amber-200' : 'bg-emerald-100 text-emerald-700 border-emerald-200')
              }`}>
                {selectedThreat.severityLabel || 'High Danger'}
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
                stroke={threatScore > 75 ? '#ef4444' : (threatScore > 40 ? '#f59e0b' : '#10b981')} 
                strokeWidth="7" 
                strokeDasharray="213.6" 
                strokeDashoffset={strokeDashoffset} 
                strokeLinecap="round" 
                fill="none" 
              />
            </svg>
            <ShieldAlert className="w-6 h-6 text-red-500 absolute" />
          </div>
        </div>

        {/* Metric 2: Total Threats Detected */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              Total Threats Detected
            </span>
            <span className="text-[10px] font-bold text-red-600 bg-red-50 px-2 py-0.5 rounded border border-red-100">
              Live
            </span>
          </div>
          <div className="text-3xl font-black font-mono text-slate-900">3,277</div>
          <div className="text-xs text-slate-500 flex items-center gap-1.5 pt-1">
            <span className="text-red-600 font-bold font-mono">1,428</span> Phish • 
            <span className="text-orange-600 font-bold font-mono">892</span> Malware • 
            <span className="text-amber-600 font-bold font-mono">645</span> Spoof
          </div>
        </div>

        {/* Metric 3: Active Suspicious Email Sender */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-1 lg:col-span-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-red-500" />
              Active Suspicious Email Sender
            </span>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-100 text-red-800">
              {selectedThreat.status || 'Blocked by Gateway'}
            </span>
          </div>
          <div className="font-mono text-sm font-bold text-slate-900 truncate">
            {selectedThreat.sender}
          </div>
          <div className="text-xs text-slate-500 flex items-center gap-2 truncate">
            <span className="font-bold text-slate-700">Attack Type:</span> 
            <span className="text-slate-800 font-medium">{selectedThreat.simpleTitle}</span> • 
            <span className="font-bold text-slate-700">Location:</span> 
            <span className="font-mono text-slate-600">{selectedThreat.city}, {selectedThreat.country}</span>
          </div>
        </div>

      </div>

      {/* Main Visual Globe Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Large Interactive 3D World Globe */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl shadow-xs overflow-hidden flex flex-col relative">
          
          <div className="p-4 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-white z-10">
            <div className="flex items-center gap-2">
              <GlobeIcon className="w-4 h-4 text-indigo-600" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                Interactive 3D Attack Location Globe
              </h3>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Danger
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Clean
              </span>
              <span className="text-slate-300">|</span>
              <span className="text-slate-500 italic">Drag to spin • Click fly buttons</span>
            </div>
          </div>

          {/* 3D Canvas */}
          <div id="globe-canvas-container" ref={canvasContainerRef} className="w-full h-[420px] sm:h-[460px]" />

          {/* 1-Click Quick Location Jump Buttons */}
          <div className="p-3 bg-slate-50 border-t border-slate-200 flex flex-wrap items-center gap-2 text-xs">
            <span className="font-bold text-slate-500 text-[11px] uppercase tracking-wider mr-1">
              Quick Fly To:
            </span>
            <button 
              onClick={() => flyToThreat(THREAT_LOCATIONS[0])}
              className="px-2.5 py-1 bg-white hover:bg-indigo-50 hover:text-indigo-600 border border-slate-200 rounded-lg font-medium transition-all"
            >
              🇩🇪 Germany (Fake M365)
            </button>
            <button 
              onClick={() => flyToThreat(THREAT_LOCATIONS[1])}
              className="px-2.5 py-1 bg-white hover:bg-indigo-50 hover:text-indigo-600 border border-slate-200 rounded-lg font-medium transition-all"
            >
              🇲🇾 Malaysia (CEO Wire)
            </button>
            <button 
              onClick={() => flyToThreat(THREAT_LOCATIONS[2])}
              className="px-2.5 py-1 bg-white hover:bg-indigo-50 hover:text-indigo-600 border border-slate-200 rounded-lg font-medium transition-all"
            >
              🇷🇺 Russia (LockBit Virus)
            </button>
            <button 
              onClick={() => flyToThreat(THREAT_LOCATIONS[3])}
              className="px-2.5 py-1 bg-white hover:bg-indigo-50 hover:text-indigo-600 border border-slate-200 rounded-lg font-medium transition-all"
            >
              🇳🇱 Netherlands (QR Scam)
            </button>
            <button 
              onClick={() => flyToThreat(THREAT_LOCATIONS[5])}
              className="px-2.5 py-1 bg-white hover:bg-emerald-50 hover:text-emerald-700 border border-slate-200 rounded-lg font-medium transition-all"
            >
              🇺🇸 USA (Safe Stripe)
            </button>
          </div>

          {/* Plain English Threat Summary Overlay */}
          <div className="p-4 bg-slate-900 text-white border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-0.5">
              <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-400">
                Current Threat Telemetry Summary
              </div>
              <p className="text-xs text-slate-200 font-medium leading-relaxed">
                {selectedThreat.plainSummary}
              </p>
            </div>
            <button 
              onClick={onOpenForensics}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl shrink-0 transition-all flex items-center gap-1.5 shadow-sm"
            >
              <Microscope className="w-3.5 h-3.5" />
              Open Forensics
            </button>
          </div>
        </div>

        {/* Right Side: Live Threat List */}
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
                <Radio className="w-4 h-4 text-red-500 animate-pulse" />
                Active Threat Incidents
              </h3>
              <span className="text-[10px] text-slate-400 font-medium">Click to inspect</span>
            </div>

            {/* Threat Feed Items */}
            <div className="space-y-2.5 mt-4 max-h-[380px] overflow-y-auto pr-1">
              {THREAT_LOCATIONS.map((item) => {
                const isItemActive = selectedThreat.id === item.id;
                const isSafe = item.severity === 'safe';
                return (
                  <div
                    key={item.id}
                    onClick={() => flyToThreat(item)}
                    className={`p-3 rounded-xl border transition-all cursor-pointer ${
                      isItemActive
                        ? 'bg-indigo-50/70 border-indigo-300 ring-1 ring-indigo-200'
                        : 'bg-slate-50/70 border-slate-200 hover:border-slate-300 hover:bg-slate-100/70'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1 min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className={`w-2 h-2 rounded-full shrink-0 ${isSafe ? 'bg-emerald-500' : 'bg-red-500'}`} />
                          <span className="text-xs font-bold text-slate-900 truncate">
                            {item.city}, {item.country}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-600 line-clamp-1 font-medium">
                          {item.simpleTitle}
                        </p>
                        <div className="text-[10px] font-mono text-slate-400">
                          {item.ip} • {item.timestamp}
                        </div>
                      </div>

                      <div className="text-right shrink-0">
                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                          isSafe ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                        }`}>
                          Score: {item.threatScore}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Quick Action Card */}
          <div className="p-4 bg-indigo-50/50 border border-indigo-100 rounded-xl space-y-2">
            <div className="text-xs font-bold text-slate-900">Analyze Suspicious Email</div>
            <p className="text-[11px] text-slate-600">Upload any .eml file or paste text to perform deep forensic inspection.</p>
            <button 
              onClick={onOpenForensics}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl transition-all shadow-xs"
            >
              Open Forensics Suite
            </button>
          </div>
        </div>

      </div>

    </div>
  );
};
