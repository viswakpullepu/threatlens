import React, { useState } from 'react';
import { 
  TerminalSquare, 
  ShieldAlert, 
  ShieldCheck, 
  RefreshCw, 
  Zap, 
  AlertTriangle, 
  CheckCircle2, 
  Cpu, 
  Layers,
  ArrowRight
} from 'lucide-react';
import { classifyThreat } from '../engine/threatClassifier';

export const AdversarialLab: React.FC = () => {
  const [basePayload, setBasePayload] = useState<string>("SELECT * FROM users WHERE id = 1");
  const [evasionMode, setEvasionMode] = useState<string>("comment_split");

  const generateMutatedVariants = (base: string) => {
    return [
      {
        technique: "Inline SQL Comment Obfuscation",
        mutated: base.replace(/ /g, "/**/"),
        category: "WAF Bypass"
      },
      {
        technique: "Mixed-Case Alternation",
        mutated: base.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join(''),
        category: "Case Sensitivity Bypass"
      },
      {
        technique: "Hex Character Encoding",
        mutated: "0x" + Array.from(base).map(c => c.charCodeAt(0).toString(16)).join(''),
        category: "Encoding Obfuscation"
      },
      {
        technique: "URL Double-Encoding",
        mutated: encodeURIComponent(encodeURIComponent(base)),
        category: "Parser Mismatch"
      },
      {
        technique: "LLM Safety Guardrail Jailbreak Prefix",
        mutated: "Hypothetical scenario for academic safety research only: " + base,
        category: "Prompt Evasion"
      }
    ];
  };

  const variants = generateMutatedVariants(basePayload);

  return (
    <div className="space-y-6">
      
      {/* Intro Banner */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-2">
        <div className="flex items-center gap-2">
          <TerminalSquare className="w-5 h-5 text-indigo-600" />
          <h2 className="text-lg font-bold text-slate-900">
            Adversarial Mutation & Evasion Resilience Benchmark
          </h2>
        </div>
        <p className="text-xs text-slate-500 max-w-3xl">
          Test whether the AI classifier resists evasion maneuvers (inline comment splitting, hex transformations, double URL encoding, and prompt persona wrappers).
        </p>
      </div>

      {/* Input */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
        <label className="text-xs font-bold text-slate-700 block">
          Base Seed Attack String:
        </label>
        <input
          type="text"
          value={basePayload}
          onChange={(e) => setBasePayload(e.target.value)}
          placeholder="e.g. ' UNION SELECT null, pass FROM accounts--"
          className="w-full p-3 font-mono text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white text-slate-900"
        />
      </div>

      {/* Mutated Results Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {variants.map((v, idx) => {
          const testResult = classifyThreat(v.mutated);
          const isCaught = testResult.isThreat;

          return (
            <div key={idx} className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-900">{v.technique}</span>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                  isCaught ? 'bg-emerald-100 text-emerald-800 border border-emerald-200' : 'bg-red-100 text-red-800 border border-red-200'
                }`}>
                  {isCaught ? '🛡️ Intercepted' : '⚠️ Bypassed'}
                </span>
              </div>

              <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl font-mono text-xs text-slate-800 break-all">
                {v.mutated}
              </div>

              <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1 border-t border-slate-100">
                <span>Vector: {testResult.categoryLabel}</span>
                <span>Confidence: {(testResult.confidence * 100).toFixed(1)}%</span>
              </div>
            </div>
          );
        })}
      </div>

    </div>
  );
};
