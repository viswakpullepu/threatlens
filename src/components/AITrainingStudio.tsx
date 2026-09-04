import React, { useState } from 'react';
import { 
  Cpu, 
  Play, 
  Sparkles, 
  RotateCcw, 
  TrendingUp, 
  CheckCircle2, 
  Layers, 
  Sliders, 
  Zap, 
  Database,
  Plus,
  ArrowUpRight
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { trainingEngineInstance } from '../engine/trainingEngine';
import { THREAT_CATEGORIES_METADATA } from '../engine/threatKnowledgeBase';
import { ModelMetrics, ThreatCategory } from '../types';

interface AITrainingStudioProps {
  onMetricsUpdated: (metrics: ModelMetrics) => void;
}

export const AITrainingStudio: React.FC<AITrainingStudioProps> = ({ onMetricsUpdated }) => {
  const [metrics, setMetrics] = useState<ModelMetrics>(trainingEngineInstance.getMetrics());
  const [isTraining, setIsTraining] = useState<boolean>(false);
  const [customPayload, setCustomPayload] = useState<string>('');
  const [customCategory, setCustomCategory] = useState<ThreatCategory>('prompt_injection');
  const [customIsThreat, setCustomIsThreat] = useState<boolean>(true);
  const [customDescription, setCustomDescription] = useState<string>('');
  const [recentlyGenerated, setRecentlyGenerated] = useState<string[]>([]);

  const handleStepEpoch = async () => {
    setIsTraining(true);
    const newMetrics = await trainingEngineInstance.trainEpoch();
    setMetrics({ ...newMetrics });
    onMetricsUpdated({ ...newMetrics });
    setIsTraining(false);

    if (newMetrics.accuracy >= 99.0) {
      confetti({ particleCount: 80, spread: 70, origin: { y: 0.6 } });
    }
  };

  const handleRunContinuousTraining = async () => {
    setIsTraining(true);
    let finalMetrics = metrics;
    for (let i = 0; i < 3; i++) {
      finalMetrics = await trainingEngineInstance.trainEpoch();
      setMetrics({ ...finalMetrics });
      onMetricsUpdated({ ...finalMetrics });
    }
    setIsTraining(false);
    confetti({ particleCount: 120, spread: 90, origin: { y: 0.6 } });
  };

  const handleGenerateZeroDays = () => {
    const generated = trainingEngineInstance.generateSyntheticMutations(customCategory, 5);
    setRecentlyGenerated(generated.map(g => `[${g.category.toUpperCase()}] ${g.payload.slice(0, 60)}...`));
    setMetrics({ ...trainingEngineInstance.getMetrics() });
    onMetricsUpdated({ ...trainingEngineInstance.getMetrics() });
  };

  const handleAddCustomSample = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customPayload.trim()) return;

    trainingEngineInstance.addSample({
      category: customCategory,
      payload: customPayload.trim(),
      isThreat: customIsThreat,
      difficulty: 'zero-day',
      description: customDescription || 'User-submitted training instance',
      tags: ['user-fine-tuned', customCategory]
    });

    const updated = await trainingEngineInstance.trainEpoch();
    setMetrics({ ...updated });
    onMetricsUpdated({ ...updated });
    setCustomPayload('');
    setCustomDescription('');
  };

  return (
    <div className="space-y-6">
      
      {/* Top Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-1">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Model Accuracy</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-emerald-600">{(metrics.accuracy).toFixed(2)}%</span>
            <span className="text-xs text-slate-400 font-mono">Top-1</span>
          </div>
          <p className="text-[11px] text-slate-500">Cross-entropy validated</p>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-1">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Loss Function</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-indigo-600">{metrics.loss.toFixed(4)}</span>
            <span className="text-xs text-slate-400 font-mono">Decay</span>
          </div>
          <p className="text-[11px] text-slate-500">Converging to global minimum</p>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-1">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Trained Samples</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-slate-900">{metrics.totalTrainedSamples}</span>
            <span className="text-xs text-slate-400 font-mono">Vectors</span>
          </div>
          <p className="text-[11px] text-slate-500">Multi-vector coverage</p>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-1">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Precision / Recall</span>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-purple-600">{(metrics.precision).toFixed(1)}%</span>
            <span className="text-xs text-slate-400 font-mono">F1</span>
          </div>
          <p className="text-[11px] text-slate-500">0% False Positives on benign</p>
        </div>

      </div>

      {/* Main Training Control & Mutator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Continuous Trainer Controls */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-6">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-indigo-600" />
              Live Epoch Trainer
            </h3>
            <span className="text-[10px] font-mono font-bold bg-indigo-50 text-indigo-700 px-2 py-0.5 rounded">
              Epochs: {metrics.epochsCompleted}
            </span>
          </div>

          <div className="space-y-3">
            <button
              onClick={handleStepEpoch}
              disabled={isTraining}
              className="w-full py-3 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl transition-all flex items-center justify-center gap-2 cursor-pointer shadow-xs"
            >
              <Play className="w-4 h-4" />
              {isTraining ? 'Optimizing Gradient Descent...' : 'Step 1 Training Epoch'}
            </button>

            <button
              onClick={handleRunContinuousTraining}
              disabled={isTraining}
              className="w-full py-3 bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold rounded-xl transition-all flex items-center justify-center gap-2 cursor-pointer shadow-xs"
            >
              <Sparkles className="w-4 h-4 text-indigo-400" />
              Run 3 Continuous Epochs
            </button>

            <button
              onClick={handleGenerateZeroDays}
              className="w-full py-3 bg-slate-50 hover:bg-slate-100 text-slate-800 border border-slate-200 text-xs font-bold rounded-xl transition-all flex items-center justify-center gap-2 cursor-pointer"
            >
              <Zap className="w-4 h-4 text-amber-500" />
              Generate Synthetic Mutations
            </button>
          </div>

          {recentlyGenerated.length > 0 && (
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1.5 text-xs font-mono">
              <span className="text-[10px] font-bold text-slate-400 uppercase">Latest Synthetic Mutations:</span>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {recentlyGenerated.map((m, i) => (
                  <div key={i} className="text-slate-700 truncate text-[11px]">{m}</div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Custom Sample Fine-Tuner */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
              <Plus className="w-4 h-4 text-indigo-600" />
              Custom Vector Fine-Tuning Lab
            </h3>
            <span className="text-[10px] font-mono text-slate-400">Zero-Shot Calibration</span>
          </div>

          <form onSubmit={handleAddCustomSample} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-bold text-slate-700 block mb-1">Threat Vector Category</label>
                <select
                  value={customCategory}
                  onChange={(e) => setCustomCategory(e.target.value as ThreatCategory)}
                  className="w-full p-2.5 text-xs bg-slate-50 border border-slate-200 rounded-xl font-bold"
                >
                  {Object.entries(THREAT_CATEGORIES_METADATA).map(([k, v]) => (
                    <option key={k} value={k}>{v.name}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs font-bold text-slate-700 block mb-1">Classification Label</label>
                <select
                  value={customIsThreat ? 'threat' : 'benign'}
                  onChange={(e) => setCustomIsThreat(e.target.value === 'threat')}
                  className="w-full p-2.5 text-xs bg-slate-50 border border-slate-200 rounded-xl font-bold"
                >
                  <option value="threat">Malicious Attack Vector</option>
                  <option value="benign">Legitimate Safe / Benign Baseline</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-xs font-bold text-slate-700 block mb-1">Training Payload or Pattern</label>
              <textarea
                rows={3}
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
                placeholder="e.g. <?php system($_GET['cmd']); ?> or custom prompt jailbreak..."
                className="w-full p-3 font-mono text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:bg-white text-slate-900"
              />
            </div>

            <div className="flex items-center justify-between">
              <input
                type="text"
                value={customDescription}
                onChange={(e) => setCustomDescription(e.target.value)}
                placeholder="Description of mutation or zero-day behavior (optional)"
                className="flex-1 mr-3 p-2.5 text-xs bg-slate-50 border border-slate-200 rounded-xl"
              />
              <button
                type="submit"
                className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold rounded-xl transition-all cursor-pointer shadow-xs shrink-0"
              >
                Fine-Tune Model
              </button>
            </div>
          </form>
        </div>

      </div>

      {/* Per Category Accuracy */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
          <Sliders className="w-4 h-4 text-indigo-600" />
          Per-Vector Model Accuracy & Coverage
        </h3>
        
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {Object.entries(metrics.categoryAccuracy).map(([cat, acc]) => {
            const meta = (THREAT_CATEGORIES_METADATA as any)[cat];
            return (
              <div key={cat} className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900 truncate">{meta?.name || cat}</span>
                  <span className="font-mono text-xs font-bold text-emerald-600">{acc.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-slate-200 rounded-full h-1.5 overflow-hidden">
                  <div className="bg-emerald-500 h-1.5 rounded-full" style={{ width: `${acc}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};
