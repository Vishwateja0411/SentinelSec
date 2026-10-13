'use client';

import React, { useState, useEffect } from 'react';
import { Target, Assessment } from '@/lib/types';
import { createAssessment } from '@/lib/api';
import { X, Play, ShieldAlert, AlertTriangle, Loader2, CheckCircle2 } from 'lucide-react';

interface AssessmentCreateModalProps {
  targets: Target[];
  isOpen: boolean;
  onClose: () => void;
  onAssessmentCreated: (assessment: Assessment) => void;
}

export const AssessmentCreateModal: React.FC<AssessmentCreateModalProps> = ({
  targets,
  isOpen,
  onClose,
  onAssessmentCreated,
}) => {
  const [selectedTargetId, setSelectedTargetId] = useState<string>(
    targets.length > 0 ? targets[0].id : ''
  );
  const [profile, setProfile] = useState<string>('standard_baseline');
  const [mode, setMode] = useState<'demonstration' | 'real'>('demonstration');
  const [sourceRepoPath, setSourceRepoPath] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setError(null);
      if (targets.length > 0 && (!selectedTargetId || !targets.some((t) => t.id === selectedTargetId))) {
        setSelectedTargetId(targets[0].id);
      }
    }
  }, [isOpen, targets]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const targetIdToUse = selectedTargetId || (targets.length > 0 ? targets[0].id : '');
    if (!targetIdToUse) {
      setError('Please select an authorized target.');
      return;
    }

    if (mode === 'real') {
      setError('Real scanning mode is disabled in this phase until scanner worker sandboxes are verified.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const created = await createAssessment({
        target_id: targetIdToUse,
        profile,
        mode,
        source_repository_path: sourceRepoPath.trim() || undefined,
      });
      onAssessmentCreated(created);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to initiate assessment.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="relative w-full max-w-xl rounded-2xl border border-navy-700 bg-navy-900 shadow-2xl p-6 sm:p-8 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-navy-700">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-cyber-blue/15 text-cyber-sky border border-cyber-blue/30">
              <Play className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Initiate Security Assessment</h2>
              <p className="text-xs text-slate-400">Launch an assessment for an authorized asset</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-navy-850 text-slate-400 hover:text-white hover:bg-navy-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {error && (
          <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-500/40 text-rose-200 text-xs flex items-start space-x-3">
            <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
            <div>{error}</div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Target Selector */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
              Select Authorized Target
            </label>
            {targets.length === 0 ? (
              <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-500/30 text-amber-200 text-xs">
                No authorized targets registered yet. Please register a target with affirmative attestation first.
              </div>
            ) : (
              <select
                value={selectedTargetId || (targets.length > 0 ? targets[0].id : '')}
                onChange={(e) => setSelectedTargetId(e.target.value)}
                className="w-full px-4 py-2.5 rounded-xl bg-navy-850 border border-navy-700 text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyber-blue font-mono"
              >
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    [{t.type.toUpperCase()}] {t.target} (ID: {t.id.slice(0, 8)}...)
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Profile Selector */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
              Assessment Profile
            </label>
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              className="w-full px-4 py-2.5 rounded-xl bg-navy-850 border border-navy-700 text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyber-blue"
            >
              <option value="standard_baseline">Standard Baseline (Multi-Method Audit: DAST + SAST + SCA)</option>
              <option value="dynamic_dast">Dynamic Application Security Testing (DAST Web & API Assessment)</option>
              <option value="web_application">Web Application Configuration & Ingress Audit</option>
              <option value="api_security_audit">API Endpoint Hardening & Surface Assessment</option>
              <option value="source_code_sast">Static Source-Code Analysis (Semgrep SAST)</option>
              <option value="dependency_sca">Software Supply-Chain Audit (Trivy SCA)</option>
            </select>
          </div>

          {/* Optional Authorized Source Repository / Archive Path */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                Source Repository Path <span className="text-slate-500 font-normal lowercase">(optional for SAST/SCA)</span>
              </label>
              <span className="text-[10px] text-cyber-sky font-mono">Read-Only Worker Sandbox</span>
            </div>
            <input
              type="text"
              placeholder="e.g., C:/Projects/repo or /workspace/src"
              value={sourceRepoPath}
              onChange={(e) => setSourceRepoPath(e.target.value)}
              className="w-full px-4 py-2.5 rounded-xl bg-navy-850 border border-navy-700 text-white text-xs font-mono placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyber-blue"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              Static analysis runs in an isolated read-only worker with no project script execution.
            </p>
          </div>

          {/* Execution Mode Selector */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">
              Execution Mode
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {/* Demonstration Mode Option */}
              <button
                type="button"
                onClick={() => setMode('demonstration')}
                className={`p-4 rounded-xl border text-left transition-all relative ${
                  mode === 'demonstration'
                    ? 'bg-cyber-blue/15 border-cyber-blue shadow-md'
                    : 'bg-navy-850 border-navy-700 opacity-60 hover:opacity-100'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-white">Demonstration Mode</span>
                  <CheckCircle2 className="h-4 w-4 text-cyber-sky" />
                </div>
                <p className="text-xs text-slate-300 mt-1">
                  Zero network traffic. Loads verified synthetic baseline findings for UI & report walkthrough.
                </p>
                <span className="inline-block mt-2 px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  SAFE & ISOLATED
                </span>
              </button>

              {/* Real Mode Option (Disabled) */}
              <button
                type="button"
                onClick={() => setMode('real')}
                className={`p-4 rounded-xl border text-left transition-all opacity-40 cursor-not-allowed ${
                  mode === 'real'
                    ? 'border-rose-500 bg-rose-950/20'
                    : 'bg-navy-850 border-navy-800'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-slate-400">Live Network Scan</span>
                  <ShieldAlert className="h-4 w-4 text-rose-500" />
                </div>
                <p className="text-xs text-slate-500 mt-1">
                  Executes live probes. Disabled until containerized scanner workers are verified.
                </p>
                <span className="inline-block mt-2 px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-400 border border-rose-500/30">
                  DISABLED IN PHASE 1
                </span>
              </button>
            </div>
          </div>

          {/* Submit */}
          <div className="flex items-center justify-end space-x-3 pt-4 border-t border-navy-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium rounded-lg text-slate-300 hover:text-white bg-navy-800 hover:bg-navy-750 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || targets.length === 0}
              className="px-5 py-2.5 rounded-lg bg-cyber-blue hover:bg-blue-600 text-white text-xs font-semibold shadow-lg shadow-blue-500/20 disabled:opacity-50 transition-all flex items-center space-x-2"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Processing Assessment...</span>
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5 fill-current" />
                  <span>Launch Assessment</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
