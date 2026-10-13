'use client';

import React from 'react';
import { Shield, Globe, Terminal, CheckCircle2, AlertTriangle, Cpu, Database } from 'lucide-react';
import { HealthResponse, Target } from '@/lib/types';

interface OverviewStatsProps {
  targets: Target[];
  totalTargets: number;
  health: HealthResponse | null;
  onNavigateToTargets: () => void;
}

export const OverviewStats: React.FC<OverviewStatsProps> = ({
  targets,
  totalTargets,
  health,
  onNavigateToTargets,
}) => {
  const ipCount = targets.filter((t) => t.type === 'ip').length;
  const urlCount = targets.filter((t) => t.type === 'url').length;

  return (
    <div className="space-y-6">
      {/* Top Banner Alert */}
      <div className="rounded-xl border border-cyber-blue/30 bg-navy-850/80 p-5 backdrop-blur-sm shadow-lg">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3">
            <div className="p-2.5 rounded-lg bg-cyber-blue/10 text-cyber-sky border border-cyber-blue/30 mt-0.5">
              <Shield className="h-6 w-6" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">
                Defensive Governance & Scope Enforced
              </h2>
              <p className="text-sm text-slate-300 mt-0.5 max-w-2xl">
                SentinelSec is in <strong className="text-cyber-sky">Phase 1 (Target Intake & Authorization Records)</strong>. 
                Submitted endpoints are persisted strictly as inert data. No external network connections, port probes, or vulnerability scanning engines are active.
              </p>
            </div>
          </div>
          <button
            onClick={onNavigateToTargets}
            className="px-4 py-2 text-sm font-medium rounded-lg bg-cyber-blue hover:bg-blue-600 text-white shadow-md shadow-blue-500/20 transition-all flex items-center space-x-2 shrink-0"
          >
            <span>Register New Target</span>
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Targets */}
        <div className="rounded-xl border border-navy-700 bg-navy-800/80 p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
              Total Targets
            </span>
            <div className="p-2 rounded-lg bg-navy-750 text-cyber-blue">
              <Shield className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-3xl font-bold text-white">{totalTargets}</span>
            <span className="text-xs text-slate-400">authorized records</span>
          </div>
        </div>

        {/* IP Targets */}
        <div className="rounded-xl border border-navy-700 bg-navy-800/80 p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
              IP Endpoints
            </span>
            <div className="p-2 rounded-lg bg-navy-750 text-indigo-400">
              <Terminal className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-3xl font-bold text-white">{ipCount}</span>
            <span className="text-xs text-slate-400">IPv4 / IPv6</span>
          </div>
        </div>

        {/* URL Targets */}
        <div className="rounded-xl border border-navy-700 bg-navy-800/80 p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
              Web URLs
            </span>
            <div className="p-2 rounded-lg bg-navy-750 text-cyan-400">
              <Globe className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-3xl font-bold text-white">{urlCount}</span>
            <span className="text-xs text-slate-400">HTTP / HTTPS</span>
          </div>
        </div>

        {/* Attestation Compliance */}
        <div className="rounded-xl border border-navy-700 bg-navy-800/80 p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
              Attestation Compliance
            </span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <CheckCircle2 className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-3xl font-bold text-emerald-400">100%</span>
            <span className="text-xs text-slate-400">Mandatory verification</span>
          </div>
        </div>
      </div>

      {/* System & Architecture Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Core Architecture */}
        <div className="rounded-xl border border-navy-700 bg-navy-800/60 p-6 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center space-x-2">
            <Cpu className="h-5 w-5 text-cyber-blue" />
            <span>Infrastructure Scaffolding Status</span>
          </h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 rounded-lg bg-navy-850 border border-navy-700">
              <div className="flex items-center space-x-3">
                <Database className="h-4 w-4 text-cyan-400" />
                <span className="text-sm text-slate-200">PostgreSQL (SQLAlchemy 2.x Async)</span>
              </div>
              <span className={`px-2.5 py-0.5 text-xs font-medium rounded-full ${
                health?.database_connected ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30' : 'bg-amber-950/80 text-amber-400 border border-amber-500/30'
              }`}>
                {health?.database_connected ? 'Connected' : 'Connecting'}
              </span>
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg bg-navy-850 border border-navy-700">
              <div className="flex items-center space-x-3">
                <Cpu className="h-4 w-4 text-cyber-blue" />
                <span className="text-sm text-slate-200">Celery Worker & Redis Broker</span>
              </div>
              <span className="px-2.5 py-0.5 text-xs font-medium rounded-full bg-navy-750 text-slate-300 border border-navy-600">
                Scaffolded (Idle / Safe)
              </span>
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg bg-navy-850 border border-navy-700">
              <div className="flex items-center space-x-3">
                <Shield className="h-4 w-4 text-amber-400" />
                <span className="text-sm text-slate-200">Tool Container Isolation Sandbox</span>
              </div>
              <span className="px-2.5 py-0.5 text-xs font-medium rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-500/30">
                Isolated Placeholder
              </span>
            </div>
          </div>
        </div>

        {/* Phase 1 Verification Requirements */}
        <div className="rounded-xl border border-navy-700 bg-navy-800/60 p-6 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center space-x-2">
            <AlertTriangle className="h-5 w-5 text-cyber-sky" />
            <span>Target Validation & Guardrails</span>
          </h3>
          <ul className="space-y-2.5 text-sm text-slate-300">
            <li className="flex items-start space-x-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              <span><strong>Affirmative Attestation:</strong> Scan intake rejects requests without explicit ownership or written permission.</span>
            </li>
            <li className="flex items-start space-x-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              <span><strong>Credential Stripping:</strong> URLs with embedded credentials (e.g. user:pass@host) are rejected at the schema level.</span>
            </li>
            <li className="flex items-start space-x-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              <span><strong>Strict Scheme Filtering:</strong> Only http:// and https:// schemes are accepted; dangerous protocols are rejected.</span>
            </li>
            <li className="flex items-start space-x-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
              <span><strong>Inert Persistence:</strong> Zero network probes or DNS queries are executed against target endpoints in this phase.</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};
