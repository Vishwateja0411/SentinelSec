'use client';

import React from 'react';
import { ShieldCheck, Server, Lock, Radio, Activity } from 'lucide-react';
import { HealthResponse } from '@/lib/types';

interface NavbarProps {
  currentTab: 'overview' | 'targets' | 'assessments';
  setCurrentTab: (tab: 'overview' | 'targets' | 'assessments') => void;
  health: HealthResponse | null;
  healthLoading: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  health,
  healthLoading,
}) => {
  return (
    <header className="sticky top-0 z-50 border-b border-navy-700 bg-navy-900/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo & Title */}
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-cyber-blue to-navy-750 border border-cyber-blue/30 flex items-center justify-center text-cyber-sky shadow-lg shadow-cyber-blue/20">
              <ShieldCheck className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xl font-bold tracking-tight text-white">
                  Sentinel<span className="text-cyber-blue">Sec</span>
                </span>
                <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-navy-750 text-cyan-400 border border-cyan-500/30">
                  Assessments & Reporting
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Defensive Security Assessment Governance Platform
              </p>
            </div>
          </div>

          {/* Navigation Controls */}
          <nav className="flex items-center space-x-1 sm:space-x-2">
            <button
              onClick={() => setCurrentTab('overview')}
              className={`px-3 py-1.5 text-sm font-medium rounded-md transition-all flex items-center space-x-2 ${
                currentTab === 'overview'
                  ? 'bg-navy-750 text-cyber-sky border border-cyber-blue/40 shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-navy-800'
              }`}
            >
              <Server className="h-4 w-4" />
              <span>Overview</span>
            </button>
            <button
              onClick={() => setCurrentTab('targets')}
              className={`px-3 py-1.5 text-sm font-medium rounded-md transition-all flex items-center space-x-2 ${
                currentTab === 'targets'
                  ? 'bg-navy-750 text-cyber-sky border border-cyber-blue/40 shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-navy-800'
              }`}
            >
              <Lock className="h-4 w-4" />
              <span>Targets & Authorization</span>
            </button>
            <button
              onClick={() => setCurrentTab('assessments')}
              className={`px-3 py-1.5 text-sm font-medium rounded-md transition-all flex items-center space-x-2 ${
                currentTab === 'assessments'
                  ? 'bg-navy-750 text-cyber-sky border border-cyber-blue/40 shadow-sm'
                  : 'text-slate-300 hover:text-white hover:bg-navy-800'
              }`}
            >
              <Activity className="h-4 w-4" />
              <span>Assessments & Results</span>
            </button>
          </nav>

          {/* Backend Status Indicator */}
          <div className="hidden md:flex items-center space-x-2 text-xs border border-navy-700 bg-navy-850 px-3 py-1.5 rounded-full">
            <Radio
              className={`h-3.5 w-3.5 animate-pulse ${
                health?.status === 'healthy' && health?.version
                  ? 'text-cyber-emerald'
                  : healthLoading
                  ? 'text-amber-400'
                  : 'text-rose-500'
              }`}
            />
            <span className="text-slate-300">
              {healthLoading
                ? 'Connecting API...'
                : health?.status === 'healthy' && health?.version
                ? `FastAPI v${health.version} Online (DB Connected)`
                : health?.status === 'healthy'
                ? `Foreign Service: ${health?.app || 'Port 8000 Conflict'}`
                : 'API Unavailable'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
