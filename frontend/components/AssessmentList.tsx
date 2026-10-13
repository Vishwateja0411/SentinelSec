'use client';

import React from 'react';
import { Assessment } from '@/lib/types';
import { Play, Activity, Clock, Shield, ChevronRight, Inbox, RefreshCw, FileText } from 'lucide-react';

interface AssessmentListProps {
  assessments: Assessment[];
  loading: boolean;
  onRefresh: () => void;
  onSelectAssessment: (assessment: Assessment) => void;
  onOpenCreateModal: () => void;
}

export const AssessmentList: React.FC<AssessmentListProps> = ({
  assessments,
  loading,
  onRefresh,
  onSelectAssessment,
  onOpenCreateModal,
}) => {
  return (
    <div className="space-y-6">
      {/* Top Banner & Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl border border-navy-700 bg-navy-800/80 shadow-xl backdrop-blur-sm">
        <div>
          <h2 className="text-base font-bold text-white flex items-center space-x-2">
            <Activity className="h-5 w-5 text-cyber-blue" />
            <span>Security Assessments & Scan History</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            View historical assessment records, triage detected vulnerabilities, and export reports.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="p-2 rounded-xl border border-navy-600 bg-navy-850 hover:bg-navy-750 text-slate-300 hover:text-white transition-all disabled:opacity-50"
            title="Refresh Assessments"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin text-cyber-blue' : ''}`} />
          </button>
          <button
            onClick={onOpenCreateModal}
            className="px-4 py-2 rounded-xl bg-cyber-blue hover:bg-blue-600 text-white text-xs font-semibold shadow-lg shadow-blue-500/20 transition-all flex items-center space-x-2"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span>New Assessment</span>
          </button>
        </div>
      </div>

      {/* Loading Skeleton */}
      {loading && assessments.length === 0 && (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-20 rounded-2xl bg-navy-800/50 border border-navy-700/50 animate-pulse" />
          ))}
        </div>
      )}

      {/* Empty State */}
      {!loading && assessments.length === 0 && (
        <div className="p-12 text-center rounded-2xl border border-navy-700 bg-navy-800/40">
          <div className="inline-flex p-3 rounded-full bg-navy-750 text-slate-400 mb-3">
            <Inbox className="h-6 w-6" />
          </div>
          <p className="text-sm font-semibold text-white">No assessments launched yet</p>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            Select an authorized target from your inventory and initiate a demonstration baseline scan.
          </p>
          <button
            onClick={onOpenCreateModal}
            className="mt-4 px-4 py-2 rounded-xl bg-cyber-blue hover:bg-blue-600 text-white text-xs font-medium transition-all"
          >
            Launch First Assessment
          </button>
        </div>
      )}

      {/* Assessments Grid / List */}
      <div className="space-y-3">
        {assessments.map((a) => {
          const totalFindings = a.finding_counts
            ? Object.values(a.finding_counts).reduce((acc, v) => acc + v, 0)
            : 0;

          return (
            <div
              key={a.id}
              onClick={() => onSelectAssessment(a)}
              className="p-5 rounded-2xl border border-navy-700 bg-navy-800/70 hover:bg-navy-750/70 hover:border-cyber-blue/40 shadow-lg cursor-pointer transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              {/* Left Info */}
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider border ${
                      a.mode === 'demonstration'
                        ? 'bg-amber-950/60 text-amber-300 border-amber-500/30'
                        : 'bg-cyber-blue/20 text-cyber-sky border-cyber-blue/30'
                    }`}
                  >
                    {a.mode === 'demonstration' ? 'DEMONSTRATION' : 'LIVE SCAN'}
                  </span>
                  <span className="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-500/30">
                    {a.status.toUpperCase()}
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    ID: {a.id.slice(0, 8)}...
                  </span>
                </div>

                <div className="text-sm font-bold text-white font-mono flex items-center space-x-2">
                  <span>{a.target?.target || a.target_id}</span>
                </div>

                <div className="flex items-center space-x-3 text-xs text-slate-400">
                  <span className="flex items-center space-x-1">
                    <Clock className="h-3 w-3" />
                    <span>{new Date(a.created_at).toUTCString()}</span>
                  </span>
                  <span>•</span>
                  <span>Profile: <strong className="text-slate-300">{a.profile}</strong></span>
                </div>
              </div>

              {/* Right Findings Pills & Action */}
              <div className="flex items-center space-x-4 self-end md:self-auto">
                <div className="flex items-center space-x-1.5 text-xs">
                  {a.finding_counts?.Critical ? (
                    <span className="px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 font-semibold text-[11px] border border-rose-500/30">
                      Crit: {a.finding_counts.Critical}
                    </span>
                  ) : null}
                  {a.finding_counts?.High ? (
                    <span className="px-2 py-0.5 rounded bg-red-950/80 text-red-300 font-semibold text-[11px] border border-red-500/30">
                      High: {a.finding_counts.High}
                    </span>
                  ) : null}
                  {a.finding_counts?.Medium ? (
                    <span className="px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 font-semibold text-[11px] border border-amber-500/30">
                      Med: {a.finding_counts.Medium}
                    </span>
                  ) : null}
                  {a.finding_counts?.Low ? (
                    <span className="px-2 py-0.5 rounded bg-blue-950/80 text-blue-300 font-semibold text-[11px] border border-blue-500/30">
                      Low: {a.finding_counts.Low}
                    </span>
                  ) : null}
                  <span className="px-2 py-0.5 rounded bg-navy-900 text-slate-400 font-medium text-[11px] border border-navy-700">
                    Total: {totalFindings}
                  </span>
                </div>

                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelectAssessment(a);
                  }}
                  className="px-3 py-1.5 rounded-xl bg-navy-750 hover:bg-navy-700 text-cyber-sky text-xs font-semibold border border-cyber-blue/30 flex items-center space-x-1 transition-all"
                >
                  <span>Results</span>
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
