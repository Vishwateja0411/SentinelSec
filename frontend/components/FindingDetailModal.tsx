'use client';

import React, { useState } from 'react';
import { Finding } from '@/lib/types';
import {
  X,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  Copy,
  Code2,
  FileCode,
  Check,
  Server,
  Network,
  Bug,
  HelpCircle,
} from 'lucide-react';

interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({ finding, onClose }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!finding) return null;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'bg-purple-950/80 text-purple-300 border-purple-500/40';
      case 'High':
        return 'bg-rose-950/80 text-rose-300 border-rose-500/40';
      case 'Medium':
        return 'bg-amber-950/80 text-amber-300 border-amber-500/40';
      case 'Low':
        return 'bg-blue-950/80 text-blue-300 border-blue-500/40';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-600';
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/85 backdrop-blur-md flex items-center justify-center p-3 sm:p-6">
      <div className="relative w-full max-w-4xl rounded-2xl border border-navy-700 bg-navy-900 shadow-2xl p-6 sm:p-8 space-y-6 max-h-[92vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-navy-750">
          <div className="space-y-2.5 max-w-2xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-2.5 py-0.5 rounded-md text-xs font-semibold border ${getSeverityBadge(finding.severity)}`}>
                {finding.severity.toUpperCase()}
              </span>
              {finding.cvss_score !== null && finding.cvss_score !== undefined && (
                <span className="px-2.5 py-0.5 rounded-md text-xs font-mono bg-navy-800 text-slate-300 border border-navy-700">
                  CVSS v3.1: <strong className="text-white">{finding.cvss_score.toFixed(1)}</strong>
                </span>
              )}
              {finding.cwe_id && (
                <span className="px-2.5 py-0.5 rounded-md text-xs font-mono bg-navy-800 text-cyan-300 border border-cyan-500/30">
                  {finding.cwe_id}
                </span>
              )}
              <span className="px-2.5 py-0.5 rounded-md text-xs font-medium bg-navy-800 text-amber-300/90 border border-amber-500/30">
                {finding.owasp_category}
              </span>
              <span className={`px-2.5 py-0.5 rounded-md text-xs font-semibold border ${
                finding.check_method === 'runtime_observations'
                  ? 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
                  : finding.check_method === 'source_code_analysis'
                  ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40'
                  : finding.check_method === 'dependency_analysis'
                  ? 'bg-amber-950/80 text-amber-300 border-amber-500/40'
                  : 'bg-navy-800 text-slate-300 border-navy-700'
              }`}>
                {finding.check_method === 'runtime_observations'
                  ? 'DAST (Runtime Observation)'
                  : finding.check_method === 'source_code_analysis'
                  ? 'SAST (Source Code)'
                  : finding.check_method === 'dependency_analysis'
                  ? 'SCA (Dependencies)'
                  : (finding.check_method || 'Check').replace(/_/g, ' ')}
              </span>
              <span className="px-2.5 py-0.5 rounded-md text-xs bg-navy-800 text-slate-400 border border-navy-700">
                Status: <span className="text-emerald-400 font-medium capitalize">{finding.validation_status}</span>
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight leading-snug">{finding.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-navy-800 text-slate-400 hover:text-white hover:bg-navy-700 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Demonstration Disclaimer if synthetic */}
        {finding.raw_output_reference?.includes('DEMONSTRATION') && (
          <div className="p-3.5 rounded-xl bg-amber-950/40 border border-amber-500/30 text-amber-200 text-xs flex items-start space-x-2.5">
            <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-amber-300">DEMONSTRATION DATA — NOT A REAL SCAN:</strong>{' '}
              This is a synthetic baseline educational fixture. It demonstrates SentinelSec's finding and verification pipeline without executing live network attacks.
            </div>
          </div>
        )}

        {/* Target IP, Open Ports & Source Code Location / DAST Scope */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          {/* Affected Endpoint & Host Info */}
          <div className="p-3.5 rounded-xl bg-navy-950/80 border border-navy-800 space-y-2">
            <div className="flex items-center space-x-1.5 text-slate-400 font-semibold uppercase tracking-wider">
              <Network className="h-3.5 w-3.5 text-cyber-blue" />
              <span>Target Asset & Endpoint</span>
            </div>
            <div className="font-mono text-cyan-300 break-all">{finding.affected_endpoint}</div>
            {finding.target_ip && (
              <div className="flex items-center space-x-2 text-slate-400 font-mono text-[11px]">
                <span>IP: <strong className="text-white">{finding.target_ip}</strong></span>
                {finding.open_ports && finding.open_ports.length > 0 && (
                  <span>| Open Ports: <strong className="text-white">{finding.open_ports.map(p => `${p.port}/${p.service || 'tcp'}`).join(', ')}</strong></span>
                )}
              </div>
            )}
          </div>

          {/* Source Code Location or DAST Dynamic Evaluation */}
          <div className="p-3.5 rounded-xl bg-navy-950/80 border border-navy-800 space-y-2">
            <div className="flex items-center space-x-1.5 text-slate-400 font-semibold uppercase tracking-wider">
              {finding.source_file ? (
                <>
                  <FileCode className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Source-Code Location</span>
                </>
              ) : (
                <>
                  <Server className="h-3.5 w-3.5 text-cyan-400" />
                  <span>DAST Assessment Scope</span>
                </>
              )}
            </div>
            {finding.source_file ? (
              <div className="flex items-center justify-between font-mono text-emerald-300 text-xs">
                <span>
                  {finding.source_file}
                  {finding.source_line_start && (
                    <span className="text-slate-400">
                      :L{finding.source_line_start}
                      {finding.source_line_end && finding.source_line_end !== finding.source_line_start
                        ? `-L${finding.source_line_end}`
                        : ''}
                    </span>
                  )}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-950/60 border border-emerald-500/30 text-emerald-400">
                  {finding.check_method?.replace(/_/g, ' ') || 'SAST'}
                </span>
              </div>
            ) : (
              <div className="flex items-center justify-between font-mono text-cyan-300 text-xs">
                <span className="flex items-center space-x-1.5">
                  <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
                  <span>Dynamic Runtime Observation</span>
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] bg-cyan-950/80 border border-cyan-500/40 text-cyan-300">
                  HTTP/HTTPS Live Protocol
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Description & Why Vulnerable */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2 p-4 rounded-xl bg-navy-850/60 border border-navy-750">
            <h3 className="text-sm font-semibold text-white flex items-center space-x-1.5">
              <span>Vulnerability Overview</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>
          </div>

          <div className="space-y-2 p-4 rounded-xl bg-navy-850/60 border border-navy-750">
            <h3 className="text-sm font-semibold text-rose-300 flex items-center space-x-1.5">
              <ShieldAlert className="h-4 w-4" />
              <span>Security Impact</span>
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">{finding.impact}</p>
          </div>
        </div>

        {/* Why Implementation Is Vulnerable */}
        {finding.why_vulnerable && (
          <div className="p-4 rounded-xl bg-navy-950/90 border border-navy-800 space-y-1.5">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-amber-400 flex items-center space-x-1.5">
              <Bug className="h-3.5 w-3.5" />
              <span>Why The Implementation Is Vulnerable</span>
            </h4>
            <p className="text-xs text-slate-200 leading-relaxed">{finding.why_vulnerable}</p>
          </div>
        )}

        {/* Observed Evidence */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              {finding.check_method === 'runtime_observations'
                ? 'Observed DAST Wire Evidence (Live HTTP Dialogue)'
                : 'Observed Technical Evidence'}{' '}
              {finding.evidence_provenance && `(${finding.evidence_provenance})`}
            </label>
            <button
              onClick={() => copyToClipboard(finding.evidence, 'evidence')}
              className="text-xs text-slate-400 hover:text-white flex items-center space-x-1"
            >
              {copiedKey === 'evidence' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copiedKey === 'evidence' ? 'Copied' : 'Copy Evidence'}</span>
            </button>
          </div>
          <pre className="p-4 rounded-xl bg-navy-950 border border-navy-800 font-mono text-xs text-slate-200 overflow-x-auto whitespace-pre-wrap">
            {finding.evidence}
          </pre>
        </div>

        {/* Safe Local Reproduction */}
        {finding.reproduction_steps && (
          <div className="p-4 rounded-xl bg-navy-950/70 border border-navy-800 space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-cyan-300 flex items-center space-x-1.5">
                <Terminal className="h-3.5 w-3.5" />
                <span>Safe Local Reproduction Instructions</span>
              </h4>
              <button
                onClick={() => copyToClipboard(finding.reproduction_steps || '', 'repro')}
                className="text-xs text-slate-400 hover:text-white flex items-center space-x-1"
              >
                {copiedKey === 'repro' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                <span>{copiedKey === 'repro' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <pre className="text-xs font-mono text-cyan-200/90 bg-navy-900/90 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
              {finding.reproduction_steps}
            </pre>
            {finding.expected_insecure_behavior && (
              <div className="text-xs text-slate-400 pt-1">
                <span className="font-semibold text-rose-300">Expected Insecure Behavior:</span> {finding.expected_insecure_behavior}
              </div>
            )}
          </div>
        )}

        {/* Secure Code Example */}
        {finding.secure_code_example && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 flex items-center space-x-1.5">
                <Code2 className="h-3.5 w-3.5" />
                <span>Secure Remediated Code Example</span>
              </h4>
              <button
                onClick={() => copyToClipboard(finding.secure_code_example || '', 'code')}
                className="text-xs text-slate-400 hover:text-white flex items-center space-x-1"
              >
                {copiedKey === 'code' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                <span>{copiedKey === 'code' ? 'Copied' : 'Copy Code'}</span>
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-navy-950 border border-emerald-500/20 font-mono text-xs text-emerald-300 overflow-x-auto whitespace-pre-wrap">
              {finding.secure_code_example}
            </pre>
          </div>
        )}

        {/* Executable Regression Test */}
        {finding.regression_test && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-cyber-blue flex items-center space-x-1.5">
                <Terminal className="h-3.5 w-3.5" />
                <span>Executable Security Regression Test (Pytest)</span>
              </h4>
              <button
                onClick={() => copyToClipboard(finding.regression_test || '', 'test')}
                className="text-xs text-slate-400 hover:text-white flex items-center space-x-1"
              >
                {copiedKey === 'test' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                <span>{copiedKey === 'test' ? 'Copied' : 'Copy Test'}</span>
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-navy-950 border border-cyber-blue/30 font-mono text-xs text-cyan-300 overflow-x-auto whitespace-pre-wrap">
              {finding.regression_test}
            </pre>
          </div>
        )}

        {/* Remediation & Verification Steps */}
        <div className="space-y-4">
          <div className="space-y-2 p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30">
            <h3 className="text-sm font-semibold text-emerald-400 flex items-center space-x-1.5">
              <CheckCircle2 className="h-4 w-4" />
              <span>Recommended Defensive Remediation</span>
            </h3>
            <p className="text-xs text-slate-200 leading-relaxed whitespace-pre-wrap">{finding.remediation}</p>
          </div>

          <div className="space-y-2 p-4 rounded-xl bg-navy-950 border border-navy-800">
            <h3 className="text-sm font-semibold text-slate-300 flex items-center space-x-1.5">
              <Terminal className="h-4 w-4 text-cyber-blue" />
              <span>Verification Steps</span>
            </h3>
            <pre className="text-xs font-mono text-cyan-300 bg-navy-900/80 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
              {finding.verification_steps}
            </pre>
          </div>
        </div>

        {/* Footer Meta */}
        <div className="pt-4 border-t border-navy-800 flex flex-wrap items-center justify-between text-xs text-slate-400 gap-2">
          <div>
            Tool: <span className="text-slate-200 font-medium">{finding.tool} (v{finding.tool_version || '1.0.0'})</span> | Method:{' '}
            <span className="text-slate-200 font-medium capitalize">{finding.check_method?.replace(/_/g, ' ')}</span> | Confidence:{' '}
            <span className="text-slate-200 font-medium">{finding.confidence}</span>
          </div>
          <div>
            Verification Status: <span className="font-medium text-amber-300 capitalize">{finding.remediation_verification_status || 'Unverified'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
