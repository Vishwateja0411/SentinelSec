'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { Assessment, Finding, OWASPCategoryCoverage } from '@/lib/types';
import {
  fetchAssessmentFindings,
  fetchAssessmentReportMarkdown,
  getAssessmentReportPdfUrl,
} from '@/lib/api';
import { FindingDetailModal } from '@/components/FindingDetailModal';
import {
  ArrowLeft,
  Download,
  FileText,
  Shield,
  AlertTriangle,
  Search,
  Filter,
  CheckCircle2,
  ExternalLink,
  Loader2,
  RefreshCw,
  BarChart2,
  Code2,
  FileCode,
  Network,
  Info,
  Layers,
  Check,
  AlertCircle,
  HelpCircle,
  Radio,
  Activity,
  Globe,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

interface ScanResultsViewProps {
  assessment: Assessment;
  onBack: () => void;
}

const OWASP_CATEGORIES_METADATA: Record<string, { name: string; description: string }> = {
  A01: { name: 'Broken Access Control', description: 'Enforcement flaws in permissions, IDOR, or CORS configurations.' },
  A02: { name: 'Cryptographic Failures', description: 'Weak ciphers, cleartext protocols, or hardcoded secrets.' },
  A03: { name: 'Injection', description: 'SQL, OS command, or code injection via unvalidated input.' },
  A04: { name: 'Insecure Design', description: 'Architectural and design flaws requiring manual threat modeling.' },
  A05: { name: 'Security Misconfiguration', description: 'Default passwords, verbose headers, unhardened middleware.' },
  A06: { name: 'Vulnerable and Outdated Components', description: 'Supply-chain dependencies and container libraries with CVEs.' },
  A07: { name: 'Identification and Authentication Failures', description: 'Session fixation, weak password schemes, or missing MFA.' },
  A08: { name: 'Software and Data Integrity Failures', description: 'Insecure deserialization and unverified CI/CD artifacts.' },
  A09: { name: 'Security Logging and Monitoring Failures', description: 'Missing audit logs, untracked authentication anomalies.' },
  A10: { name: 'Server-Side Request Forgery (SSRF)', description: 'Unrestricted remote network resource fetching by the server.' },
};

export const ScanResultsView: React.FC<ScanResultsViewProps> = ({ assessment, onBack }) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Active view tab
  const [activeTab, setActiveTab] = useState<'matrix' | 'findings' | 'dast' | 'source_code'>('matrix');

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [methodFilter, setMethodFilter] = useState<string>('ALL');

  // Report download states
  const [downloadingMarkdown, setDownloadingMarkdown] = useState<boolean>(false);

  const loadFindings = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAssessmentFindings(assessment.id, { limit: 100 });
      setFindings(data.items);
    } catch (err: any) {
      setError(err.message || 'Failed to load assessment findings.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, [assessment.id]);

  const handleDownloadMarkdown = async () => {
    setDownloadingMarkdown(true);
    try {
      const report = await fetchAssessmentReportMarkdown(assessment.id);
      const blob = new Blob([report.markdown], { type: 'text/markdown;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sentinelsec_report_${assessment.id.slice(0, 8)}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Error exporting report: ${err.message}`);
    } finally {
      setDownloadingMarkdown(false);
    }
  };

  const counts = useMemo(() => {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
    findings.forEach((f) => {
      if (f.severity in c) {
        c[f.severity as keyof typeof c]++;
      }
    });
    return c;
  }, [findings]);

  const chartData = useMemo(() => {
    return [
      { name: 'Critical', count: counts.Critical, color: '#a855f7' },
      { name: 'High', count: counts.High, color: '#f43f5e' },
      { name: 'Medium', count: counts.Medium, color: '#f59e0b' },
      { name: 'Low', count: counts.Low, color: '#3b82f6' },
      { name: 'Info', count: counts.Informational, color: '#64748b' },
    ];
  }, [counts]);

  const dastFindings = useMemo(() => {
    return findings.filter(
      (f) =>
        f.check_method === 'runtime_observations' ||
        (!f.source_file && f.check_method !== 'dependency_analysis')
    );
  }, [findings]);

  const sourceCodeFindings = useMemo(() => {
    return findings.filter((f) => f.source_file);
  }, [findings]);

  // Filtered & Displayed Findings
  const displayedFindings = useMemo(() => {
    let list = findings;
    if (activeTab === 'dast') {
      list = dastFindings;
    } else if (activeTab === 'source_code') {
      list = sourceCodeFindings;
    }

    return list.filter((f) => {
      const matchesSearch =
        searchQuery === '' ||
        f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.affected_endpoint.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (f.cwe_id && f.cwe_id.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (f.source_file && f.source_file.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesSeverity =
        severityFilter === 'ALL' || f.severity === severityFilter;

      const matchesStatus =
        statusFilter === 'ALL' || f.validation_status === statusFilter;

      const matchesCategory =
        categoryFilter === 'ALL' ||
        (f.owasp_category && f.owasp_category.includes(categoryFilter));

      const matchesMethod =
        methodFilter === 'ALL' || f.check_method === methodFilter;

      return matchesSearch && matchesSeverity && matchesStatus && matchesCategory && matchesMethod;
    });
  }, [findings, activeTab, dastFindings, sourceCodeFindings, searchQuery, severityFilter, statusFilter, categoryFilter, methodFilter]);

  const getSeverityBadgeClass = (severity: string) => {
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

  const getCoverageBadge = (status: string) => {
    switch (status) {
      case 'findings_identified':
        return {
          bg: 'bg-rose-950/70 border-rose-500/50 text-rose-300',
          dot: 'bg-rose-400',
          label: 'Findings Identified',
        };
      case 'no_findings_identified':
        return {
          bg: 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300',
          dot: 'bg-emerald-400',
          label: 'No Findings by Checks',
        };
      case 'manual_review_required':
        return {
          bg: 'bg-amber-950/60 border-amber-500/40 text-amber-300',
          dot: 'bg-amber-400',
          label: 'Manual Review Required',
        };
      case 'inconclusive':
        return {
          bg: 'bg-yellow-950/60 border-yellow-500/40 text-yellow-300',
          dot: 'bg-yellow-400',
          label: 'Inconclusive',
        };
      case 'not_assessed':
      default:
        return {
          bg: 'bg-slate-800/80 border-slate-700 text-slate-400',
          dot: 'bg-slate-500',
          label: 'Not Assessed',
        };
    }
  };

  const matrix = assessment.owasp_coverage_matrix || {};

  return (
    <div className="space-y-6">
      {/* Navigation & Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <button
          onClick={onBack}
          className="inline-flex items-center space-x-2 text-xs font-semibold text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>Back to Assessments</span>
        </button>

        {/* Report Export Action Buttons */}
        <div className="flex items-center space-x-3">
          <button
            onClick={handleDownloadMarkdown}
            disabled={downloadingMarkdown || loading}
            className="px-3.5 py-2 rounded-xl border border-navy-600 bg-navy-850 hover:bg-navy-750 text-slate-200 hover:text-white text-xs font-medium transition-all flex items-center space-x-2 disabled:opacity-50"
          >
            {downloadingMarkdown ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <FileText className="h-3.5 w-3.5 text-cyber-sky" />
            )}
            <span>Export Markdown</span>
          </button>

          <a
            href={getAssessmentReportPdfUrl(assessment.id)}
            target="_blank"
            rel="noopener noreferrer"
            className="px-4 py-2 rounded-xl bg-cyber-blue hover:bg-blue-600 text-white text-xs font-semibold shadow-md shadow-blue-500/20 transition-all flex items-center space-x-2"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Download PDF Report</span>
          </a>
        </div>
      </div>

      {/* Demonstration Banner */}
      {assessment.mode === 'demonstration' && (
        <div className="p-4 rounded-2xl bg-amber-950/40 border border-amber-500/30 text-amber-200 text-xs flex items-start space-x-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="font-bold text-amber-300 uppercase tracking-wide">
              Demonstration Assessment — Synthetic Educational Fixtures
            </h4>
            <p className="text-amber-200/90 leading-relaxed">
              This assessment utilized synthetic fixtures mapping to OWASP Top 10:2025. No network packets were directed at the target{' '}
              <strong className="text-white font-mono">{assessment.target?.target || assessment.target_id}</strong>. 
              Findings include source-code locations, why vulnerable, safe reproduction steps, secure code examples, and executable regression test assertions.
            </p>
          </div>
        </div>
      )}

      {/* Assessment Meta Banner */}
      <div className="rounded-2xl border border-navy-700 bg-navy-850/80 p-5 shadow-xl backdrop-blur-sm grid grid-cols-1 md:grid-cols-4 gap-4">
        <div>
          <span className="text-[11px] uppercase text-slate-400 font-semibold tracking-wider">Target Endpoint</span>
          <div className="text-sm font-bold text-white font-mono mt-1 truncate" title={assessment.target?.target}>
            {assessment.target?.target || assessment.target_id}
          </div>
          {assessment.target_ip && (
            <div className="text-xs text-cyber-sky font-mono mt-0.5 flex items-center space-x-1.5">
              <span>IP: {assessment.target_ip}</span>
            </div>
          )}
        </div>
        <div>
          <span className="text-[11px] uppercase text-slate-400 font-semibold tracking-wider">Identified Ports</span>
          <div className="text-xs font-mono text-slate-300 mt-1">
            {assessment.open_ports && assessment.open_ports.length > 0 ? (
              assessment.open_ports.map((p) => `${p.port}/${p.service || 'tcp'}`).join(', ')
            ) : (
              <span className="text-slate-500 italic">No ports recorded</span>
            )}
          </div>
        </div>
        <div>
          <span className="text-[11px] uppercase text-slate-400 font-semibold tracking-wider">Profile & Status</span>
          <div className="flex items-center space-x-2 mt-1">
            <span className="px-2 py-0.5 rounded text-xs bg-navy-750 text-slate-300 border border-navy-700 font-mono">
              {assessment.profile}
            </span>
            <span className="px-2 py-0.5 rounded text-xs bg-emerald-950/80 text-emerald-400 border border-emerald-500/30 font-medium uppercase">
              {assessment.status}
            </span>
          </div>
        </div>
        <div>
          <span className="text-[11px] uppercase text-slate-400 font-semibold tracking-wider">Assessment ID</span>
          <div className="text-xs text-slate-300 font-mono mt-1 truncate" title={assessment.id}>
            {assessment.id}
          </div>
        </div>
      </div>

      {/* Severity Breakdown & Distribution Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Metrics Cards */}
        <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-5 gap-3">
          <div className="p-3.5 rounded-xl border border-purple-500/30 bg-purple-950/20 text-center">
            <span className="text-[11px] font-medium text-purple-300 uppercase">Critical</span>
            <div className="text-2xl font-bold text-purple-400 mt-1">{counts.Critical}</div>
          </div>
          <div className="p-3.5 rounded-xl border border-rose-500/30 bg-rose-950/20 text-center">
            <span className="text-[11px] font-medium text-rose-300 uppercase">High</span>
            <div className="text-2xl font-bold text-rose-400 mt-1">{counts.High}</div>
          </div>
          <div className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-950/20 text-center">
            <span className="text-[11px] font-medium text-amber-300 uppercase">Medium</span>
            <div className="text-2xl font-bold text-amber-400 mt-1">{counts.Medium}</div>
          </div>
          <div className="p-3.5 rounded-xl border border-blue-500/30 bg-blue-950/20 text-center">
            <span className="text-[11px] font-medium text-blue-300 uppercase">Low</span>
            <div className="text-2xl font-bold text-blue-400 mt-1">{counts.Low}</div>
          </div>
          <div className="p-3.5 rounded-xl border border-slate-600 bg-navy-800 text-center col-span-2 sm:col-span-1">
            <span className="text-[11px] font-medium text-slate-400 uppercase">Info</span>
            <div className="text-2xl font-bold text-slate-300 mt-1">{counts.Informational}</div>
          </div>
        </div>

        {/* Severity Chart */}
        <div className="rounded-xl border border-navy-700 bg-navy-800/80 p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-semibold text-slate-300 uppercase">Severity Distribution</span>
            <BarChart2 className="h-4 w-4 text-cyber-blue" />
          </div>
          <div className="h-28 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <YAxis allowDecimals={false} tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-navy-700 pb-3">
        <button
          onClick={() => setActiveTab('matrix')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all flex items-center space-x-2 ${
            activeTab === 'matrix'
              ? 'bg-cyber-blue text-white shadow-md shadow-blue-500/20'
              : 'bg-navy-800 text-slate-400 hover:text-white hover:bg-navy-750'
          }`}
        >
          <Layers className="h-4 w-4" />
          <span>OWASP Top 10:2025 Coverage Matrix</span>
        </button>
        <button
          onClick={() => setActiveTab('findings')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all flex items-center space-x-2 ${
            activeTab === 'findings'
              ? 'bg-cyber-blue text-white shadow-md shadow-blue-500/20'
              : 'bg-navy-800 text-slate-400 hover:text-white hover:bg-navy-750'
          }`}
        >
          <AlertCircle className="h-4 w-4" />
          <span>All Findings ({findings.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('dast')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all flex items-center space-x-2 ${
            activeTab === 'dast'
              ? 'bg-cyan-600 text-white shadow-md shadow-cyan-500/30 ring-1 ring-cyan-400'
              : 'bg-navy-800 text-cyan-300 hover:text-white hover:bg-navy-750 border border-cyan-500/20'
          }`}
        >
          <Radio className="h-4 w-4 text-cyan-400" />
          <span>Dynamic DAST ({dastFindings.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('source_code')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all flex items-center space-x-2 ${
            activeTab === 'source_code'
              ? 'bg-emerald-600 text-white shadow-md shadow-emerald-500/30 ring-1 ring-emerald-400'
              : 'bg-navy-800 text-emerald-300 hover:text-white hover:bg-navy-750 border border-emerald-500/20'
          }`}
        >
          <FileCode className="h-4 w-4 text-emerald-400" />
          <span>Source Code SAST ({sourceCodeFindings.length})</span>
        </button>
      </div>

      {/* TAB 1: OWASP Top 10:2025 Coverage Matrix */}
      {activeTab === 'matrix' && (
        <div className="space-y-4">
          {/* Honest Coverage Standard Callout */}
          <div className="p-4 rounded-xl bg-navy-850/80 border border-navy-700 text-xs text-slate-300 flex items-start space-x-3">
            <Info className="h-4 w-4 text-cyber-sky shrink-0 mt-0.5" />
            <div className="space-y-1">
              <strong className="text-white">Evidence-Based OWASP Coverage Standard:</strong>
              <p className="text-slate-400">
                SentinelSec records coverage status based solely on completed check methods. Zero scanner findings does not mean the application is invulnerable. Categories without executed tests are clearly labeled <strong className="text-slate-300">Not assessed</strong> or <strong className="text-amber-400">Manual review required</strong>.
              </p>
            </div>
          </div>

          {/* Matrix Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {Object.entries(OWASP_CATEGORIES_METADATA).map(([code, meta]) => {
              const row = matrix[code] || {
                status: 'not_assessed',
                findings_count: 0,
                methods_evaluated: [],
                notes: 'No evaluation checks run.',
              };
              const badge = getCoverageBadge(row.status);

              return (
                <div
                  key={code}
                  className="p-4 rounded-xl border border-navy-700 bg-navy-850/60 hover:bg-navy-800/80 transition-all flex flex-col justify-between space-y-3"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-navy-800 text-cyan-300 border border-navy-750">
                          {code}
                        </span>
                        <h4 className="text-sm font-semibold text-white">{meta.name}</h4>
                      </div>
                      <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold border flex items-center space-x-1.5 ${badge.bg}`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${badge.dot}`} />
                        <span>{badge.label}</span>
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{meta.description}</p>
                  </div>

                  <div className="pt-2 border-t border-navy-750/80 flex flex-wrap items-center justify-between text-[11px] gap-2">
                    <div className="flex items-center space-x-1.5 text-slate-400">
                      <span>Evaluated:</span>
                      {row.methods_evaluated && row.methods_evaluated.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {row.methods_evaluated.map((m: string) => {
                            const isDast = m === 'runtime_observations';
                            const isSast = m === 'source_code_analysis';
                            const isSca = m === 'dependency_analysis';
                            return (
                              <span
                                key={m}
                                className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                                  isDast
                                    ? 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
                                    : isSast
                                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40'
                                    : isSca
                                    ? 'bg-amber-950/80 text-amber-300 border-amber-500/40'
                                    : 'bg-navy-800 text-slate-300 border-navy-750'
                                }`}
                              >
                                {isDast
                                  ? 'DAST (Runtime)'
                                  : isSast
                                  ? 'SAST (Code)'
                                  : isSca
                                  ? 'SCA (Deps)'
                                  : m.replace(/_/g, ' ')}
                              </span>
                            );
                          })}
                        </div>
                      ) : (
                        <span className="text-slate-500 italic">None</span>
                      )}
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="text-slate-400">Findings:</span>
                      <strong className={`font-mono ${row.findings_count > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
                        {row.findings_count}
                      </strong>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 2, 3 & 4: Findings Table (All, DAST, or SAST) */}
      {(activeTab === 'findings' || activeTab === 'dast' || activeTab === 'source_code') && (
        <div className="rounded-2xl border border-navy-700 bg-navy-800/80 shadow-xl overflow-hidden backdrop-blur-sm">
          {/* Filter Controls Header */}
          <div className="p-5 border-b border-navy-700 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center space-x-3">
              <h3 className="text-base font-bold text-white flex items-center space-x-2">
                {activeTab === 'dast' && <Radio className="h-4 w-4 text-cyan-400" />}
                {activeTab === 'source_code' && <FileCode className="h-4 w-4 text-emerald-400" />}
                {activeTab === 'findings' && <AlertCircle className="h-4 w-4 text-cyber-sky" />}
                <span>
                  {activeTab === 'dast'
                    ? 'Dynamic DAST Runtime Findings'
                    : activeTab === 'source_code'
                    ? 'Static SAST Source-Code Findings'
                    : 'All Vulnerability Findings'}{' '}
                  ({displayedFindings.length})
                </span>
              </h3>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              {/* Search Box */}
              <div className="relative">
                <Search className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search finding, file, endpoint..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8 pr-3 py-1.5 rounded-lg bg-navy-850 border border-navy-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyber-blue w-56"
                />
              </div>

              {/* Method Filter */}
              <select
                value={methodFilter}
                onChange={(e) => setMethodFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-navy-850 border border-navy-700 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyber-blue"
              >
                <option value="ALL">All Methods</option>
                <option value="runtime_observations">DAST (Runtime Observations)</option>
                <option value="source_code_analysis">SAST (Source Code)</option>
                <option value="dependency_analysis">SCA (Dependencies)</option>
                <option value="configuration_checks">Configuration Checks</option>
              </select>

              {/* Severity Filter */}
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-navy-850 border border-navy-700 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyber-blue"
              >
                <option value="ALL">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
                <option value="Informational">Informational</option>
              </select>

              {/* OWASP Category Filter */}
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="px-3 py-1.5 rounded-lg bg-navy-850 border border-navy-700 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyber-blue"
              >
                <option value="ALL">All OWASP Categories</option>
                {Object.keys(OWASP_CATEGORIES_METADATA).map((code) => (
                  <option key={code} value={code}>
                    {code}: {OWASP_CATEGORIES_METADATA[code].name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Loading State */}
          {loading && (
            <div className="p-8 text-center text-slate-400 space-y-2">
              <Loader2 className="h-6 w-6 animate-spin mx-auto text-cyber-blue" />
              <p className="text-xs">Loading findings...</p>
            </div>
          )}

          {/* Error State */}
          {error && (
            <div className="p-8 text-center text-rose-300">
              <p className="text-xs">{error}</p>
            </div>
          )}

          {/* Empty State */}
          {!loading && !error && displayedFindings.length === 0 && (
            <div className="p-12 text-center text-slate-400">
              <p className="text-sm font-medium text-white">No matching vulnerability findings</p>
              <p className="text-xs text-slate-500 mt-1">Adjust your search query or filters.</p>
            </div>
          )}

          {/* Table */}
          {!loading && !error && displayedFindings.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-navy-850/80 text-[11px] uppercase text-slate-400 border-b border-navy-700">
                  <tr>
                    <th className="px-5 py-3">Severity</th>
                    <th className="px-5 py-3">Finding Title</th>
                    <th className="px-5 py-3">Inspection Target / Location</th>
                    <th className="px-5 py-3">OWASP Category</th>
                    <th className="px-5 py-3">CWE ID</th>
                    <th className="px-5 py-3">Check Method</th>
                    <th className="px-5 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-700/60 font-sans">
                  {displayedFindings.map((f) => {
                    const isDast = f.check_method === 'runtime_observations' || (!f.source_file && f.check_method !== 'dependency_analysis');
                    const isSast = f.check_method === 'source_code_analysis' && !!f.source_file;
                    const isSca = f.check_method === 'dependency_analysis';

                    return (
                      <tr
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className="hover:bg-navy-750/40 cursor-pointer transition-colors"
                      >
                        <td className="px-5 py-3.5 whitespace-nowrap">
                          <span className={`px-2.5 py-0.5 rounded-md text-[11px] font-semibold border ${getSeverityBadgeClass(f.severity)}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="px-5 py-3.5 font-medium text-white max-w-xs truncate">
                          {f.title}
                        </td>
                        <td className="px-5 py-3.5 font-mono text-slate-300 max-w-xs truncate">
                          {isDast ? (
                            <span className="text-cyan-300 font-mono flex items-center space-x-1.5">
                              <span className="px-1.5 py-0.2 rounded text-[9px] bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 font-sans font-bold uppercase tracking-wider">
                                DAST
                              </span>
                              <span className="truncate">{f.affected_endpoint}</span>
                            </span>
                          ) : isSca ? (
                            <span className="text-amber-300 font-mono flex items-center space-x-1.5">
                              <span className="px-1.5 py-0.2 rounded text-[9px] bg-amber-950/80 border border-amber-500/40 text-amber-300 font-sans font-bold uppercase tracking-wider">
                                SCA
                              </span>
                              <span className="truncate">{f.affected_endpoint}</span>
                            </span>
                          ) : (
                            <span className="text-emerald-400 font-mono flex items-center space-x-1.5">
                              <span className="px-1.5 py-0.2 rounded text-[9px] bg-emerald-950/80 border border-emerald-500/40 text-emerald-300 font-sans font-bold uppercase tracking-wider">
                                SAST
                              </span>
                              <span className="truncate">
                                {f.source_file}{f.source_line_start ? `:L${f.source_line_start}` : ''}
                              </span>
                            </span>
                          )}
                        </td>
                        <td className="px-5 py-3.5 whitespace-nowrap">
                          <span className="px-2 py-0.5 rounded bg-navy-850 text-slate-300 border border-navy-700 text-[11px]">
                            {f.owasp_category?.split(':')[0] || 'A00'}
                          </span>
                        </td>
                        <td className="px-5 py-3.5 font-mono text-cyan-400 whitespace-nowrap">
                          {f.cwe_id || '—'}
                        </td>
                        <td className="px-5 py-3.5 whitespace-nowrap">
                          {isDast ? (
                            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 flex items-center space-x-1 w-fit">
                              <Radio className="h-3 w-3 text-cyan-400" />
                              <span>DAST (Runtime)</span>
                            </span>
                          ) : isSast ? (
                            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-950/80 border border-emerald-500/40 text-emerald-300 flex items-center space-x-1 w-fit">
                              <FileCode className="h-3 w-3 text-emerald-400" />
                              <span>SAST (Code)</span>
                            </span>
                          ) : isSca ? (
                            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-amber-950/80 border border-amber-500/40 text-amber-300 w-fit">
                              SCA (Deps)
                            </span>
                          ) : (
                            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-slate-800 border border-slate-700 text-slate-300 w-fit">
                              {f.check_method?.replace(/_/g, ' ') || 'Scanner'}
                            </span>
                          )}
                        </td>
                        <td className="px-5 py-3.5 text-right whitespace-nowrap">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedFinding(f);
                            }}
                            className="px-2.5 py-1 rounded bg-navy-750 hover:bg-navy-700 text-cyber-sky font-medium border border-cyber-blue/30 text-[11px] transition-all"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Detail Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
};
