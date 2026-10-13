'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { Navbar } from '@/components/Navbar';
import { OverviewStats } from '@/components/OverviewStats';
import { TargetForm } from '@/components/TargetForm';
import { TargetList } from '@/components/TargetList';
import { AssessmentList } from '@/components/AssessmentList';
import { ScanResultsView } from '@/components/ScanResultsView';
import { AssessmentCreateModal } from '@/components/AssessmentCreateModal';
import { fetchHealth, fetchTargets, fetchAssessments } from '@/lib/api';
import { HealthResponse, Target, Assessment } from '@/lib/types';
import { AlertCircle, RefreshCw } from 'lucide-react';

export default function Home() {
  const [currentTab, setCurrentTab] = useState<'overview' | 'targets' | 'assessments'>('overview');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);

  // Targets state
  const [targets, setTargets] = useState<Target[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [skip, setSkip] = useState<number>(0);
  const [limit] = useState<number>(20);
  const [targetsLoading, setTargetsLoading] = useState<boolean>(true);
  const [targetsError, setTargetsError] = useState<string | null>(null);

  // Assessments state
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [assessmentsLoading, setAssessmentsLoading] = useState<boolean>(false);
  const [selectedAssessment, setSelectedAssessment] = useState<Assessment | null>(null);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState<boolean>(false);

  const loadHealth = useCallback(async () => {
    setHealthLoading(true);
    try {
      const data = await fetchHealth();
      setHealth(data);
    } catch (err: any) {
      console.warn('Backend health check error:', err);
      setHealth(null);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  const loadTargets = useCallback(async (currentSkip: number) => {
    setTargetsLoading(true);
    setTargetsError(null);
    try {
      const data = await fetchTargets(currentSkip, limit);
      setTargets(data.items);
      setTotal(data.total);
    } catch (err: any) {
      setTargetsError(
        err.message || 'Could not connect to SentinelSec API. Ensure backend service is running on port 8000.'
      );
    } finally {
      setTargetsLoading(false);
    }
  }, [limit]);

  const loadAssessments = useCallback(async () => {
    setAssessmentsLoading(true);
    try {
      const data = await fetchAssessments(0, 50);
      setAssessments(data.items);
    } catch (err: any) {
      console.warn('Failed to load assessments:', err);
    } finally {
      setAssessmentsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHealth();
    loadTargets(skip);
    loadAssessments();
  }, [loadHealth, loadTargets, loadAssessments, skip]);

  const handleTargetCreated = (newTarget: Target) => {
    setTargets((prev) => [newTarget, ...prev]);
    setTotal((prev) => prev + 1);
  };

  const handleAssessmentCreated = (newAssessment: Assessment) => {
    setAssessments((prev) => [newAssessment, ...prev]);
    setSelectedAssessment(newAssessment);
    setCurrentTab('assessments');
  };

  return (
    <div className="min-h-screen flex flex-col bg-navy-900 text-slate-100">
      <Navbar
        currentTab={currentTab}
        setCurrentTab={(tab) => {
          setCurrentTab(tab);
          if (tab !== 'assessments') {
            setSelectedAssessment(null);
          }
        }}
        health={health}
        healthLoading={healthLoading}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* API Offline Banner */}
        {!healthLoading && !health && (
          <div className="rounded-lg border border-amber-500/40 bg-amber-950/40 p-4 text-amber-200 flex items-start justify-between gap-3">
            <div className="flex items-start space-x-3">
              <AlertCircle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
              <div className="text-sm">
                <span className="font-semibold text-white">Backend API Offline:</span> SentinelSec FastAPI server is currently unreachable at http://localhost:8000. Start the backend using{' '}
                <code className="bg-navy-950 px-1.5 py-0.5 rounded text-amber-300 font-mono text-xs">
                  docker compose up
                </code>{' '}
                or{' '}
                <code className="bg-navy-950 px-1.5 py-0.5 rounded text-amber-300 font-mono text-xs">
                  .\.venv\Scripts\python -m uvicorn backend.app.main:app --port 8000
                </code>.
              </div>
            </div>
            <button
              onClick={() => {
                loadHealth();
                loadTargets(skip);
                loadAssessments();
              }}
              className="px-3 py-1 text-xs font-medium rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 shrink-0 flex items-center space-x-1"
            >
              <RefreshCw className="h-3 w-3" />
              <span>Retry</span>
            </button>
          </div>
        )}

        {/* Port Conflict Banner */}
        {!healthLoading && health && !health.version && (
          <div className="rounded-lg border border-rose-500/50 bg-rose-950/50 p-4 text-rose-200 flex items-start justify-between gap-3">
            <div className="flex items-start space-x-3">
              <AlertCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
              <div className="text-sm">
                <span className="font-semibold text-white">Port 8000 Conflict:</span> A different service ({health.app || 'Unrecognized Application'}) is running on port 8000. SentinelSec's backend is not connected. Stop the other service with{' '}
                <code className="bg-navy-950 px-1.5 py-0.5 rounded text-rose-300 font-mono text-xs">
                  docker stop secureshop-backend
                </code>{' '}
                then launch SentinelSec.
              </div>
            </div>
            <button
              onClick={() => {
                loadHealth();
                loadTargets(skip);
                loadAssessments();
              }}
              className="px-3 py-1 text-xs font-medium rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 shrink-0 flex items-center space-x-1"
            >
              <RefreshCw className="h-3 w-3" />
              <span>Refresh</span>
            </button>
          </div>
        )}

        {/* Tab Views */}
        {currentTab === 'overview' && (
          <OverviewStats
            targets={targets}
            totalTargets={total}
            health={health}
            onNavigateToTargets={() => setCurrentTab('targets')}
          />
        )}

        {currentTab === 'targets' && (
          <div className="space-y-8">
            <TargetForm onTargetCreated={handleTargetCreated} />
            <TargetList
              targets={targets}
              total={total}
              skip={skip}
              limit={limit}
              loading={targetsLoading}
              error={targetsError}
              onRefresh={() => loadTargets(skip)}
              onPageChange={(newSkip) => setSkip(newSkip)}
            />
          </div>
        )}

        {currentTab === 'assessments' && (
          <div>
            {selectedAssessment ? (
              <ScanResultsView
                assessment={selectedAssessment}
                onBack={() => {
                  setSelectedAssessment(null);
                  loadAssessments();
                }}
              />
            ) : (
              <AssessmentList
                assessments={assessments}
                loading={assessmentsLoading}
                onRefresh={loadAssessments}
                onSelectAssessment={(a) => setSelectedAssessment(a)}
                onOpenCreateModal={() => setIsCreateModalOpen(true)}
              />
            )}
          </div>
        )}

        {/* Create Assessment Modal */}
        <AssessmentCreateModal
          targets={targets}
          isOpen={isCreateModalOpen}
          onClose={() => setIsCreateModalOpen(false)}
          onAssessmentCreated={handleAssessmentCreated}
        />
      </main>

      {/* Footer */}
      <footer className="border-t border-navy-800 bg-navy-950 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>SentinelSec Platform &copy; 2026 — Defensive Security Governance</span>
          <span>Authorized Security Assessment Workflow & Reporting</span>
        </div>
      </footer>
    </div>
  );
}
