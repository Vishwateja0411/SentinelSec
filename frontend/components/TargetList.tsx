'use client';

import React, { useState } from 'react';
import { Target } from '@/lib/types';
import {
  Globe,
  Terminal,
  CheckCircle2,
  RefreshCw,
  AlertCircle,
  Inbox,
  ChevronLeft,
  ChevronRight,
  Trash2,
  AlertTriangle,
  X,
} from 'lucide-react';

interface TargetListProps {
  targets: Target[];
  total: number;
  skip: number;
  limit: number;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  onPageChange: (newSkip: number) => void;
  onDeleteTarget?: (targetId: string) => Promise<void>;
}

export const TargetList: React.FC<TargetListProps> = ({
  targets,
  total,
  skip,
  limit,
  loading,
  error,
  onRefresh,
  onPageChange,
  onDeleteTarget,
}) => {
  const [targetToDelete, setTargetToDelete] = useState<Target | null>(null);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const currentPage = Math.floor(skip / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const handleConfirmDelete = async () => {
    if (!targetToDelete || !onDeleteTarget) return;
    setIsDeleting(true);
    setDeleteError(null);
    try {
      await onDeleteTarget(targetToDelete.id);
      setTargetToDelete(null);
    } catch (err: any) {
      setDeleteError(err.message || 'Failed to delete target. Please try again.');
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="rounded-xl border border-navy-700 bg-navy-800/80 shadow-xl overflow-hidden backdrop-blur-sm">
      {/* Table Header Controls */}
      <div className="p-5 border-b border-navy-700 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-white">Registered Target Inventory</h2>
          <p className="text-xs text-slate-400">
            Immutable log of authorized targets and server-generated UTC attestation records.
          </p>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="px-3 py-1.5 rounded-lg border border-navy-600 bg-navy-850 hover:bg-navy-750 text-slate-300 hover:text-white text-xs font-medium transition-all flex items-center space-x-1.5 self-start sm:self-auto disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-cyber-blue' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-6 text-center">
          <div className="inline-flex p-3 rounded-full bg-rose-950/60 text-rose-400 border border-rose-500/30 mb-3">
            <AlertCircle className="h-6 w-6" />
          </div>
          <p className="text-sm font-medium text-rose-200">Failed to load target inventory</p>
          <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">{error}</p>
          <button
            onClick={onRefresh}
            className="mt-3 px-3 py-1.5 text-xs font-medium rounded-md bg-navy-750 text-slate-200 hover:text-white border border-navy-600"
          >
            Try Again
          </button>
        </div>
      )}

      {/* Loading state skeleton */}
      {loading && !error && (
        <div className="p-8 space-y-4">
          {[1, 2, 3].map((idx) => (
            <div key={idx} className="h-14 rounded-lg bg-navy-750/50 animate-pulse" />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && targets.length === 0 && (
        <div className="p-12 text-center">
          <div className="inline-flex p-3 rounded-full bg-navy-750 text-slate-400 mb-3">
            <Inbox className="h-6 w-6" />
          </div>
          <p className="text-sm font-medium text-white">No targets registered yet</p>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            Use the registration form above to submit an authorized IP address or web URL.
          </p>
        </div>
      )}

      {/* Data Table */}
      {!loading && !error && targets.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-navy-850/80 text-xs uppercase text-slate-400 border-b border-navy-700">
              <tr>
                <th scope="col" className="px-5 py-3">Type</th>
                <th scope="col" className="px-5 py-3">Target Endpoint</th>
                <th scope="col" className="px-5 py-3">Attestation Record</th>
                <th scope="col" className="px-5 py-3">UTC Registered</th>
                <th scope="col" className="px-5 py-3">Target ID</th>
                <th scope="col" className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-navy-700/60 font-sans">
              {targets.map((target) => (
                <tr key={target.id} className="hover:bg-navy-750/40 transition-colors">
                  {/* Type */}
                  <td className="px-5 py-3.5 whitespace-nowrap">
                    {target.type === 'url' ? (
                      <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-cyan-950/60 text-cyan-300 border border-cyan-500/30">
                        <Globe className="h-3 w-3" />
                        <span>URL</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-indigo-950/60 text-indigo-300 border border-indigo-500/30">
                        <Terminal className="h-3 w-3" />
                        <span>IP</span>
                      </span>
                    )}
                  </td>

                  {/* Target Endpoint */}
                  <td className="px-5 py-3.5 font-mono text-xs text-white max-w-md truncate">
                    {target.target}
                  </td>

                  {/* Authorization Status */}
                  <td className="px-5 py-3.5 whitespace-nowrap">
                    {target.authorization_attestation ? (
                      <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-emerald-950/60 text-emerald-300 border border-emerald-500/30">
                        <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                        <span>Authorized & Attested</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-rose-900/50 text-rose-300">
                        Unconfirmed
                      </span>
                    )}
                  </td>

                  {/* Timestamp */}
                  <td className="px-5 py-3.5 whitespace-nowrap text-xs text-slate-300 font-mono">
                    {new Date(target.created_at).toUTCString()}
                  </td>

                  {/* Target ID */}
                  <td className="px-5 py-3.5 whitespace-nowrap font-mono text-xs text-slate-400">
                    <span title={target.id} className="bg-navy-850 px-2 py-1 rounded border border-navy-700">
                      {target.id.substring(0, 8)}...
                    </span>
                  </td>

                  {/* Actions / Delete Button */}
                  <td className="px-5 py-3.5 whitespace-nowrap text-right">
                    <button
                      onClick={() => setTargetToDelete(target)}
                      className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 hover:text-rose-100 border border-rose-500/30 transition-all shadow-sm hover:shadow-rose-900/20 group"
                      title={`Delete target ${target.target}`}
                    >
                      <Trash2 className="h-3 w-3 text-rose-400 group-hover:scale-110 transition-transform" />
                      <span>Delete</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination Footer */}
      {!loading && !error && total > 0 && (
        <div className="p-4 border-t border-navy-700 bg-navy-850/50 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
          <div>
            Showing <span className="font-semibold text-slate-200">{targets.length}</span> of{' '}
            <span className="font-semibold text-slate-200">{total}</span> total records (Page{' '}
            <span className="font-semibold text-slate-200">{currentPage}</span> of{' '}
            <span className="font-semibold text-slate-200">{totalPages}</span>)
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => onPageChange(Math.max(0, skip - limit))}
              disabled={skip === 0}
              className="p-1.5 rounded-md border border-navy-600 bg-navy-800 hover:bg-navy-700 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              onClick={() => onPageChange(skip + limit)}
              disabled={skip + limit >= total}
              className="p-1.5 rounded-md border border-navy-600 bg-navy-800 hover:bg-navy-700 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {targetToDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-md animate-fade-in">
          <div className="w-full max-w-md rounded-2xl border border-navy-700 bg-navy-900 p-6 shadow-2xl space-y-4">
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-3">
                <div className="p-2.5 rounded-xl bg-rose-950/60 border border-rose-500/30 text-rose-400">
                  <AlertTriangle className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white">Delete Authorized Target</h3>
                  <p className="text-xs text-slate-400">This action will permanently remove this target.</p>
                </div>
              </div>
              <button
                onClick={() => {
                  setTargetToDelete(null);
                  setDeleteError(null);
                }}
                disabled={isDeleting}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-navy-800 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-navy-850/80 border border-navy-750 space-y-2 text-xs">
              <div>
                <span className="text-slate-400">Target Endpoint:</span>
                <p className="font-mono text-white font-semibold break-all mt-0.5">{targetToDelete.target}</p>
              </div>
              <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                <span>Type: <strong className="text-slate-200">{targetToDelete.type.toUpperCase()}</strong></span>
                <span>ID: {targetToDelete.id.slice(0, 12)}...</span>
              </div>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Deleting this target will also cascade and remove any associated assessment runs and technical findings.
            </p>

            {deleteError && (
              <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-500/30 text-rose-300 text-xs flex items-center space-x-2">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{deleteError}</span>
              </div>
            )}

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={() => {
                  setTargetToDelete(null);
                  setDeleteError(null);
                }}
                disabled={isDeleting}
                className="px-3.5 py-2 rounded-xl text-xs font-medium text-slate-300 hover:text-white bg-navy-800 hover:bg-navy-750 border border-navy-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmDelete}
                disabled={isDeleting}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 transition-all shadow-lg shadow-rose-900/30 flex items-center space-x-2 disabled:opacity-50"
              >
                {isDeleting ? (
                  <>
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    <span>Deleting...</span>
                  </>
                ) : (
                  <>
                    <Trash2 className="h-3.5 w-3.5" />
                    <span>Delete Target</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
