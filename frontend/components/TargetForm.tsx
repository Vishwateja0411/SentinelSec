'use client';

import React, { useState } from 'react';
import { Globe, Terminal, ShieldAlert, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';
import { registerTarget } from '@/lib/api';
import { Target, TargetType } from '@/lib/types';

interface TargetFormProps {
  onTargetCreated: (target: Target) => void;
}

export const TargetForm: React.FC<TargetFormProps> = ({ onTargetCreated }) => {
  const [targetType, setTargetType] = useState<TargetType>('url');
  const [targetValue, setTargetValue] = useState<string>('');
  const [attestation, setAttestation] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [inlineError, setInlineError] = useState<string | null>(null);
  const [successTarget, setSuccessTarget] = useState<Target | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setInlineError(null);
    setSuccessTarget(null);

    // Client-side pre-validations
    const cleanTarget = targetValue.trim();
    if (!cleanTarget) {
      setInlineError('Please enter a target address.');
      return;
    }

    if (!attestation) {
      setInlineError('You must explicitly confirm and check the authorization attestation before registering a target.');
      return;
    }

    if (targetType === 'url') {
      if (!cleanTarget.startsWith('http://') && !cleanTarget.startsWith('https://')) {
        setInlineError('Target URL must begin with http:// or https://');
        return;
      }
      if (cleanTarget.includes('@')) {
        setInlineError('Embedded credentials (user:pass@host) are prohibited in target URLs.');
        return;
      }
    }

    setLoading(true);
    try {
      const created = await registerTarget({
        target: cleanTarget,
        type: targetType,
        authorization_attestation: attestation,
      });

      setSuccessTarget(created);
      setTargetValue('');
      setAttestation(false); // Reset attestation checkbox back to unchecked
      onTargetCreated(created);
    } catch (err: any) {
      setInlineError(err.message || 'Failed to register target. Please check the target format.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-xl border border-navy-700 bg-navy-800/80 p-6 shadow-xl backdrop-blur-sm">
      <div className="flex items-center space-x-3 pb-4 border-b border-navy-700">
        <div className="p-2 rounded-lg bg-cyber-blue/10 text-cyber-sky border border-cyber-blue/30">
          <ShieldAlert className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-base font-semibold text-white">Target Registration & Authorization Record</h2>
          <p className="text-xs text-slate-400">
            All submitted targets are stored as inert records. Explicit authorization confirmation is legally required.
          </p>
        </div>
      </div>

      {/* Success Notification */}
      {successTarget && (
        <div className="mt-4 p-4 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-200 flex items-start space-x-3">
          <CheckCircle className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-emerald-300">Target Registered Successfully!</p>
            <p className="text-xs text-emerald-200/80 mt-1">
              Record ID: <span className="font-mono text-white">{successTarget.id}</span>
            </p>
            <p className="text-xs text-emerald-200/80">
              UTC Attestation Timestamp: <span className="font-mono text-white">{new Date(successTarget.attestation_timestamp).toUTCString()}</span>
            </p>
          </div>
        </div>
      )}

      {/* Error Notification */}
      {inlineError && (
        <div className="mt-4 p-4 rounded-lg bg-rose-950/60 border border-rose-500/40 text-rose-200 flex items-start space-x-3">
          <AlertCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-rose-300">Validation Error</p>
            <p className="text-xs text-rose-200/90 mt-0.5">{inlineError}</p>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="mt-5 space-y-5">
        {/* Type Selector */}
        <div>
          <label className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-2">
            Target Type
          </label>
          <div className="grid grid-cols-2 gap-3 max-w-md">
            <button
              type="button"
              onClick={() => {
                setTargetType('url');
                setInlineError(null);
              }}
              className={`flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg border text-sm font-medium transition-all ${
                targetType === 'url'
                  ? 'bg-cyber-blue/15 border-cyber-blue text-cyber-sky shadow-sm'
                  : 'bg-navy-850 border-navy-700 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Globe className="h-4 w-4" />
              <span>Web URL</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setTargetType('ip');
                setInlineError(null);
              }}
              className={`flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg border text-sm font-medium transition-all ${
                targetType === 'ip'
                  ? 'bg-cyber-blue/15 border-cyber-blue text-cyber-sky shadow-sm'
                  : 'bg-navy-850 border-navy-700 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Terminal className="h-4 w-4" />
              <span>IP Address</span>
            </button>
          </div>
        </div>

        {/* Target Input */}
        <div>
          <label htmlFor="target-input" className="block text-xs font-medium text-slate-300 uppercase tracking-wider mb-2">
            {targetType === 'url' ? 'Target URL (HTTP or HTTPS)' : 'Target IP Address (IPv4 or IPv6)'}
          </label>
          <input
            id="target-input"
            type="text"
            value={targetValue}
            onChange={(e) => setTargetValue(e.target.value)}
            placeholder={
              targetType === 'url'
                ? 'https://example.com/app or http://192.168.1.50:8080'
                : '192.168.1.100 or 2001:db8::1'
            }
            className="w-full px-4 py-2.5 rounded-lg bg-navy-850 border border-navy-700 text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyber-blue focus:border-transparent text-sm font-mono"
            required
          />
          <p className="mt-1.5 text-xs text-slate-400">
            {targetType === 'url'
              ? 'Must be a valid HTTP or HTTPS URI. Embedded user credentials (@) are rejected.'
              : 'Must be a valid IPv4 or IPv6 address. Domain hostnames are not accepted for type IP.'}
          </p>
        </div>

        {/* Authorization Attestation Checkbox (Unchecked by default) */}
        <div className="rounded-lg border border-navy-700 bg-navy-850/90 p-4">
          <label className="flex items-start space-x-3 cursor-pointer">
            <input
              type="checkbox"
              id="authorization-attestation"
              checked={attestation}
              onChange={(e) => setAttestation(e.target.checked)}
              className="mt-1 h-4 w-4 rounded border-navy-600 bg-navy-900 text-cyber-blue focus:ring-cyber-blue focus:ring-offset-navy-900 cursor-pointer"
              required
            />
            <div className="text-xs leading-relaxed text-slate-200 select-none">
              <span className="font-semibold text-cyber-sky">Required Affirmative Authorization Attestation:</span>{' '}
              I explicitly attest and confirm under legal authority that I own this target system or possess documented, 
              written authorization from the legitimate system owner to register this asset for defensive assessment 
              management. I understand this action and timestamp will be permanently logged.
            </div>
          </label>
        </div>

        {/* Submit Button */}
        <div className="flex items-center justify-end space-x-4 pt-2">
          <button
            type="submit"
            disabled={loading}
            className="px-5 py-2.5 rounded-lg bg-cyber-blue hover:bg-blue-600 active:bg-blue-700 text-white text-sm font-medium shadow-lg shadow-blue-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center space-x-2"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Validating & Recording...</span>
              </>
            ) : (
              <span>Confirm & Register Target</span>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
