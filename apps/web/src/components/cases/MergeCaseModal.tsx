'use client';

import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { casesApi } from '@/lib/api';

interface MergeCaseModalProps {
  open: boolean;
  targetCaseId: string;
  targetCaseNumber?: string;
  onClose: () => void;
  onMerged?: () => void;
}

export function MergeCaseModal({
  open,
  targetCaseId,
  targetCaseNumber,
  onClose,
  onMerged,
}: MergeCaseModalProps) {
  const [sourceCaseInput, setSourceCaseInput] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setSourceCaseInput('');
    setError(null);
    setSubmitting(false);
  }, [open]);

  if (!open) return null;

  const handleMerge = async () => {
    const trimmed = sourceCaseInput.trim();
    if (!trimmed) {
      setError('Please provide a source case number or UUID.');
      return;
    }
    if (
      trimmed.toLowerCase() === targetCaseId.toLowerCase() ||
      (targetCaseNumber && trimmed.toLowerCase() === targetCaseNumber.toLowerCase())
    ) {
      setError('Cannot merge a case into itself.');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      await casesApi.mergeCase(targetCaseId, trimmed);
      toast.success(`Successfully merged case into this case.`);
      onMerged?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Merge failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-500/15 text-cyan-400">
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
            </span>
            Merge Another Case into {targetCaseNumber || targetCaseId.slice(0, 8)}
          </h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors"
          >
            ✕
          </button>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          Merging will transfer all alerts, evidence, and MITRE techniques from the source case into this case.
          The case severity will be elevated if the source case had higher severity. The source case will be closed.
        </p>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
            {error}
          </div>
        )}

        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">
            Source Case ID or Number <span className="text-red-400">*</span>
          </label>
          <input
            type="text"
            value={sourceCaseInput}
            onChange={(e) => setSourceCaseInput(e.target.value)}
            placeholder="e.g. CASE-A1B2C3D4 or 550e8400-e29b-41d4-a716-446655440000"
            className="w-full rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-cyan-500/50 focus:outline-none font-mono"
            autoFocus
          />
        </div>

        <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleMerge}
            disabled={submitting}
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-4 py-2 text-xs font-semibold text-white transition-colors disabled:opacity-50"
          >
            {submitting && (
              <span className="h-3 w-3 animate-spin rounded-full border border-white/30 border-t-white" />
            )}
            {submitting ? 'Merging…' : 'Confirm Merge'}
          </button>
        </div>
      </div>
    </div>
  );
}
