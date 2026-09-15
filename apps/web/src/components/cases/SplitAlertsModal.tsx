'use client';

import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { casesApi } from '@/lib/api';

interface SplitAlertsModalProps {
  open: boolean;
  caseId: string;
  caseNumber?: string;
  selectedAlertIds: string[];
  onClose: () => void;
  onSplit?: () => void;
}

export function SplitAlertsModal({
  open,
  caseId,
  caseNumber,
  selectedAlertIds,
  onClose,
  onSplit,
}: SplitAlertsModalProps) {
  const [title, setTitle] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setTitle('');
    setError(null);
    setSubmitting(false);
  }, [open]);

  if (!open) return null;

  const handleSplit = async () => {
    if (selectedAlertIds.length === 0) {
      setError('No alerts selected to split.');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const newCase = await casesApi.splitCase(
        caseId,
        selectedAlertIds,
        title.trim() || undefined,
      );
      toast.success(
        `Extracted ${selectedAlertIds.length} alert(s) into new case ${newCase.caseNumber || newCase.id.slice(0, 8)}.`,
      );
      onSplit?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Split failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-purple-500/15 text-purple-400">
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
              </svg>
            </span>
            Split {selectedAlertIds.length} Alert(s) into New Case
          </h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors"
          >
            ✕
          </button>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          The selected {selectedAlertIds.length} alert(s) will be extracted from this case ({caseNumber || caseId.slice(0, 8)})
          and placed into an independent new Case container.
        </p>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
            {error}
          </div>
        )}

        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">
            New Case Title (Optional)
          </label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Auto-generated from original case if left blank"
            className="w-full rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:border-purple-500/50 focus:outline-none"
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
            onClick={handleSplit}
            disabled={submitting}
            className="inline-flex items-center gap-2 rounded-lg bg-purple-600 hover:bg-purple-500 px-4 py-2 text-xs font-semibold text-white transition-colors disabled:opacity-50"
          >
            {submitting && (
              <span className="h-3 w-3 animate-spin rounded-full border border-white/30 border-t-white" />
            )}
            {submitting ? 'Splitting…' : 'Confirm Split'}
          </button>
        </div>
      </div>
    </div>
  );
}
