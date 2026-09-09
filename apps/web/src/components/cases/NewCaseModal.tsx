'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import toast from 'react-hot-toast';
import { casesApi, type CaseSeverity } from '@/lib/api';

interface NewCaseModalProps {
  open: boolean;
  onClose: () => void;
  /** Called after a successful create so the list view can revalidate. */
  onCreated: () => void;
}

/**
 * Standalone "New Case" wizard for the Cases page (manual investigation
 * start, not seeded from an alert — see CreateCaseModal in
 * components/alerts for the alert-promotion flow). The backend
 * `POST /api/v1/cases` has always supported this; only the UI entry point
 * was missing.
 */
export function NewCaseModal({ open, onClose, onCreated }: NewCaseModalProps) {
  const router = useRouter();
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<CaseSeverity>('medium');
  const [submitting, setSubmitting] = useState(false);

  if (!open) return null;

  const reset = () => {
    setTitle('');
    setDescription('');
    setSeverity('medium');
  };

  const handleClose = () => {
    if (submitting) return;
    reset();
    onClose();
  };

  const handleSubmit = async () => {
    if (submitting) return;
    if (title.trim().length < 3) {
      toast.error('Case title must be at least 3 characters.');
      return;
    }
    setSubmitting(true);
    try {
      const created = await casesApi.create({
        title: title.trim(),
        description: description.trim() || undefined,
        severity,
      });
      toast.success(`Created ${created.caseNumber ?? 'case'}`);
      reset();
      onCreated();
      onClose();
      router.push(`/cases/${encodeURIComponent(created.caseNumber ?? created.id)}`);
    } catch {
      toast.error('Could not create the case. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Create new case"
      onClick={handleClose}
    >
      <div
        className="w-full max-w-lg rounded-xl border border-gray-800 bg-gray-900 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-gray-800 px-5 py-4">
          <h2 className="text-base font-semibold text-white">New case</h2>
          <button
            type="button"
            onClick={handleClose}
            className="text-gray-400 hover:text-white"
            aria-label="Close"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="space-y-4 px-5 py-4">
          <div>
            <label htmlFor="new-case-title" className="mb-1 block text-xs font-medium text-gray-400">
              Title
            </label>
            <input
              id="new-case-title"
              type="text"
              autoFocus
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              placeholder="Short case title"
            />
          </div>
          <div>
            <label htmlFor="new-case-description" className="mb-1 block text-xs font-medium text-gray-400">
              Description <span className="text-gray-600">(optional)</span>
            </label>
            <textarea
              id="new-case-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full resize-none rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              placeholder="What are you investigating?"
            />
          </div>
          <div>
            <label htmlFor="new-case-severity" className="mb-1 block text-xs font-medium text-gray-400">
              Severity
            </label>
            <select
              id="new-case-severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value as CaseSeverity)}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-gray-800 px-5 py-4">
          <button
            type="button"
            onClick={handleClose}
            className="rounded-lg px-4 py-2 text-sm font-medium text-gray-300 hover:text-white"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={submitting}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting ? 'Creating…' : 'Create case'}
          </button>
        </div>
      </div>
    </div>
  );
}
