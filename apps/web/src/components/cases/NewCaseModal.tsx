'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import { casesApi, type CaseSeverity } from '@/lib/api';

interface NewCaseModalProps {
  open: boolean;
  onClose: () => void;
  /** Revalidate the caller's SWR list so the new case appears without a reload. */
  onCreated?: () => void;
}

const SEVERITIES: CaseSeverity[] = ['low', 'medium', 'high', 'critical'];

const SEVERITY_STYLE: Record<CaseSeverity, string> = {
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
};

/** Creates an empty case from scratch (no originating alert). */
export function NewCaseModal({ open, onClose, onCreated }: NewCaseModalProps) {
  const router = useRouter();
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<CaseSeverity>('medium');
  const [assignee, setAssignee] = useState('');
  const [mitre, setMitre] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setTitle('');
    setDescription('');
    setSeverity('medium');
    setAssignee('');
    setMitre('');
    setError(null);
    setSubmitting(false);
  }, [open]);

  if (!open) return null;

  const handleSubmit = async () => {
    if (submitting) return;
    if (title.trim().length < 3) {
      setError('Case title must be at least 3 characters.');
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      const created = await casesApi.create({
        title: title.trim(),
        description: description.trim() || undefined,
        severity,
        assignee: assignee.trim() || undefined,
        mitre: mitre
          .split(',')
          .map((t) => t.trim().toUpperCase())
          .filter(Boolean),
      });
      toast.success(`Created ${created.caseNumber ?? 'case'}`);
      onCreated?.();
      onClose();
      router.push(`/cases/${created.caseNumber ?? created.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the case.');
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Create case"
      onClick={(e) => {
        if (e.target === e.currentTarget && !submitting) onClose();
      }}
      onKeyDown={(e) => {
        if (e.key === 'Escape' && !submitting) onClose();
      }}
    >
      <div className="w-full max-w-lg rounded-xl border border-gray-800 bg-gray-900 shadow-2xl">
        <div className="flex items-center justify-between border-b border-gray-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-gray-100">New case</h2>
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            aria-label="Close"
            className="rounded-lg p-1 text-gray-500 hover:text-gray-200 disabled:opacity-50"
          >
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="space-y-4 px-5 py-4">
          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              {error}
            </div>
          )}

          <label className="block">
            <span className="mb-1.5 block text-xs uppercase tracking-wider text-gray-500">Title</span>
            <input
              autoFocus
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Suspected credential theft on FIN-DB01"
              className="w-full rounded-lg border border-gray-700 bg-gray-800/60 px-3 py-2 text-sm text-gray-100 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
            />
          </label>

          <label className="block">
            <span className="mb-1.5 block text-xs uppercase tracking-wider text-gray-500">
              Description <span className="text-gray-600">(optional)</span>
            </span>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What prompted this case?"
              className="w-full resize-y rounded-lg border border-gray-700 bg-gray-800/60 px-3 py-2 text-sm text-gray-100 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
            />
          </label>

          <div>
            <span className="mb-1.5 block text-xs uppercase tracking-wider text-gray-500">Severity</span>
            <div className="flex flex-wrap gap-2">
              {SEVERITIES.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSeverity(s)}
                  className={clsx(
                    'rounded-lg border px-3 py-1.5 text-xs font-medium capitalize transition-colors',
                    severity === s
                      ? SEVERITY_STYLE[s]
                      : 'border-gray-700 text-gray-500 hover:text-gray-300',
                  )}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <label className="block">
              <span className="mb-1.5 block text-xs uppercase tracking-wider text-gray-500">
                Assignee <span className="text-gray-600">(optional)</span>
              </span>
              <input
                value={assignee}
                onChange={(e) => setAssignee(e.target.value)}
                placeholder="analyst@company.com"
                className="w-full rounded-lg border border-gray-700 bg-gray-800/60 px-3 py-2 text-sm text-gray-100 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="mb-1.5 block text-xs uppercase tracking-wider text-gray-500">
                ATT&amp;CK <span className="text-gray-600">(comma-sep)</span>
              </span>
              <input
                value={mitre}
                onChange={(e) => setMitre(e.target.value)}
                placeholder="T1003, T1110"
                className="w-full rounded-lg border border-gray-700 bg-gray-800/60 px-3 py-2 text-sm text-gray-100 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
              />
            </label>
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-gray-800 px-5 py-4">
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className="rounded-lg px-3 py-2 text-sm text-gray-400 hover:text-gray-200 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={submitting}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60"
          >
            {submitting ? 'Creating…' : 'Create case'}
          </button>
        </div>
      </div>
    </div>
  );
}
