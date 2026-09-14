'use client';

import { useMemo, useState } from 'react';
import clsx from 'clsx';
import {
  TACTICS,
  TACTIC_BY_ID,
  OTHER_TACTIC,
  tacticsFor,
  type Tactic,
} from '@/lib/mitreTactics';

interface AlertLike {
  id?: string;
  title?: string;
  mitre_techniques?: unknown;
  mitreTechniques?: unknown;
  mitre?: unknown;
}

interface CaseMitreHeatmapProps {
  caseMitre?: string[];
  alerts?: AlertLike[];
  className?: string;
}

type StageCategory = 'early' | 'intrusion' | 'objective';

function getTacticCategory(tacticId: string): StageCategory {
  switch (tacticId) {
    case 'TA0043': // Reconnaissance
    case 'TA0042': // Resource Development
    case 'TA0001': // Initial Access
      return 'early';
    case 'TA0002': // Execution
    case 'TA0003': // Persistence
    case 'TA0004': // Privilege Escalation
    case 'TA0005': // Defense Evasion
    case 'TA0006': // Credential Access
    case 'TA0007': // Discovery
      return 'intrusion';
    case 'TA0008': // Lateral Movement
    case 'TA0009': // Collection
    case 'TA0011': // Command and Control
    case 'TA0010': // Exfiltration
    case 'TA0040': // Impact
      return 'objective';
    default:
      return 'intrusion';
  }
}

const CATEGORY_STYLES: Record<StageCategory, { label: string; badge: string; glow: string }> = {
  early: {
    label: 'Early Stage',
    badge: 'bg-sky-500/10 text-sky-400 border-sky-500/30',
    glow: 'from-sky-500/20 to-blue-500/10',
  },
  intrusion: {
    label: 'Intrusion & Control',
    badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    glow: 'from-amber-500/20 to-orange-500/10',
  },
  objective: {
    label: 'Lateral & Objective',
    badge: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    glow: 'from-rose-500/20 to-red-500/10',
  },
};

export function CaseMitreHeatmap({
  caseMitre = [],
  alerts = [],
  className,
}: CaseMitreHeatmapProps) {
  const [showAllTactics, setShowAllTactics] = useState(false);
  const [focusedTacticId, setFocusedTacticId] = useState<string | null>(null);

  // Aggregate all unique MITRE techniques from case and linked alerts
  const { allTechniques, tacticBuckets, activeTacticsCount } = useMemo(() => {
    const techSet = new Set<string>();
    const safeCaseMitre = Array.isArray(caseMitre) ? caseMitre : [];
    const safeAlerts = Array.isArray(alerts) ? alerts : [];

    // From case directly
    for (const t of safeCaseMitre) {
      if (t && typeof t === 'string') techSet.add(t.trim());
    }

    // From linked alerts
    for (const alert of safeAlerts) {
      if (!alert) continue;
      const raw = alert.mitre_techniques ?? alert.mitreTechniques ?? alert.mitre;
      if (Array.isArray(raw)) {
        for (const item of raw) {
          if (typeof item === 'string' && item.trim()) {
            techSet.add(item.trim());
          } else if (item && typeof item === 'object') {
            const obj = item as Record<string, unknown>;
            const tid = String(obj.technique_id ?? obj.id ?? obj.techniqueId ?? '');
            if (tid) techSet.add(tid.trim());
          }
        }
      }
    }

    const allTech = Array.from(techSet).sort();

    // Map techniques into tactics
    const buckets: Record<string, Set<string>> = {};
    for (const t of TACTICS) {
      buckets[t.id] = new Set();
    }
    buckets[OTHER_TACTIC.id] = new Set();

    for (const tech of allTech) {
      const tIds = tacticsFor(tech);
      for (const tid of tIds) {
        if (!buckets[tid]) buckets[tid] = new Set();
        buckets[tid].add(tech);
      }
    }

    let activeCount = 0;
    for (const t of TACTICS) {
      if ((buckets[t.id]?.size ?? 0) > 0) activeCount++;
    }

    return {
      allTechniques: allTech,
      tacticBuckets: buckets,
      activeTacticsCount: activeCount,
    };
  }, [caseMitre, alerts]);

  // Determine span: first active tactic to last active tactic in kill chain
  const killChainSpan = useMemo(() => {
    const activeIndices = TACTICS.map((t, idx) => ({
      tactic: t,
      idx,
      count: tacticBuckets[t.id]?.size ?? 0,
    })).filter((item) => item.count > 0);

    if (activeIndices.length === 0) return null;
    const first = activeIndices[0].tactic;
    const last = activeIndices[activeIndices.length - 1].tactic;
    return {
      first,
      last,
      spanCount: activeIndices.length,
      percentage: Math.round((activeIndices.length / TACTICS.length) * 100),
    };
  }, [tacticBuckets]);

  const displayedTactics = useMemo(() => {
    if (showAllTactics) {
      return TACTICS;
    }
    const filtered = TACTICS.filter((t) => (tacticBuckets[t.id]?.size ?? 0) > 0);
    if ((tacticBuckets[OTHER_TACTIC.id]?.size ?? 0) > 0) {
      filtered.push(OTHER_TACTIC);
    }
    return filtered;
  }, [showAllTactics, tacticBuckets]);

  if (allTechniques.length === 0) {
    return (
      <div className={clsx('rounded-xl border border-slate-800/80 bg-slate-900/40 p-5', className)}>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <span className="flex h-6 w-6 items-center justify-center rounded bg-orange-500/10 text-orange-400 font-mono text-xs font-bold">
              M
            </span>
            <h4 className="text-sm font-semibold text-slate-200">MITRE ATT&CK Framework</h4>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">0 techniques mapped</span>
        </div>
        <p className="text-xs text-slate-400">
          No MITRE ATT&CK techniques have been mapped to this case or its linked alerts yet.
          Techniques are populated automatically when detection rules and enriched events are correlated.
        </p>
      </div>
    );
  }

  return (
    <div className={clsx('rounded-xl border border-slate-800/80 bg-slate-900/50 p-5 space-y-5', className)}>
      {/* Header & Kill-Chain Span Metric */}
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800/70 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-6 w-6 items-center justify-center rounded-md bg-orange-500/15 text-orange-400 font-mono text-xs font-bold">
              M
            </span>
            <h4 className="text-sm font-semibold text-white tracking-wide">
              MITRE ATT&CK Kill-Chain Progression
            </h4>
            <span className="rounded-full border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-[11px] font-mono font-medium text-orange-300">
              {allTechniques.length} {allTechniques.length === 1 ? 'technique' : 'techniques'}
            </span>
          </div>

          {killChainSpan && (
            <p className="mt-1.5 text-xs text-slate-300 flex items-center gap-1.5 flex-wrap">
              <span className="text-slate-400">Progression Span:</span>
              <span className="font-medium text-amber-300">{killChainSpan.first.shortName}</span>
              <span className="text-slate-500">&rarr;</span>
              <span className="font-medium text-rose-300">{killChainSpan.last.shortName}</span>
              <span className="text-slate-500">·</span>
              <span className="text-slate-400">
                {killChainSpan.spanCount} of {TACTICS.length} tactics ({killChainSpan.percentage}% of kill chain)
              </span>
            </p>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowAllTactics((prev) => !prev)}
            className="rounded-lg border border-slate-700/80 bg-slate-800/60 px-2.5 py-1 text-xs font-medium text-slate-300 hover:bg-slate-700/60 hover:text-white transition-all"
          >
            {showAllTactics ? 'Show Active Only' : 'Show All 14 Tactics'}
          </button>
        </div>
      </div>

      {/* Kill-Chain Progression Ribbon (Horizontal Stepper) */}
      <div>
        <div className="text-[10px] uppercase font-semibold tracking-wider text-slate-400 mb-2 flex items-center justify-between">
          <span>Kill-Chain Trajectory</span>
          <span className="text-slate-500 lowercase">Click tactic to focus</span>
        </div>

        <div className="overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-slate-700">
          <div className="flex items-center gap-1 min-w-[760px]">
            {TACTICS.map((tactic, idx) => {
              const count = tacticBuckets[tactic.id]?.size ?? 0;
              const isActive = count > 0;
              const isFocused = focusedTacticId === tactic.id;
              const category = getTacticCategory(tactic.id);
              const styles = CATEGORY_STYLES[category];

              return (
                <div key={tactic.id} className="flex items-center">
                  <button
                    type="button"
                    onClick={() => setFocusedTacticId(isFocused ? null : tactic.id)}
                    className={clsx(
                      'group relative flex flex-col items-center rounded-lg border px-2.5 py-2 text-center transition-all cursor-pointer min-w-[62px]',
                      isFocused
                        ? 'ring-2 ring-orange-500 border-orange-500 bg-orange-950/40'
                        : isActive
                        ? 'border-slate-700/80 bg-slate-800/70 hover:border-slate-600 hover:bg-slate-800'
                        : 'border-slate-800/40 bg-slate-900/30 opacity-45 hover:opacity-75',
                    )}
                    title={`${tactic.name} (${tactic.id}) — ${count} technique(s)`}
                  >
                    <div className="flex items-center gap-1">
                      <span
                        className={clsx(
                          'h-1.5 w-1.5 rounded-full',
                          isActive ? (category === 'objective' ? 'bg-rose-400 animate-pulse' : 'bg-amber-400') : 'bg-slate-600',
                        )}
                      />
                      <span
                        className={clsx(
                          'text-[9px] font-mono font-bold',
                          isActive ? 'text-slate-200' : 'text-slate-500',
                        )}
                      >
                        {count > 0 ? count : '—'}
                      </span>
                    </div>
                    <span
                      className={clsx(
                        'mt-1 text-[10px] font-medium leading-tight line-clamp-1',
                        isActive ? 'text-slate-100 font-semibold' : 'text-slate-500',
                      )}
                    >
                      {tactic.shortName}
                    </span>
                  </button>

                  {idx < TACTICS.length - 1 && (
                    <span className="mx-0.5 text-[10px] text-slate-700 select-none">&rarr;</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Tactic Cards Heatmap Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {displayedTactics.map((tactic) => {
          const techniques = Array.from(tacticBuckets[tactic.id] ?? []).sort();
          const count = techniques.length;
          const isActive = count > 0;
          const isFocused = focusedTacticId === tactic.id;
          const category = getTacticCategory(tactic.id);
          const catStyle = CATEGORY_STYLES[category];

          if (!isActive && !showAllTactics) return null;

          return (
            <div
              key={tactic.id}
              className={clsx(
                'rounded-xl border p-3.5 transition-all flex flex-col justify-between',
                isFocused
                  ? 'border-orange-500 bg-orange-950/20 ring-1 ring-orange-500/40 shadow-lg shadow-orange-950/30'
                  : isActive
                  ? 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                  : 'border-slate-800/40 bg-slate-900/20 opacity-50',
              )}
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div>
                    <div className="flex items-center gap-1.5">
                      <span className={clsx('text-[9px] font-semibold uppercase px-1.5 py-0.2 rounded border', catStyle.badge)}>
                        {catStyle.label}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">{tactic.id}</span>
                    </div>
                    <h5 className="text-xs font-bold text-slate-100 mt-1">
                      {tactic.name}
                    </h5>
                  </div>
                  <span
                    className={clsx(
                      'rounded-full px-2 py-0.5 text-[10px] font-mono font-semibold shrink-0',
                      isActive ? 'bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/30' : 'bg-slate-800 text-slate-500',
                    )}
                  >
                    {count}
                  </span>
                </div>

                {techniques.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5 mt-2.5">
                    {techniques.map((tid) => (
                      <a
                        key={tid}
                        href={`https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 rounded-md border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-[10px] font-mono font-medium text-orange-200 transition-all hover:bg-orange-500/25 hover:border-orange-500/50"
                        title={`View MITRE ATT&CK technique ${tid}`}
                      >
                        <span>{tid}</span>
                        <span className="text-[8px] text-orange-400/70 select-none">↗</span>
                      </a>
                    ))}
                  </div>
                ) : (
                  <p className="mt-2 text-[11px] text-slate-600 italic">No techniques detected</p>
                )}
              </div>

              <div className="mt-3 pt-2 border-t border-slate-800/40 flex items-center justify-between text-[10px] text-slate-500">
                <a
                  href={`https://attack.mitre.org/tactics/${tactic.id}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  MITRE Docs &rarr;
                </a>
                {isActive && (
                  <span className="text-emerald-400 font-medium">Covered</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
