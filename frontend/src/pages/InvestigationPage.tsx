import { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Download,
  Search,
  Send,
  Share2,
  Sparkles,
} from 'lucide-react';
import { useParams } from 'react-router-dom';
import { api, apiText } from '../api/client';
import { useAuthorization } from '../auth/authorization';
import {
  ErrorPanel,
  EventRows,
  Loading,
  Metric,
  Scope,
  SeverityBadge,
  SourceIcon,
  fmt,
} from '../components/common';
import type { AIResponse, Disposition, Incident, RecommendedAction, SecurityEvent } from '../types';

function Overview({ incident }: { incident: Incident }) {
  return (
    <div className="grid grid-cols-[1.5fr_1fr] gap-4">
      <div className="space-y-4">
        <section className="panel p-5">
          <div className="label">Executive Summary</div>
          <p className="mt-3 leading-7 text-sm">
            {incident.description} The sequence affects <b>{incident.primary_user}</b> on{' '}
            <b>{incident.primary_host}</b> and warrants immediate analyst review.
          </p>
        </section>
        <section className="panel p-5 border-l-2 border-l-amber-400">
          <div className="flex justify-between">
            <div className="label">Root Cause Hypothesis</div>
            <span className="text-xs text-cyan-300">
              Evidence confidence: {incident.confidence_score}/100
            </span>
          </div>
          <p className="mt-3 text-sm leading-6">{incident.root_cause}</p>
          <div className="text-[10px] muted mt-3">HYPOTHESIS — requires analyst validation</div>
        </section>
        <section className="panel p-5">
          <div className="label mb-4">Scope</div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <Scope name="Affected User" value={incident.primary_user || 'Unconfirmed'} />
            <Scope name="Affected Host" value={incident.primary_host || 'Unconfirmed'} />
            <Scope name="Source IPs" value={incident.source_ips.join(', ')} />
            <Scope name="Evidence IDs" value={incident.event_ids.length + ' correlated events'} />
          </div>
        </section>
      </div>
      <div className="space-y-4">
        <section className="panel p-5">
          <div className="label">Risk Score Breakdown</div>
          <div className="mt-5 space-y-4">
            {Object.entries(incident.score_breakdown).map(([name, value]) => (
              <div key={name}>
                <div className="flex justify-between text-xs">
                  <span>{name}</span>
                  <b>+{value}</b>
                </div>
                <div className="h-1.5 bg-[#172b39] rounded mt-2">
                  <div
                    className="h-full bg-cyan-400 rounded"
                    style={{ width: Math.min(100, (value / 40) * 100) + '%' }}
                  />
                </div>
              </div>
            ))}
          </div>
          <div className="border-t border-[#294052] mt-5 pt-4 flex justify-between">
            <span className="font-semibold">Total risk</span>
            <div>
              <b className="text-2xl text-red-400">{incident.risk_score}</b>
              <span className="muted"> / 100</span>
            </div>
          </div>
          <div className="mt-3">
            <SeverityBadge severity={incident.severity} />
          </div>
        </section>
        <section className="panel p-5">
          <div className="label">Evidence Confidence Breakdown</div>
          {Object.entries(incident.confidence_breakdown).map(([name, value]) => (
            <div key={name} className="flex justify-between text-xs mt-3">
              <span>{name}</span>
              <b>{value}</b>
            </div>
          ))}
        </section>
      </div>
    </div>
  );
}
function Timeline({ events }: { events: SecurityEvent[] }) {
  const [expanded, setExpanded] = useState(''),
    [filter, setFilter] = useState('All');
  const shown = events.filter((event) => filter === 'All' || event.source === filter);
  return (
    <div className="panel p-5">
      <div className="flex justify-between">
        <div>
          <div className="label">Forensic Timeline</div>
          <div className="text-sm muted mt-1">
            Chronological reconstruction from correlated telemetry
          </div>
        </div>
        <div className="flex gap-2">
          {['All', 'Identity', 'Endpoint', 'Network', 'Cloud'].map((source) => (
            <button
              key={source}
              onClick={() => setFilter(source)}
              className={'btn ' + (filter === source ? 'border-cyan-400 text-cyan-300' : '')}
            >
              {source}
            </button>
          ))}
        </div>
      </div>
      <div className="mt-6 ml-3 border-l border-[#315168]">
        {shown.map((event) => (
          <div key={event.id} className="relative pl-7 pb-5">
            <div className="absolute -left-3 top-0 w-6 h-6 bg-[#102434] border border-[#315168] rounded-full grid place-items-center text-cyan-300">
              <SourceIcon source={event.source} />
            </div>
            <button
              className="panel p-4 w-full text-left hover:border-[#3d657d]"
              onClick={() => setExpanded(expanded === event.id ? '' : event.id)}
            >
              <div className="flex justify-between">
                <div>
                  <span className="font-mono text-xs text-cyan-300">
                    {new Date(event.timestamp).toISOString().slice(11, 19)}Z
                  </span>
                  <b className="ml-4 text-sm">{event.activity}</b>
                  <div className="text-xs muted mt-2">
                    {event.source} · {event.user || event.host || event.source_ip} · {event.id}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {event.risk_flags.map((flag) => (
                    <span
                      key={flag}
                      className="text-[9px] px-2 py-1 bg-amber-500/10 text-amber-300 rounded"
                    >
                      {flag}
                    </span>
                  ))}
                  <ChevronDown size={15} />
                </div>
              </div>
              {expanded === event.id && (
                <pre className="mt-4 p-3 bg-black/30 border border-[#263e4e] rounded text-[11px] text-slate-400 overflow-auto">
                  {JSON.stringify(event.raw, null, 2)}
                </pre>
              )}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
function Evidence({ incident }: { incident: Incident }) {
  const [query, setQuery] = useState(''),
    [expanded, setExpanded] = useState('');
  const events = incident.events.filter((event) =>
    JSON.stringify(event).toLowerCase().includes(query.toLowerCase()),
  );
  return (
    <div className="panel overflow-hidden">
      <div className="p-4 flex justify-between">
        <div>
          <div className="label">Correlated Evidence</div>
          <div className="text-xs muted mt-1">
            {events.length} structured telemetry records · {incident.detection_findings.length}{' '}
            versioned findings
          </div>
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-2.5 muted" size={14} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search evidence"
            className="bg-[#0a1822] border border-[#294254] rounded pl-9 pr-3 py-2 text-xs"
          />
        </div>
      </div>
      <EventRows events={events} expanded={expanded} setExpanded={setExpanded} />
    </div>
  );
}
function EntityGraph({ incident }: { incident: Incident }) {
  const [selected, setSelected] = useState<Incident['graph']['nodes'][number]>();
  return (
    <div className="grid grid-cols-[1fr_300px] gap-4">
      <div className="panel p-6 min-h-[440px]">
        <div className="flex items-center gap-2">
          <Share2 size={17} className="text-cyan-300" />
          <b>Entity Investigation Graph</b>
        </div>
        <p className="text-xs muted mt-1">
          Actual entity relationships emitted by the correlation engine.
        </p>
        <div className="grid grid-cols-3 gap-3 mt-7">
          {incident.graph.nodes.map((node) => (
            <button
              key={node.id}
              onClick={() => setSelected(node)}
              className="panel px-4 py-3 hover:border-cyan-500 text-left"
            >
              <div className="label text-cyan-400">{node.type.replace('_', ' ')}</div>
              <div className="text-xs mt-1 break-all">{node.value}</div>
              <div className="text-[10px] muted mt-2">
                {node.evidence_ids.length} evidence links
              </div>
            </button>
          ))}
        </div>
        <div className="label mt-7 mb-2">Observed relationships</div>
        {incident.graph.edges.map((edge) => (
          <div key={edge.id} className="text-xs border-t border-[#213b4e] py-2">
            <span className="text-cyan-300">{edge.from}</span>{' '}
            <ChevronRight className="inline" size={12} /> {edge.relationship.replaceAll('_', ' ')}{' '}
            <ChevronRight className="inline" size={12} />{' '}
            <span className="text-cyan-300">{edge.to}</span>
            <span className="muted ml-2">
              score {edge.score} · {edge.evidence_ids.join(', ')}
            </span>
          </div>
        ))}
      </div>
      <aside className="panel p-5">
        <div className="label">Node Inspector</div>
        {selected ? (
          <div className="mt-4">
            <b className="break-all">{selected.value}</b>
            <div className="label mt-5">Type</div>
            <div className="text-sm mt-1">{selected.type}</div>
            <div className="label mt-5">Related Evidence</div>
            <div className="text-xs text-cyan-300 mt-2">{selected.evidence_ids.join(' · ')}</div>
            <div className="label mt-5">Risk Flags</div>
            <div className="text-xs text-amber-300 mt-2">
              {selected.risk_flags.join(' · ') || 'None'}
            </div>
          </div>
        ) : (
          <p className="text-xs muted mt-4">Select a node to inspect its evidence relationships.</p>
        )}
      </aside>
    </div>
  );
}
function AttackMapping({ incident }: { incident: Incident }) {
  return (
    <div>
      <div className="mb-4 text-xs muted">
        Mappings are simplified, evidence-scoped demonstration mappings—not authoritative ATT&CK
        classifications.
      </div>
      <div className="grid grid-cols-2 gap-4">
        {incident.techniques.map((technique) => (
          <div key={technique.id} className="panel p-5">
            <div className="flex gap-3">
              <span className="font-mono text-cyan-300 bg-cyan-400/10 px-2 py-1 rounded h-fit">
                {technique.id}
              </span>
              <div>
                <h3 className="font-bold">{technique.name}</h3>
                <div className="label mt-4">Why it was mapped</div>
                <p className="text-sm mt-2 leading-6">{technique.reason}</p>
                <div className="label mt-4">Technique-specific Evidence</div>
                <div className="text-xs text-cyan-300 mt-2">
                  {technique.evidence_ids.join(' · ')}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
function ResponsePanel({
  incident,
  reload,
  notify,
}: {
  incident: Incident;
  reload: () => void;
  notify: (message: string) => void;
}) {
  const { can } = useAuthorization();
  type Approval = {
    id: string;
    incident_id: string;
    action: string;
    requested_by: string;
    approved_by?: string;
    status: string;
    created_at: string;
  };
  const [confirm, setConfirm] = useState<RecommendedAction>(),
    [approvals, setApprovals] = useState<Approval[]>([]),
    [error, setError] = useState('');
  const loadApprovals = useCallback(() => {
    if (can('actions:approve'))
      api<Approval[]>('/approvals')
        .then(setApprovals)
        .catch(() => setApprovals([]));
  }, [can]);
  useEffect(loadApprovals, [loadApprovals]);
  const requestApproval = async (action: string) => {
    setError('');
    try {
      await api(`/incidents/${incident.id}/approvals`, {
        method: 'POST',
        body: JSON.stringify({ action }),
      });
      notify('Approval requested from a second responder');
      loadApprovals();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Approval request failed.');
    }
  };
  const approve = async (id: string) => {
    setError('');
    try {
      await api(`/approvals/${id}/approve`, { method: 'POST' });
      notify('Response action approved');
      loadApprovals();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Approval failed.');
    }
  };
  const execute = async () => {
    if (!confirm) return;
    setError('');
    try {
      await api(`/incidents/${incident.id}/actions`, {
        method: 'POST',
        body: JSON.stringify({
          action: confirm.action,
          analyst: 'analyst@demo',
        }),
      });
      notify('Response action executed and added to the audit log');
      setConfirm(undefined);
      reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Action failed.');
    }
  };
  return (
    <div>
      <div className="grid grid-cols-3 gap-3 mb-4">
        <Metric name="Original Risk" value={incident.risk_score + '/100'} />
        <Metric
          name="Residual Risk"
          value={incident.residual_risk_score + '/100'}
          color="text-cyan-300"
        />
        <Metric
          name="Estimated Reduction"
          value={incident.risk_score - incident.residual_risk_score + ' points'}
          color="text-emerald-300"
        />
      </div>
      <div className="flex items-center gap-2 text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 p-3 rounded mb-4">
        <AlertTriangle size={15} />
        {can('actions:execute')
          ? 'High-impact actions require approval and may invoke an allowlisted sandbox connector.'
          : 'Read-only response view. Your role cannot execute actions.'}
      </div>
      {error && <div className="mb-3 text-xs text-red-300">{error}</div>}
      <div className="panel overflow-hidden">
        <div className="p-4 label">Recommended Actions</div>
        {incident.recommended_actions.map((action) => {
          const highImpact = action.reduction_points >= 12,
            approval = approvals.find(
              (item) =>
                item.incident_id === incident.id &&
                item.action === action.action &&
                item.status === 'APPROVED',
            );
          return (
            <div
              key={action.action}
              className="grid-table grid-cols-[1.3fr_2fr_120px_120px_100px] px-4 text-xs"
            >
              <b>{action.action}</b>
              <span className="muted">{action.reason}</span>
              <span>-{action.reduction_points} pts</span>
              <span
                className={action.status === 'EXECUTED' ? 'text-emerald-300' : 'text-amber-300'}
              >
                {action.status}
              </span>
              {highImpact && !approval && can('actions:request') ? (
                <button
                  disabled={action.status === 'EXECUTED'}
                  onClick={() => requestApproval(action.action)}
                  className="btn"
                >
                  Request approval
                </button>
              ) : (
                <button
                  disabled={action.status === 'EXECUTED' || !can('actions:execute')}
                  onClick={() => setConfirm(action)}
                  className="btn"
                >
                  {action.status === 'EXECUTED' ? 'Executed' : 'Execute'}
                </button>
              )}
            </div>
          );
        })}
      </div>
      {can('actions:approve') && approvals.some((item) => item.status === 'PENDING') && (
        <div className="panel mt-4 p-4">
          <div className="label mb-3">Pending two-person approvals</div>
          {approvals
            .filter((item) => item.status === 'PENDING')
            .map((item) => (
              <div
                key={item.id}
                className="flex items-center justify-between border-t border-[#294052] py-3 text-xs"
              >
                <span>
                  <b>{item.action}</b> · {item.incident_id}
                </span>
                <button className="btn" onClick={() => approve(item.id)}>
                  Approve
                </button>
              </div>
            ))}
        </div>
      )}
      {confirm && (
        <div className="fixed inset-0 z-50 bg-black/70 grid place-items-center">
          <div className="panel p-6 w-[420px]">
            <h3 className="font-bold">Confirm response action</h3>
            <p className="text-sm muted mt-3">
              Execute <b className="text-slate-200">{confirm.action}</b>? This uses the configured
              connector and records an auditable result.
            </p>
            <div className="flex justify-end gap-2 mt-5">
              <button className="btn" onClick={() => setConfirm(undefined)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={execute}>
                Confirm Execute
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
function CasePanel({
  incident,
  reload,
  notify,
}: {
  incident: Incident;
  reload: () => void;
  notify: (message: string) => void;
}) {
  const { can } = useAuthorization();
  const [note, setNote] = useState(''),
    [bookmark, setBookmark] = useState(incident.events[0]?.id || ''),
    [bookmarkNote, setBookmarkNote] = useState(''),
    [error, setError] = useState('');
  const perform = async (path: string, method: string, body: object, message: string) => {
    setError('');
    try {
      await api(path, { method, body: JSON.stringify(body) });
      notify(message);
      reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Case update failed.');
    }
  };
  return (
    <div className="grid grid-cols-[1fr_1fr] gap-4">
      <div className="space-y-4">
        <section className="panel p-5">
          <div className="label">Analyst Disposition</div>
          <select
            disabled={!can('incidents:write')}
            aria-label="Incident disposition"
            value={incident.disposition}
            onChange={(e) =>
              perform(
                `/incidents/${incident.id}/disposition`,
                'PATCH',
                { disposition: e.target.value, analyst: 'analyst@demo' },
                'Disposition updated',
              )
            }
            className="mt-3 w-full bg-[#081722] border border-[#294052] rounded px-3 py-2 text-sm"
          >
            {(['UNSET', 'TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN_POSITIVE'] as Disposition[]).map(
              (value) => (
                <option key={value}>{value}</option>
              ),
            )}
          </select>
        </section>
        <section className="panel p-5">
          <div className="label">Add Case Note</div>
          <textarea
            disabled={!can('incidents:write')}
            aria-label="Case note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="mt-3 w-full h-24 bg-[#081722] border border-[#294052] rounded p-3 text-sm"
            placeholder="Record analyst observations…"
          />
          <button
            disabled={!note.trim() || !can('incidents:write')}
            className="btn btn-primary mt-3"
            onClick={() =>
              perform(
                `/incidents/${incident.id}/notes`,
                'POST',
                { text: note, analyst: 'analyst@demo' },
                'Case note added',
              ).then(() => setNote(''))
            }
          >
            Add Note
          </button>
        </section>
        <section className="panel p-5">
          <div className="label">Bookmark Evidence</div>
          <select
            disabled={!can('incidents:write')}
            aria-label="Evidence event"
            value={bookmark}
            onChange={(e) => setBookmark(e.target.value)}
            className="mt-3 w-full bg-[#081722] border border-[#294052] rounded px-3 py-2 text-sm"
          >
            {incident.events.map((event) => (
              <option key={event.id} value={event.id}>
                {event.id} — {event.activity}
              </option>
            ))}
          </select>
          <input
            disabled={!can('incidents:write')}
            aria-label="Bookmark note"
            value={bookmarkNote}
            onChange={(e) => setBookmarkNote(e.target.value)}
            className="mt-3 w-full bg-[#081722] border border-[#294052] rounded px-3 py-2 text-sm"
            placeholder="Why this evidence matters"
          />
          <button
            disabled={!can('incidents:write')}
            className="btn btn-primary mt-3"
            onClick={() =>
              perform(
                `/incidents/${incident.id}/bookmarks`,
                'POST',
                {
                  event_id: bookmark,
                  note: bookmarkNote,
                  analyst: 'analyst@demo',
                },
                'Evidence bookmarked',
              ).then(() => setBookmarkNote(''))
            }
          >
            Bookmark
          </button>
          {error && <div className="text-xs text-red-300 mt-3">{error}</div>}
        </section>
      </div>
      <div className="space-y-4">
        <section className="panel p-5">
          <div className="label">Case Notes</div>
          {incident.notes.length ? (
            incident.notes.map((note) => (
              <div key={note.id} className="border-t border-[#294052] mt-3 pt-3">
                <div className="text-sm">{note.text}</div>
                <div className="text-[10px] muted mt-1">
                  {note.analyst} · {fmt(note.timestamp)}
                </div>
              </div>
            ))
          ) : (
            <p className="text-xs muted mt-3">No analyst notes yet.</p>
          )}
        </section>
        <section className="panel p-5">
          <div className="label">Bookmarked Evidence</div>
          {incident.bookmarks.length ? (
            incident.bookmarks.map((item) => (
              <div key={item.event_id} className="text-xs text-cyan-300 mt-3">
                {item.event_id}
              </div>
            ))
          ) : (
            <p className="text-xs muted mt-3">No evidence bookmarked yet.</p>
          )}
        </section>
        <section className="panel p-5">
          <div className="label">Residual Risk History</div>
          {incident.risk_history.map((item, index) => (
            <div
              key={item.timestamp + index}
              className="border-t border-[#294052] mt-3 pt-3 text-xs"
            >
              <b>
                {item.original_risk} → {item.residual_risk}
              </b>
              <div className="muted mt-1">
                {item.reason} · {fmt(item.timestamp)}
              </div>
            </div>
          ))}
        </section>
      </div>
    </div>
  );
}
function AIInvestigator({ incident }: { incident: Incident }) {
  const [messages, setMessages] = useState([
      {
        role: 'assistant',
        text: 'I’m grounded in this incident’s correlated evidence. Ask what happened, what supports the hypothesis, or what to investigate next.',
      },
    ]),
    [question, setQuestion] = useState(''),
    [busy, setBusy] = useState(false),
    [meta, setMeta] = useState<AIResponse>(),
    [error, setError] = useState('');
  const ask = async (value = question) => {
    if (!value.trim()) return;
    setMessages((items) => [...items, { role: 'user', text: value }]);
    setQuestion('');
    setBusy(true);
    setError('');
    try {
      const response = await api<AIResponse>(`/incidents/${incident.id}/ask`, {
        method: 'POST',
        body: JSON.stringify({ question: value }),
      });
      setMeta(response);
      setMessages((items) => [...items, { role: 'assistant', text: response.answer }]);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Investigator request failed.');
    } finally {
      setBusy(false);
    }
  };
  const suggestions = [
    'What probably happened?',
    'What evidence supports credential compromise?',
    'What systems are affected?',
    'What should I investigate next?',
    'Recommend containment actions.',
    'Why is this critical?',
  ];
  return (
    <div className="grid grid-cols-[1.6fr_1fr] gap-4">
      <div className="panel flex flex-col h-[570px]">
        <div className="p-4 border-b border-[#294052] flex gap-2 items-center">
          <Sparkles className="text-cyan-300" size={17} />
          <b>Evidence-grounded Investigator</b>
          <span className="ml-auto text-[10px] bg-emerald-500/10 text-emerald-300 px-2 py-1 rounded">
            {meta?.mode === 'openai'
              ? 'OPENAI API'
              : meta?.mode === 'local_fallback'
                ? 'LOCAL FALLBACK'
                : 'LOCAL DETERMINISTIC'}
          </span>
          {meta?.validated && (
            <span className="text-[10px] text-cyan-300">✓ Evidence structure validated</span>
          )}
        </div>
        <div className="flex-1 p-4 overflow-y-auto scroll space-y-3">
          {messages.map((message, index) => (
            <div
              key={message.role + index}
              className={
                'max-w-[85%] rounded-lg p-3 text-sm whitespace-pre-wrap leading-6 ' +
                (message.role === 'user'
                  ? 'ml-auto bg-cyan-500/15 border border-cyan-500/20'
                  : 'bg-[#112431] border border-[#294052]')
              }
            >
              {message.text}
            </div>
          ))}
          {busy && <div className="muted text-xs animate-pulse">Analyzing supplied evidence…</div>}
          {error && <div className="text-xs text-red-300">{error}</div>}
        </div>
        <div className="px-4 flex gap-2 flex-wrap">
          {suggestions.map((value) => (
            <button
              key={value}
              onClick={() => ask(value)}
              className="text-[10px] border border-[#294052] px-2 py-1 rounded text-cyan-300"
            >
              {value}
            </button>
          ))}
        </div>
        <div className="p-4 flex gap-2">
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && ask()}
            className="flex-1 bg-[#081722] border border-[#294052] rounded px-3 text-sm"
            placeholder="Ask about this incident’s evidence…"
          />
          <button
            aria-label="Send question"
            disabled={busy}
            className="btn btn-primary"
            onClick={() => ask()}
          >
            <Send size={15} />
          </button>
        </div>
      </div>
      <div className="panel p-5">
        <div className="label">Investigation Context</div>
        <div className="space-y-4 mt-5">
          <Scope name="Evidence events" value={incident.events.length} />
          <Scope name="Affected user" value={incident.primary_user || 'Unconfirmed'} />
          <Scope name="Affected host" value={incident.primary_host || 'Unconfirmed'} />
          <Scope name="Risk score" value={incident.risk_score + '/100'} />
          <Scope
            name="Detected techniques"
            value={incident.techniques.map((t) => t.id).join(', ')}
          />
          {meta && <Scope name="Response latency" value={meta.latency_ms + ' ms'} />}
        </div>
        <div className="border-t border-[#294052] mt-6 pt-4 text-xs muted leading-5">
          Evidence-ID validation constrains grounding but does not prove that an interpretation is
          correct.
        </div>
      </div>
    </div>
  );
}
export default function InvestigationPage() {
  const { can } = useAuthorization();
  const { id } = useParams(),
    [incident, setIncident] = useState<Incident>(),
    [tab, setTab] = useState('Overview'),
    [toast, setToast] = useState(''),
    [error, setError] = useState('');
  const load = useCallback(() => {
    setError('');
    api<Incident>('/incidents/' + id)
      .then(setIncident)
      .catch((e: Error) => setError(e.message));
  }, [id]);
  useEffect(load, [load]);
  if (error) return <ErrorPanel message={error} retry={load} />;
  if (!incident) return <Loading />;
  const update = async (status: string) => {
    try {
      await api(`/incidents/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      });
      setToast(`Incident marked ${status}`);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Status update failed.');
    }
  };
  const exportReport = async () => {
    const report = await apiText(`/incidents/${id}/report`);
    const url = URL.createObjectURL(new Blob([report], { type: 'text/markdown' })),
      anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = id + '-report.md';
    anchor.click();
    URL.revokeObjectURL(url);
  };
  const tabs = [
    'Overview',
    'Timeline',
    'Evidence',
    'Entity Graph',
    'Attack Mapping',
    'Response',
    'Case',
    'AI Investigator',
  ];
  return (
    <>
      {toast && (
        <div className="fixed right-6 top-20 z-50 bg-emerald-950 border border-emerald-700 px-4 py-3 rounded-lg text-sm">
          <CheckCircle2 className="inline mr-2" size={16} />
          {toast}
        </div>
      )}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex gap-3 items-center">
            <SeverityBadge severity={incident.severity} />
            <span className="font-mono text-xs muted">{incident.id}</span>
            <span className="label">{incident.incident_type}</span>
          </div>
          <h1 className="text-2xl font-bold mt-3">{incident.title}</h1>
          <div className="flex gap-5 text-xs muted mt-2">
            <span>
              Status <b className="text-cyan-300">{incident.status}</b>
            </span>
            <span>
              Disposition <b className="text-slate-300">{incident.disposition}</b>
            </span>
            <span>
              First seen <b className="text-slate-300">{fmt(incident.events[0].timestamp)}</b>
            </span>
            <span>
              Last seen <b className="text-slate-300">{fmt(incident.events.at(-1)!.timestamp)}</b>
            </span>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            disabled={!can('incidents:resolve')}
            className="btn"
            onClick={() => update('INVESTIGATING')}
          >
            Assign to Me
          </button>
          <button
            disabled={!can('incidents:resolve')}
            className="btn"
            onClick={() => update('RESOLVED')}
          >
            Resolve
          </button>
          <button className="btn flex gap-2" onClick={exportReport}>
            <Download size={14} />
            Export Report
          </button>
        </div>
      </div>
      <div className="grid grid-cols-4 gap-3 mt-5">
        <Metric name="Original Risk" value={incident.risk_score + '/100'} color="text-red-400" />
        <Metric
          name="Evidence Confidence"
          value={incident.confidence_score + '/100'}
          color="text-cyan-300"
        />
        <Metric name="Evidence Events" value={incident.events.length} />
        <Metric name="Affected Assets" value={incident.affected_assets.length} />
      </div>
      <div className="flex gap-7 border-b border-[#1d3545] mt-5">
        {tabs.map((name) => (
          <button
            key={name}
            className={'tab ' + (tab === name ? 'active' : '')}
            onClick={() => setTab(name)}
          >
            {name}
          </button>
        ))}
      </div>
      <div className="mt-5">
        {tab === 'Overview' && <Overview incident={incident} />}{' '}
        {tab === 'Timeline' && <Timeline events={incident.events} />}{' '}
        {tab === 'Evidence' && <Evidence incident={incident} />}{' '}
        {tab === 'Entity Graph' && <EntityGraph incident={incident} />}{' '}
        {tab === 'Attack Mapping' && <AttackMapping incident={incident} />}{' '}
        {tab === 'Response' && (
          <ResponsePanel incident={incident} reload={load} notify={setToast} />
        )}{' '}
        {tab === 'Case' && <CasePanel incident={incident} reload={load} notify={setToast} />}{' '}
        {tab === 'AI Investigator' && <AIInvestigator incident={incident} />}
      </div>
    </>
  );
}
