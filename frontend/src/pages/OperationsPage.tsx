import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Database, RefreshCw, ShieldCheck } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { ErrorPanel, Loading, PageTitle, fmt } from '../components/common';
import { useAuthorization } from '../auth/authorization';

type Approval = {
  id: string;
  incident_id: string;
  action: string;
  requested_by: string;
  approved_by?: string;
  status: string;
  created_at: string;
};
type Job = {
  id: string;
  status: string;
  event_count: number;
  attempts: number;
  error?: string;
  created_at: string;
};
type Execution = {
  id: string;
  incident_id: string;
  action: string;
  connector: string;
  provider_request_id?: string;
  status: string;
  dry_run: boolean;
  attempts: number;
  detail: string;
  created_at: string;
};
type Queue = { available: boolean; stream_depth: number | null; dlq_depth: number | null };

function message(error: unknown) {
  if (error instanceof ApiError && error.requestId)
    return `${error.message} · Request ${error.requestId}`;
  return error instanceof Error ? error.message : 'Operation failed';
}

export default function OperationsPage() {
  const { can } = useAuthorization();
  const [approvals, setApprovals] = useState<Approval[]>();
  const [jobs, setJobs] = useState<Job[]>();
  const [executions, setExecutions] = useState<Execution[]>();
  const [queue, setQueue] = useState<Queue>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');

  const load = useCallback(async () => {
    setError('');
    try {
      const requests: Promise<unknown>[] = [
        api<Job[]>('/telemetry/jobs'),
        api<Execution[]>('/connector-executions'),
        api<Queue>('/operations/queue'),
      ];
      if (can('actions:approve')) requests.push(api<Approval[]>('/approvals'));
      const [jobRows, executionRows, queueState, approvalRows = []] = await Promise.all(requests);
      setJobs(jobRows as Job[]);
      setExecutions(executionRows as Execution[]);
      setQueue(queueState as Queue);
      setApprovals(approvalRows as Approval[]);
    } catch (cause) {
      setError(message(cause));
    }
  }, [can]);

  useEffect(() => void load(), [load]);

  const approve = async (id: string) => {
    setBusy(id);
    try {
      await api(`/approvals/${id}/approve`, { method: 'POST' });
      await load();
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy('');
    }
  };
  const reconcile = async (id: string) => {
    setBusy(id);
    try {
      await api(`/connector-executions/${id}/reconcile`, { method: 'POST' });
      await load();
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy('');
    }
  };

  if (!jobs || !executions || !queue || !approvals)
    return error ? <ErrorPanel message={error} retry={load} /> : <Loading />;
  return (
    <>
      <PageTitle
        eyebrow="Platform Operations"
        title="Control Plane"
        sub="Approval inbox, asynchronous ingestion health, and connector reconciliation"
      />
      {error && (
        <div role="alert" className="mb-4 text-sm text-red-300">
          {error}
        </div>
      )}
      <div className="grid md:grid-cols-3 gap-4 mb-6">
        <div className="panel p-4">
          <Database className="text-cyan-300" />
          <div className="label mt-3">Queue depth</div>
          <div className="text-2xl font-bold mt-1">{queue.stream_depth ?? 'Unavailable'}</div>
        </div>
        <div className="panel p-4">
          <AlertTriangle className="text-amber-300" />
          <div className="label mt-3">Dead-letter depth</div>
          <div className="text-2xl font-bold mt-1">{queue.dlq_depth ?? 'Unavailable'}</div>
        </div>
        <div className="panel p-4">
          <ShieldCheck className="text-emerald-300" />
          <div className="label mt-3">Pending approvals</div>
          <div className="text-2xl font-bold mt-1">
            {approvals.filter((x) => x.status === 'PENDING').length}
          </div>
        </div>
      </div>

      <section className="panel mb-6 overflow-x-auto">
        <h2 className="font-bold p-4 border-b border-[#1d3545]">Two-person approval inbox</h2>
        <div className="min-w-[760px]">
          {approvals.map((row) => (
            <div
              key={row.id}
              className="grid grid-cols-[1fr_1.5fr_1fr_120px] gap-4 p-4 border-b border-[#1d3545] text-xs"
            >
              <span>
                {row.incident_id}
                <small className="block muted mt-1">{fmt(row.created_at)}</small>
              </span>
              <span>
                {row.action}
                <small className="block muted mt-1">Requested by {row.requested_by}</small>
              </span>
              <span className="font-mono">{row.status}</span>
              <button
                disabled={row.status !== 'PENDING' || busy === row.id}
                onClick={() => approve(row.id)}
                className="btn"
              >
                Approve
              </button>
            </div>
          ))}
          {!approvals.length && (
            <div className="p-6 muted text-sm">No approval records for this tenant.</div>
          )}
        </div>
      </section>

      <section className="panel mb-6 overflow-x-auto">
        <h2 className="font-bold p-4 border-b border-[#1d3545]">Connector execution history</h2>
        <div className="min-w-[900px]">
          {executions.map((row) => (
            <div
              key={row.id}
              className="grid grid-cols-[1.2fr_1.2fr_1fr_1.4fr_120px] gap-4 p-4 border-b border-[#1d3545] text-xs"
            >
              <span>
                {row.action}
                <small className="block muted mt-1">{row.incident_id}</small>
              </span>
              <span>
                {row.connector}
                <small className="block muted mt-1">
                  {row.dry_run ? 'Dry-run' : 'Live sandbox'}
                </small>
              </span>
              <span className="text-emerald-300">{row.status}</span>
              <span className="truncate" title={row.detail}>
                {row.provider_request_id || row.detail}
              </span>
              <button
                disabled={!can('actions:execute') || busy === row.id}
                onClick={() => reconcile(row.id)}
                className="btn flex items-center gap-1"
              >
                <RefreshCw size={13} /> Reconcile
              </button>
            </div>
          ))}
          {!executions.length && (
            <div className="p-6 muted text-sm">No connector executions yet.</div>
          )}
        </div>
      </section>

      <section className="panel overflow-x-auto">
        <h2 className="font-bold p-4 border-b border-[#1d3545]">Ingestion jobs</h2>
        <div className="min-w-[760px]">
          {jobs.map((row) => (
            <div
              key={row.id}
              className="grid grid-cols-[1.5fr_1fr_1fr_2fr] gap-4 p-4 border-b border-[#1d3545] text-xs"
            >
              <span className="font-mono">
                {row.id}
                <small className="block muted mt-1">{fmt(row.created_at)}</small>
              </span>
              <span>{row.event_count} events</span>
              <span className="flex gap-1 items-center">
                {row.status === 'COMPLETED' && (
                  <CheckCircle2 size={14} className="text-emerald-300" />
                )}
                {row.status}
              </span>
              <span className="truncate text-red-300" title={row.error}>
                {row.error || `${row.attempts} processing attempts`}
              </span>
            </div>
          ))}
          {!jobs.length && (
            <div className="p-6 muted text-sm">No asynchronous ingestion jobs yet.</div>
          )}
        </div>
      </section>
    </>
  );
}
