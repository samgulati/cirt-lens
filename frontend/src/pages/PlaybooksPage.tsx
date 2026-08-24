import { useCallback, useEffect, useState } from 'react';
import { ChevronRight, Play } from 'lucide-react';
import { api } from '../api/client';
import { EmptyState, ErrorPanel, Loading, PageTitle } from '../components/common';
import type { Playbook } from '../types';
export default function PlaybooksPage() {
  const [items, setItems] = useState<Playbook[]>(),
    [error, setError] = useState('');
  const load = useCallback(() => {
    void api<Playbook[]>('/playbooks')
      .then(setItems)
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);
  if (error) return <ErrorPanel message={error} retry={load} />;
  if (!items) return <Loading />;
  return (
    <>
      <PageTitle
        eyebrow="Response Automation"
        title="Playbooks"
        sub="Deterministic, safely simulated response workflows"
      />
      {items.length ? (
        <div className="grid grid-cols-3 gap-4">
          {items.map((playbook) => (
            <div key={playbook.id} className="panel p-5">
              <div className="w-9 h-9 grid place-items-center rounded bg-cyan-400/10 text-cyan-300">
                <Play size={17} />
              </div>
              <h3 className="font-bold mt-4">{playbook.name}</h3>
              <p className="text-xs muted mt-2 leading-5">{playbook.description}</p>
              <div className="label mt-5">Conditions</div>
              {playbook.conditions.map((condition) => (
                <div key={condition} className="text-xs text-amber-300 mt-2 font-mono">
                  {condition}
                </div>
              ))}
              <div className="label mt-5">Simulated Actions</div>
              {playbook.actions.map((action) => (
                <div key={action} className="flex gap-2 text-xs mt-2">
                  <ChevronRight size={13} className="text-cyan-400" />
                  {action}
                </div>
              ))}
            </div>
          ))}
        </div>
      ) : (
        <EmptyState message="No playbooks are configured." />
      )}
    </>
  );
}
