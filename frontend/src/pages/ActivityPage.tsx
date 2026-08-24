import {useCallback,useEffect,useState} from 'react';
import {Command} from 'lucide-react';
import {api} from '../api/client';
import {ErrorPanel,Loading,PageTitle,fmt} from '../components/common';
import type {ActivityRecord} from '../types';

const columns='grid-cols-[160px_minmax(220px,1.1fr)_minmax(260px,1.8fr)_160px_100px]';

export default function ActivityPage(){
  const[items,setItems]=useState<ActivityRecord[]>(),[error,setError]=useState('');
  const load=useCallback(()=>{void api<ActivityRecord[]>('/activity').then(setItems).catch((e:Error)=>setError(e.message))},[]);
  useEffect(load,[load]);
  if(error)return <ErrorPanel message={error} retry={load}/>;
  if(!items)return <Loading/>;
  return <>
    <PageTitle eyebrow="Audit & Compliance" title="Activity Log" sub="Immutable-style trail of every simulated analyst action"/>
    <div className="panel overflow-x-auto scroll">
      <div className="min-w-[980px]">
        <div className={`grid-table ${columns} gap-4 px-4 label bg-[#0b1924]`}>
          <span>Timestamp</span><span>Analyst</span><span>Action</span><span>Incident</span><span>Result</span>
        </div>
        {items.map(item=><div key={item.id} className={`grid-table ${columns} gap-4 px-4 text-xs`}>
          <span className="whitespace-nowrap">{fmt(item.timestamp)}</span>
          <span className="min-w-0 truncate" title={item.analyst}>{item.analyst}</span>
          <span className="min-w-0 truncate font-mono" title={item.action}>{item.action}</span>
          <span className="whitespace-nowrap text-cyan-300">{item.incident_id}</span>
          <span className="whitespace-nowrap text-emerald-300">{item.result}</span>
        </div>)}
        {!items.length&&<div className="p-12 text-center"><Command className="mx-auto muted"/><div className="mt-3">No analyst actions yet</div><div className="text-xs muted mt-1">Execute a response action to create an audit entry.</div></div>}
      </div>
    </div>
  </>;
}
