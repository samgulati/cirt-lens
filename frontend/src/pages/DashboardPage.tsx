import { useCallback, useEffect, useState } from 'react';
import { Activity, AlertTriangle, ShieldAlert, Zap } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { ErrorPanel, IncidentTable, Loading, PageTitle, Panel } from '../components/common';
import type { DashboardResponse } from '../types';
export default function DashboardPage() {
  const nav = useNavigate(),
    [data, setData] = useState<DashboardResponse>(),
    [error, setError] = useState('');
  const load = useCallback(() => {
    setError('');
    api<DashboardResponse>('/dashboard')
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);
  if (error) return <ErrorPanel message={error} retry={load} />;
  if (!data) return <Loading />;
  const pie = Object.entries(data.severity).map(([name, value]) => ({ name, value }));
  const metrics = [
    ['Open Incidents', data.kpis.open_incidents, ShieldAlert],
    ['Critical Incidents', data.kpis.critical_incidents, AlertTriangle],
    ['Events Analyzed', data.kpis.events_analyzed.toLocaleString(), Activity],
    ['Detection Findings', data.kpis.detection_findings, Zap],
  ] as const;
  return (
    <>
      <PageTitle
        eyebrow="Security Operations"
        title="Overview"
        sub="Unified security posture across identity, endpoint, network, and cloud telemetry"
      />
      <div className="grid grid-cols-4 gap-4">
        {metrics.map(([name, value, Icon]) => (
          <div key={name} className="panel p-4">
            <div className="flex justify-between">
              <div className="label">{name}</div>
              <Icon size={17} className="text-cyan-400" />
            </div>
            <div className="text-3xl font-bold mt-3">{value}</div>
            <div className="text-[11px] text-emerald-400 mt-2">● Live demo data</div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-2 gap-4 mt-4">
        <Panel title="Incident Trend — 24 hours">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={data.trend}>
              <CartesianGrid stroke="#1b3546" vertical={false} />
              <XAxis dataKey="hour" stroke="#587083" fontSize={10} />
              <YAxis stroke="#587083" fontSize={10} />
              <Tooltip contentStyle={{ background: '#0b1924', border: '1px solid #294254' }} />
              <Line type="monotone" dataKey="incidents" stroke="#24c7f5" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>
        <div className="grid grid-cols-2 gap-4">
          <Panel title="Incidents by Severity">
            <ResponsiveContainer width="100%" height={190}>
              <PieChart>
                <Pie data={pie} dataKey="value" innerRadius={45} outerRadius={70}>
                  {['#f05b69', '#f59b52', '#f5cf4e', '#45c899'].map((color) => (
                    <Cell key={color} fill={color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#0b1924', border: '1px solid #294254' }} />
              </PieChart>
            </ResponsiveContainer>
          </Panel>
          <Panel title="Detection Sources">
            <ResponsiveContainer width="100%" height={190}>
              <BarChart
                data={Object.entries(data.sources).map(([name, value]) => ({ name, value }))}
              >
                <XAxis dataKey="name" stroke="#587083" fontSize={9} />
                <Tooltip contentStyle={{ background: '#0b1924', border: '1px solid #294254' }} />
                <Bar dataKey="value" fill="#24c7f5" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Panel>
        </div>
      </div>
      <IncidentTable items={data.recent} onOpen={(id) => nav('/incidents/' + id)} />
    </>
  );
}
