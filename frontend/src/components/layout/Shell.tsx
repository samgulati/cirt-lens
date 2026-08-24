import { useEffect, useState, type ReactNode } from 'react';
import {
  Activity,
  BarChart3,
  BookOpen,
  Command,
  LogOut,
  Menu,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  Wrench,
  X,
} from 'lucide-react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth0 } from '@auth0/auth0-react';
import { api } from '../../api/client';
import type { Incident, SearchResults } from '../../types';
import { useAuthorization } from '../../auth/authorization';
function Clock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  return (
    <div className="text-xs text-slate-400 font-mono">{time.toISOString().slice(11, 19)} UTC</div>
  );
}
const claimNamespace = 'https://github.com/samgulati/cirt-lens';
function AuthUser() {
  const { user, logout } = useAuth0();
  const roles = (user?.[`${claimNamespace}/roles`] as string[] | undefined) || [];
  return (
    <div className="flex items-center gap-3 border-l border-[#294254] pl-4">
      <div className="text-right leading-tight">
        <div className="text-xs font-semibold max-w-40 truncate">{user?.email || user?.name}</div>
        <div className="text-[10px] uppercase tracking-wider text-cyan-300">
          {roles.join(', ') || 'Authenticated'}
        </div>
      </div>
      <button
        aria-label="Sign out"
        title="Sign out"
        className="text-slate-400 hover:text-white"
        onClick={() => logout({ logoutParams: { returnTo: window.location.origin } })}
      >
        <LogOut size={17} />
      </button>
    </div>
  );
}
function GlobalSearch() {
  const nav = useNavigate(),
    [query, setQuery] = useState(''),
    [results, setResults] = useState<SearchResults | null>(null),
    [active, setActive] = useState(0);
  useEffect(() => {
    if (query.length < 2) {
      setResults(null);
      return;
    }
    const timer = setTimeout(
      () =>
        api<SearchResults>('/search?q=' + encodeURIComponent(query))
          .then(setResults)
          .catch(() => setResults(null)),
      250,
    );
    return () => clearTimeout(timer);
  }, [query]);
  const items = results
    ? [
        ...results.incidents.map((x) => ({
          label: x.title,
          sub: x.id,
          path: '/incidents/' + x.id,
        })),
        ...results.users.map((x) => ({
          label: x,
          sub: 'USER',
          path: '/hunt?q=user:' + encodeURIComponent(x),
        })),
        ...results.hosts.map((x) => ({
          label: x,
          sub: 'HOST',
          path: '/hunt?q=host:' + encodeURIComponent(x),
        })),
        ...results.ips.map((x) => ({
          label: x,
          sub: 'IP',
          path: '/hunt?q=ip:' + encodeURIComponent(x),
        })),
        ...results.events.map((x) => ({
          label: x.activity,
          sub: x.id,
          path: '/telemetry?q=' + encodeURIComponent(x.id),
        })),
      ]
    : [];
  const go = (path: string) => {
    nav(path);
    setQuery('');
    setResults(null);
  };
  return (
    <div className="relative flex-1 max-w-lg">
      <Search size={15} className="absolute left-3 top-2.5 text-slate-500" />
      <input
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setActive(0);
        }}
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            setQuery('');
            setResults(null);
          } else if (e.key === 'ArrowDown') setActive((x) => Math.min(items.length - 1, x + 1));
          else if (e.key === 'ArrowUp') setActive((x) => Math.max(0, x - 1));
          else if (e.key === 'Enter' && items[active]) go(items[active].path);
        }}
        className="w-full bg-[#0e1e2a] border border-[#213b4e] rounded-md py-2 pl-9 pr-3 text-xs outline-none focus:border-cyan-500"
        placeholder="Global search — incidents, users, hosts, IPs"
      />
      {results && (
        <div className="absolute top-11 inset-x-0 panel overflow-hidden shadow-2xl z-50">
          {items.length ? (
            items.map((item, index) => (
              <button
                key={item.path + item.label}
                onMouseEnter={() => setActive(index)}
                onClick={() => go(item.path)}
                className={
                  'w-full text-left px-4 py-2.5 text-xs border-b border-[#1d3545] ' +
                  (active === index ? 'bg-cyan-400/10' : '')
                }
              >
                <b>{item.label}</b>
                <span className="ml-2 muted">{item.sub}</span>
              </button>
            ))
          ) : (
            <div className="p-4 text-xs muted">No matching security entities.</div>
          )}
        </div>
      )}
    </div>
  );
}
export default function Shell({ children }: { children: ReactNode }) {
  const nav = useNavigate();
  const { can } = useAuthorization();
  const [modal, setModal] = useState(false),
    [mobileNav, setMobileNav] = useState(false),
    [scenario, setScenario] = useState('credential'),
    [busy, setBusy] = useState(false),
    [error, setError] = useState('');
  const generate = async () => {
    setBusy(true);
    setError('');
    try {
      const incident = await api<Incident>('/demo/generate', {
        method: 'POST',
        body: JSON.stringify({ scenario }),
      });
      setModal(false);
      nav('/incidents/' + incident.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to generate incident.');
    } finally {
      setBusy(false);
    }
  };
  const links = [
    [BarChart3, 'Overview', '/'],
    [ShieldAlert, 'Incidents', '/incidents'],
    [Activity, 'Telemetry', '/telemetry'],
    [Search, 'Threat Hunt', '/hunt'],
    [BookOpen, 'Playbooks', '/playbooks'],
    [Command, 'Activity', '/activity'],
    ...(can('audit:read') ? ([[Wrench, 'Operations', '/operations']] as const) : []),
  ] as const;
  return (
    <div className="min-h-screen flex">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      {mobileNav && (
        <button
          aria-label="Close navigation"
          className="fixed inset-0 bg-black/60 z-20 md:hidden"
          onClick={() => setMobileNav(false)}
        />
      )}
      <aside
        className={`app-sidebar w-56 fixed inset-y-0 border-r border-[#1c3445] bg-[#09151f] flex flex-col z-30 transition-transform ${mobileNav ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}`}
      >
        <div className="h-16 flex items-center px-5 gap-3 border-b border-[#1c3445]">
          <div className="w-8 h-8 rounded-lg bg-cyan-400/15 text-cyan-300 grid place-items-center">
            <Shield size={19} />
          </div>
          <div>
            <div className="font-black tracking-wide">CIRT LENS</div>
            <div className="text-[9px] tracking-[.18em] text-slate-500">SECURITY OPERATIONS</div>
          </div>
        </div>
        <nav className="p-3 space-y-1">
          {links.map(([Icon, name, path]) => (
            <NavLink
              key={path}
              to={path}
              onClick={() => setMobileNav(false)}
              end={path === '/'}
              className={({ isActive }) =>
                'flex items-center gap-3 px-3 py-2.5 rounded-md text-sm ' +
                (isActive
                  ? 'bg-cyan-400/10 text-cyan-300 border border-cyan-400/15'
                  : 'text-slate-400 hover:text-slate-100')
              }
            >
              <Icon size={16} />
              {name}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto p-4">
          <div className="panel p-3 text-xs">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              All systems operational
            </div>
            <div className="mt-3 text-[10px] border border-amber-500/30 text-amber-300 bg-amber-500/10 rounded px-2 py-1 text-center tracking-wider">
              DEMO ENVIRONMENT
            </div>
          </div>
        </div>
      </aside>
      <main id="main-content" tabIndex={-1} className="md:ml-56 flex-1 min-w-0">
        <header className="min-h-16 sticky top-0 z-10 bg-[#08131c]/95 backdrop-blur border-b border-[#1c3445] flex items-center px-3 md:px-6 py-3 gap-3 md:gap-5">
          <button
            aria-label="Open navigation"
            className="md:hidden btn p-2"
            onClick={() => setMobileNav(true)}
          >
            <Menu size={18} />
          </button>
          <GlobalSearch />
          <Clock />
          {can('telemetry:ingest') && (
            <button
              onClick={() => setModal(true)}
              className="btn btn-primary flex gap-2 items-center"
            >
              <Sparkles size={15} />
              Generate Demo Incident
            </button>
          )}
          {import.meta.env.VITE_AUTH0_DOMAIN && <AuthUser />}
        </header>
        <div className="p-6">{children}</div>
      </main>
      {modal && (
        <div className="fixed inset-0 bg-black/70 z-50 grid place-items-center">
          <div className="panel w-[480px] p-6 shadow-2xl">
            <div className="flex justify-between">
              <div>
                <div className="label">Synthetic Telemetry Lab</div>
                <h2 className="text-xl font-bold mt-1">Generate demo incident</h2>
              </div>
              <button aria-label="Close" onClick={() => setModal(false)}>
                <X />
              </button>
            </div>
            <p className="text-sm muted mt-2">
              Generate raw telemetry, validate it, run detections, correlate evidence, score risk,
              and derive the investigation.
            </p>
            <div className="space-y-2 mt-5">
              {[
                ['credential', 'Credential Compromise', 'MFA fatigue and impossible travel'],
                ['endpoint', 'Endpoint Compromise', 'PowerShell, credential access, and C2'],
                ['exfiltration', 'Data Exfiltration', 'Sensitive access and unusual egress'],
              ].map(([value, name, description]) => (
                <button
                  key={value}
                  onClick={() => setScenario(value)}
                  className={
                    'w-full text-left p-4 rounded-lg border ' +
                    (scenario === value
                      ? 'border-cyan-400 bg-cyan-400/10'
                      : 'border-[#294254] bg-[#0b1924]')
                  }
                >
                  <div className="font-semibold">{name}</div>
                  <div className="text-xs muted mt-1">{description}</div>
                </button>
              ))}
            </div>
            {error && <div className="text-xs text-red-300 mt-3">{error}</div>}
            <button disabled={busy} onClick={generate} className="btn btn-primary w-full mt-5 py-3">
              {busy ? 'Running security pipeline…' : 'Generate Incident'}
            </button>
            <div className="text-[10px] text-center muted mt-3">
              No real systems or data are affected.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
