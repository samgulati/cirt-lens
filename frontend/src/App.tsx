import { lazy, Suspense } from 'react';
import { Route, Routes } from 'react-router-dom';
import Shell from './components/layout/Shell';
import { Loading } from './components/common';
const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const IncidentsPage = lazy(() => import('./pages/IncidentsPage'));
const InvestigationPage = lazy(() => import('./pages/InvestigationPage'));
const TelemetryPage = lazy(() => import('./pages/TelemetryPage'));
const ThreatHuntPage = lazy(() => import('./pages/ThreatHuntPage'));
const PlaybooksPage = lazy(() => import('./pages/PlaybooksPage'));
const ActivityPage = lazy(() => import('./pages/ActivityPage'));
const OperationsPage = lazy(() => import('./pages/OperationsPage'));
export default function App() {
  return (
    <Shell>
      <Suspense fallback={<Loading />}>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:id" element={<InvestigationPage />} />
          <Route path="/telemetry" element={<TelemetryPage />} />
          <Route path="/hunt" element={<ThreatHuntPage />} />
          <Route path="/playbooks" element={<PlaybooksPage />} />
          <Route path="/activity" element={<ActivityPage />} />
          <Route path="/operations" element={<OperationsPage />} />
        </Routes>
      </Suspense>
    </Shell>
  );
}
