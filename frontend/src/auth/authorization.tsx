import { createContext, useContext, type ReactNode } from 'react';
const ROLE_PERMISSIONS: Record<string, string[]> = {
  Viewer: ['incidents:read', 'telemetry:read', 'rules:read', 'audit:read'],
  Analyst: [
    'incidents:read',
    'incidents:write',
    'incidents:resolve',
    'telemetry:read',
    'actions:request',
    'rules:read',
    'audit:read',
  ],
  Responder: [
    'incidents:read',
    'incidents:write',
    'incidents:resolve',
    'telemetry:read',
    'actions:request',
    'actions:approve',
    'actions:execute',
    'rules:read',
    'audit:read',
  ],
  Administrator: [
    'incidents:read',
    'incidents:write',
    'incidents:resolve',
    'telemetry:read',
    'telemetry:ingest',
    'actions:request',
    'actions:approve',
    'actions:execute',
    'rules:read',
    'rules:manage',
    'users:manage',
    'audit:read',
  ],
};
type Authorization = {
  roles: string[];
  permissions: Set<string>;
  can: (permission: string) => boolean;
};
const localPermissions = new Set(ROLE_PERMISSIONS.Administrator);
const AuthorizationContext = createContext<Authorization>({
  roles: ['Administrator'],
  permissions: localPermissions,
  can: (permission) => localPermissions.has(permission),
});
export function AuthorizationProvider({
  roles,
  children,
}: {
  roles: string[];
  children: ReactNode;
}) {
  const permissions = new Set(roles.flatMap((role) => ROLE_PERMISSIONS[role] || []));
  return (
    <AuthorizationContext.Provider
      value={{ roles, permissions, can: (permission) => permissions.has(permission) }}
    >
      {children}
    </AuthorizationContext.Provider>
  );
}
export const useAuthorization = () => useContext(AuthorizationContext);
