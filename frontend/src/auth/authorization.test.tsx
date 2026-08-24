import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { AuthorizationProvider, useAuthorization } from './authorization';

function Probe() {
  const { can } = useAuthorization();
  return (
    <>
      <span>{can('incidents:read') ? 'read-allowed' : 'read-denied'}</span>
      <span>{can('actions:execute') ? 'execute-allowed' : 'execute-denied'}</span>
      <span>{can('users:manage') ? 'admin-allowed' : 'admin-denied'}</span>
    </>
  );
}

describe('role-derived UI authorization', () => {
  it('keeps a viewer read-only', () => {
    render(
      <AuthorizationProvider roles={['Viewer']}>
        <Probe />
      </AuthorizationProvider>,
    );
    expect(screen.getByText('read-allowed')).toBeInTheDocument();
    expect(screen.getByText('execute-denied')).toBeInTheDocument();
    expect(screen.getByText('admin-denied')).toBeInTheDocument();
  });

  it('allows administrator-only controls for an administrator', () => {
    render(
      <AuthorizationProvider roles={['Administrator']}>
        <Probe />
      </AuthorizationProvider>,
    );
    expect(screen.getByText('execute-allowed')).toBeInTheDocument();
    expect(screen.getByText('admin-allowed')).toBeInTheDocument();
  });
});
