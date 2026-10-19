import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { ProtectedRoute } from '@/src/App';
import { AuthProvider } from '@/src/hooks/useAuth';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

describe('route guard', () => {
  it.each(['/events?action=BLOCK', '/requests/my-request'])('redirects an unauthenticated direct route %s to login', async (entry) => {
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[entry]}>
          <AuthProvider>
            <Routes>
              <Route path="/login" element={<p>Login screen</p>} />
              <Route
                path={entry.split('?')[0]}
                element={
                  <ProtectedRoute>
                    <p>Protected events</p>
                  </ProtectedRoute>
                }
              />
            </Routes>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByText('Login screen')).toBeInTheDocument();
    expect(screen.queryByText('Protected events')).not.toBeInTheDocument();
  });
});
