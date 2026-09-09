'use client';

/**
 * Root (`/`) — auth gate, not a marketing page.
 *
 * The public marketing landing page was removed so visitors go straight
 * into the product: signed-in users land on `/dashboard`, everyone else
 * lands on `/login`. This mirrors the redirect-on-mount pattern already
 * used by `apps/web/src/app/login/page.tsx` for its own "already signed
 * in" check, since auth state here is client-side only (localStorage via
 * `authApi.isAuthenticated()`) — there is no middleware/cookie check to
 * do this redirect on the server.
 */

import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { authApi } from '@/lib/api';

export const dynamic = 'force-dynamic';

export default function RootPage() {
  const router = useRouter();

  useEffect(() => {
    router.replace(authApi.isAuthenticated() ? '/dashboard' : '/login');
  }, [router]);

  return <div className="min-h-screen bg-zinc-950" />;
}
