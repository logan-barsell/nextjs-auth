import { BetterSqlite3Adapter } from '@lucia-auth/adapter-sqlite';
import { Lucia } from 'lucia';
import db from './db';
import { cookies } from 'next/headers';

const adapter = new BetterSqlite3Adapter(db, {
  user: 'users',
  session: 'sessions',
});
const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === 'production',
    },
  },
});

const setCookie = sessionCookie => {
  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );
};

export async function createAuthSession(userId) {
  const session = await lucia.createSession(userId, {});
  const sessionCookie = lucia.createSessionCookie(session.id);
  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );
}

export async function verifyAuth() {
  const noSession = {
    user: null,
    session: null,
  };

  const sessionCookie = cookies().get(lucia.sessionCookieName);

  if (!sessionCookie) {
    return noSession;
  }

  const sessionId = sessionCookie.value;

  if (!sessionId) {
    return noSession;
  }

  const result = await lucia.validateSession(sessionId);

  try {
    if (result.session && result.session.fresh) {
      const sessionCookie = lucia.createSessionCookie(lucia.sessionCookieName);
      setCookie(sessionCookie);
    }
    if (!result.session) {
      const sessionCookie = lucia.createBlankSessionCookie();
      setCookie(sessionCookie);
    }
  } catch {}

  return result;
}

export async function destroySession() {
  const { session } = await verifyAuth();
  if (!session) {
    return {
      error: 'Unauthorized',
    };
  }

  await lucia.invalidateSession(session.id);
  const sessionCookie = lucia.createBlankSessionCookie();
  setCookie(sessionCookie);
}
