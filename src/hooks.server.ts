import { COOKIE_KEY, authN, type AuthNPaths } from '$lib/server/auth';
import * as cookie from 'cookie';
import type { Handle } from '@sveltejs/kit';
import { dev } from '$app/environment';

/** @type {import('@sveltejs/kit').Handle} */
export const handle: Handle = async ({ event, resolve }) => {
	const cookies = cookie.parse(event.request.headers.get('cookie') || '');

	const paths: AuthNPaths = {
		protected: [],
		public: ['/auth/**'],
		protectedByDefault: true
	};

	const currentPath = new URL(event.request.url).pathname;

	if (authN.pathRequiresAuthentication(paths, currentPath)) {
		const accessToken = cookies[COOKIE_KEY.ACCESS_TOKEN(dev)];
		const expiresAt = cookies[COOKIE_KEY.EXPIRES_AT(dev)];
		const validAccessToken = await authN.validateAccessToken(accessToken, expiresAt, false);
		if (!validAccessToken) {
			return authN.redirectToLogin({ urlToReturnUserTo: currentPath }, dev);
		}
	}

	return await resolve(event);
};
