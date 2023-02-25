import { dev } from '$app/environment';
import { authN, COOKIE_KEY } from '$lib/server/auth';
import type { RequestHandler } from '@sveltejs/kit';

export const GET = (async ({ cookies, url }) => {
	const code = Number(url.searchParams.get('code') ?? null);
	const oAuthStateBase64 = cookies.get(COOKIE_KEY.OAUTH_STATE(dev)) as string;
	const codeVerifier = cookies.get(COOKIE_KEY.CODE_VERIFIER(dev)) as string;

	return authN.processCallback(code, oAuthStateBase64, url, codeVerifier, dev);
}) satisfies RequestHandler;
