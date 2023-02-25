import { dev } from '$app/environment';
import { authN, COOKIE_KEY } from '$lib/server/auth';
import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load = (async ({ cookies }) => {
	const codeVerifier = cookies.get(COOKIE_KEY.CODE_VERIFIER(dev)) as string;
	const oAuthState = cookies.get(COOKIE_KEY.OAUTH_STATE(dev)) as string;
	const oAuthUrl = await authN.generateOAuthUrl(codeVerifier, oAuthState);

	throw redirect(302, oAuthUrl);
}) satisfies PageServerLoad;
