import minimatch from 'minimatch';
import * as oauth from 'oauth4webapi';
import cookies from 'cookie';
import { env } from '$env/dynamic/private';
import { Base64 } from 'js-base64';
import { error } from '@sveltejs/kit';

export interface AuthNPaths {
	protected: string[];
	public: string[];
	protectedByDefault: boolean;
}

const pathRequiresAuthentication = (paths: AuthNPaths, requestUrl: string): boolean => {
	for (const path of paths.protected) {
		if (minimatch(requestUrl, path)) {
			return true;
		}
	}

	for (const path of paths.public) {
		if (minimatch(requestUrl, path)) {
			return false;
		}
	}

	return paths.protectedByDefault;
};

const getValidOAuthConfig = async (): Promise<{
	oAuthServer: oauth.AuthorizationServer;
	oAuthClient: oauth.Client;
}> => {
	const issuer = new URL(env.ISSUER_URL as string); // auth0

	const oAuthServer = await oauth
		.discoveryRequest(issuer)
		.then((response) => oauth.processDiscoveryResponse(issuer, response));

	const oAuthClient: oauth.Client = {
		client_id: env.CLIENT_ID as string,
		client_secret: env.CLIENT_SECRET as string,
		token_endpoint_auth_method: 'client_secret_basic'
	};

	return { oAuthServer, oAuthClient };
};

const generateOAuthUrl = async (code_verifier: string, state: string): Promise<string> => {
	const { oAuthClient, oAuthServer } = await getValidOAuthConfig();
	if (oAuthServer.code_challenge_methods_supported?.includes('S256') !== true) {
		// This example assumes S256 PKCE support is signalled
		// If it isn't supported, random `nonce` must be used for CSRF protection.
		throw new Error();
	}
	const { code_challenge, code_challenge_method } = await generateCodeChallenge(code_verifier);
	const callback_uri = env.CALLBACK_URL as string;

	const authUrl = new URL(oAuthServer.authorization_endpoint || '');
	// Ory specific
	// authUrl.pathname = '/ui/login';
	authUrl.searchParams.set('prompt', 'login');

	// Common between Ory and Auth0
	authUrl.searchParams.set('client_id', oAuthClient.client_id);
	authUrl.searchParams.set('code_challenge', code_challenge);
	authUrl.searchParams.set('code_challenge_method', code_challenge_method);
	authUrl.searchParams.set('redirect_uri', callback_uri);
	authUrl.searchParams.set('response_type', 'code');
	// offline_access is required for refresh tokens
	authUrl.searchParams.set('scope', 'openid email offline_access');
	authUrl.searchParams.set('state', state);

	console.log('authUrl :>> ', authUrl);
	console.log('authUrl.toString() :>> ', authUrl.toString());
	return authUrl.toString();
};

const generateCodeChallenge = async (
	code_verifier: string
): Promise<{ code_challenge: string; code_challenge_method: string }> => {
	const code_challenge = await oauth.calculatePKCECodeChallenge(code_verifier);
	const code_challenge_method = 'S256';
	return { code_challenge, code_challenge_method };
};

const generateRandomCodeVerifier = (): string => {
	return oauth.generateRandomCodeVerifier();
};

const generateAccessTokenCookie = (accessToken: string, dev = true): string => {
	return generateCookie(COOKIE_KEY.ACCESS_TOKEN(dev), accessToken, dev);
};

const generateRefreshTokenCookie = (refreshToken: string, dev = true): string => {
	return generateCookie(COOKIE_KEY.REFRESH_TOKEN(dev), refreshToken, dev);
};

const generateCodeVerifierAndCookie = (dev = true): string => {
	const codeVerifier = generateRandomCodeVerifier();
	return generateCookie(COOKIE_KEY.CODE_VERIFIER(dev), codeVerifier, dev);
};

const generateoAuthStateCookie = (oAuthState: { [key: string]: string }, dev = true): string => {
	const base64State = Base64.encode(JSON.stringify(oAuthState), true);
	return generateCookie('oauth_state', base64State, dev);
};

const generateExpiresAtCookie = (expires_in: number, dev = true): string => {
	const expiresAt = new Date();
	expiresAt.setSeconds(expiresAt.getSeconds() + expires_in);
	return generateCookie('expires_at', expiresAt.toString(), dev);
};

const generateCookie = (key: string, value: string, dev = true): string => {
	return cookies.serialize(key, value, {
		path: '/',
		httpOnly: true,
		secure: !dev,
		// sameSite: !dev ? 'strict' : 'lax',
		maxAge: 3600 // 1 hour
	});
};

const setMultipleCookies = (cookies: string[]): string => {
	return cookies.join(', ');
};

const introspectAccessToken = async (accessToken: string): Promise<boolean> => {
	const { oAuthServer, oAuthClient } = await getValidOAuthConfig();
	try {
		const tokenIntrospection = await oauth.introspectionRequest(
			oAuthServer,
			oAuthClient,
			accessToken
		);
		if (tokenIntrospection.body == null) return false;
		return (await tokenIntrospection.json()) satisfies { active: boolean };
	} catch (e) {
		console.log(e);
	}
	return false;
};

export const redirectToLogin = (state: { [key: string]: string }, dev = true): Response => {
	return new Response(null, {
		status: 307,
		headers: new Headers({
			Location: '/auth/login',
			'set-cookie': setMultipleCookies([
				generateCodeVerifierAndCookie(dev),
				generateoAuthStateCookie(state, dev)
			])
		})
	});
};

export const validateAccessToken = async (
	accessToken: string | undefined,
	expiresAt: string | undefined,
	introspect = false
): Promise<boolean> => {
	if (accessToken == undefined || expiresAt == undefined) return false;
	const expiresAtDate = new Date(expiresAt);
	const today = new Date();
	let result = expiresAtDate > today;
	if (introspect) {
		result = result && (await introspectAccessToken(accessToken));
	}
	return result;
};

export const processCallback = async (
	code: number,
	oAuthStateBase64: string,
	url: URL,
	codeVerifier: string,
	dev = true
): Promise<Response> => {
	if (code === null) throw error(400, 'Callback is missing code parameter');

	const { oAuthClient, oAuthServer } = await getValidOAuthConfig();
	const oAuthState = JSON.parse(Base64.decode(oAuthStateBase64));
	const authParams = oauth.validateAuthResponse(oAuthServer, oAuthClient, url, oAuthStateBase64);

	// TODO Handle OAuth 2.0 redirect error in callback
	if (oauth.isOAuth2Error(authParams)) throw error(500, 'OAuth 2.0 redirect error in callback');

	const response = await oauth.authorizationCodeGrantRequest(
		oAuthServer,
		oAuthClient,
		authParams,
		env.CALLBACK_URL as string,
		codeVerifier
	);

	let challenges: oauth.WWWAuthenticateChallenge[] | undefined;

	if ((challenges = oauth.parseWwwAuthenticateChallenges(response))) {
		for (const challenge of challenges) {
			console.log('challenge', challenge);
		}
		// TODO Handle www-authenticate challenges as needed
		throw error(500, 'www-authenticate challenges as needed');
	}

	const result = await oauth.processAuthorizationCodeOpenIDResponse(
		oAuthServer,
		oAuthClient,
		response
	);
	if (oauth.isOAuth2Error(result)) {
		console.log('error', result);
		throw error(500); // TODO Handle OAuth 2.0 response body error
	}

	const { access_token, refresh_token, expires_in } = result;
	const claims = oauth.getValidatedIdTokenClaims(result);
	// TODO: Store claims details in DB

	return new Response(null, {
		status: 302,
		headers: new Headers({
			Location: oAuthState['urlToReturnUserTo'],
			'set-cookie': setMultipleCookies([
				generateAccessTokenCookie(access_token, dev),
				generateExpiresAtCookie(Number(expires_in), dev),
				generateRefreshTokenCookie(refresh_token as string, dev)
			])
		})
	});
};

export const authN = {
	processCallback,
	validateAccessToken,
	pathRequiresAuthentication,
	redirectToLogin,
	generateOAuthUrl
};

export const COOKIE_KEY = {
	ACCESS_TOKEN: (dev = true): string => {
		return dev ? 'access_token' : '__Secure-access_token';
	},

	REFRESH_TOKEN: (dev = true): string => {
		return dev ? 'refresh_token' : '__Secure-refresh_token';
	},

	CODE_VERIFIER: (dev = true): string => {
		return dev ? 'code_verifier' : '__Secure-code_verifier';
	},

	OAUTH_STATE: (dev = true): string => {
		return dev ? 'oauth_state' : '__Secure-oauth_state';
	},

	EXPIRES_AT: (dev = true): string => {
		return dev ? 'expires_at' : '__Secure-expires_at';
	}
};
