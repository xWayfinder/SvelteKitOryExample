# SveltKitOryExample

## Auth logic

Most of the logic is in `/src/lib/server/auth.ts` which wraps the pure js library `oauth4webapi`

`/src/hooks.server.ts` checks the access token is valid and redirects to `/src/routes/auth/login` and sets up cookies.

`/src/routes/auth/login` builds the authorisation url and redirects there

`/src/routes/auth/callback` validates and sets cookies.

## Environment Variables

Create a `/.env` substituring with your config

```
CALLBACK_URL=http://localhost:5173/auth/callback
# auth0
ISSUER_URL=<your-issuer>
CLIENT_ID=<your-client-id>
CLIENT_SECRET=<your-client-secret>

```

## Developing

Install dependencies with:
`npm install` (or `pnpm install` or `yarn`)

Start a development server:

```bash
npm run dev

# or start the server and open the app in a new browser tab
npm run dev -- --open
```

## Building

To create a production version of your app:

```bash
npm run build
```

You can preview the production build with `npm run preview`.

> To deploy your app, you may need to install an [adapter](https://kit.svelte.dev/docs/adapters) for your target environment.
