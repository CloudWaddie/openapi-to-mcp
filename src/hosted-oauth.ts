import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { openHostedOAuthStore } from './hosted-oauth-store';
import express, { type Express, type RequestHandler } from 'express';
import type { AuthorizationParams, OAuthServerProvider } from '../node_modules/@modelcontextprotocol/sdk/dist/cjs/server/auth/provider';
import type { OAuthRegisteredClientsStore } from '../node_modules/@modelcontextprotocol/sdk/dist/cjs/server/auth/clients';
import type { OAuthClientInformationFull } from '../node_modules/@modelcontextprotocol/sdk/dist/cjs/shared/auth';

const authPath = path.join(__dirname, '..', 'node_modules', '@modelcontextprotocol', 'sdk', 'dist/cjs/server/auth');
const { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } =
  require(path.join(authPath, 'router.js')) as typeof import('../node_modules/@modelcontextprotocol/sdk/dist/cjs/server/auth/router');
const { InvalidGrantError, InvalidClientMetadataError, InvalidTargetError, InvalidTokenError, InvalidScopeError } =
  require(path.join(authPath, 'errors.js')) as typeof import('../node_modules/@modelcontextprotocol/sdk/dist/cjs/server/auth/errors');

const approvalLifetime = 5 * 60_000;
const codeLifetime = 2 * 60_000;
const accessLifetime = 2 * 60 * 60;
const refreshLifetime = 90 * 24 * 60 * 60;
const attemptWindow = 15 * 60_000;
const maxFailedAttempts = 10;

type PendingAuthorization = { clientId: string; params: AuthorizationParams; expiresAt: number };

function secret(): string {
  return randomBytes(32).toString('base64url');
}

function digest(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

function allowsRedirect(value: string): boolean {
  const url = new URL(value);
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  return !url.username && !url.password && !url.hash &&
    (url.protocol === 'https:' || (url.protocol === 'http:' && loopback));
}

function removeExpired(records: Map<string, { expiresAt: number }>): void {
  for (const [id, entry] of records) {
    if (entry.expiresAt <= Date.now()) records.delete(id);
  }
}

export function configureHostedOAuth(
  app: Express,
  config: { publicUrl: string; password: string; storeFile?: string },
  readBearerToken: (authorization?: string) => string | undefined,
): RequestHandler {
  const issuer = new URL(config.publicUrl);
  const resource = new URL('/mcp', issuer);
  const metadataUrl = getOAuthProtectedResourceMetadataUrl(resource);
  const passwordHash = digest(config.password);
  const store = openHostedOAuthStore(config.storeFile ?? './.mcp-data/oauth-state.json', resource.href);
  const approvals = new Map<string, PendingAuthorization>();
  const codes = new Map<string, PendingAuthorization>();
  let failedAttempts = 0;
  let resetAttemptsAt = 0;

  function checkResource(target?: URL): void {
    if (target && target.href !== resource.href) throw new InvalidTargetError('Invalid MCP resource');
  }

  function getGrant<T extends { clientId: string; expiresAt: number }>(
    records: Map<string, T>, value: string, clientId: string,
  ): T {
    const grant = records.get(value);
    if (!grant || grant.clientId !== clientId || grant.expiresAt <= Date.now()) {
      throw new InvalidGrantError('Invalid or expired grant');
    }
    return grant;
  }

  function issueTokens(clientId: string, scopes: string[], authorizationId: string, consumedRefresh?: string) {
    const accessToken = secret();
    const refreshToken = secret();
    const grant = { clientId, scopes, authorizationId };
    store.update(({ access, refresh }) => {
      removeExpired(access);
      removeExpired(refresh);
      if (consumedRefresh) refresh.delete(consumedRefresh);
      access.set(digest(accessToken).toString('hex'), { ...grant, expiresAt: Date.now() + accessLifetime * 1000 });
      refresh.set(digest(refreshToken).toString('hex'), { ...grant, expiresAt: Date.now() + refreshLifetime * 1000 });
    });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: accessLifetime,
      refresh_token: refreshToken,
      ...(scopes.length ? { scope: scopes.join(' ') } : {}),
    };
  }

  const clientsStore: OAuthRegisteredClientsStore = {
    getClient: (id) => store.state.clients.get(id),
    registerClient: (client) => {
      if (!client.redirect_uris.length || !client.redirect_uris.every(allowsRedirect)) {
        throw new InvalidClientMetadataError('Redirect URIs must use HTTPS or loopback HTTP and omit fragments and credentials');
      }
      if (store.state.clients.size >= 10_000) throw new InvalidClientMetadataError('Client registration limit reached');
      const registered: OAuthClientInformationFull = {
        client_id: secret(),
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      };
      store.update(({ clients }) => clients.set(registered.client_id, registered));
      return registered;
    },
  };

  const provider: OAuthServerProvider = {
    clientsStore,
    // Validate and consume the code in one step with its PKCE proof.
    skipLocalPkceValidation: true,
    async authorize(client, params, res) {
      checkResource(params.resource);
      if (!/^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge)) {
        throw new InvalidGrantError('A valid S256 PKCE challenge is required');
      }
      removeExpired(approvals);
      const approval = secret();
      if (approvals.size >= 1000) throw new InvalidGrantError('Too many pending authorizations');
      approvals.set(approval, { clientId: client.client_id, params, expiresAt: Date.now() + approvalLifetime });
      const host = new URL(params.redirectUri).origin.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      res.set({
        'Cache-Control': 'no-store',
        'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
        // Keep the browser's form POST Origin without leaking the authorization URL.
        'Referrer-Policy': 'origin',
      }).type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8">
<title>Authorize MCP access</title><h1>Authorize MCP access</h1><p>Client callback: ${host}</p>
<form action="/approve" method="post">
<input type="hidden" name="approval" value="${approval}">
<label>Password <input type="password" name="password" required></label>
<button type="submit">Authorize</button></form></html>`);
    },
    async challengeForAuthorizationCode(client, code) {
      return getGrant(codes, code, client.client_id).params.codeChallenge;
    },
    async exchangeAuthorizationCode(client, code, verifier, redirectUri, target) {
      checkResource(target);
      const { params } = getGrant(codes, code, client.client_id);
      if (redirectUri !== params.redirectUri || !verifier || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) {
        throw new InvalidGrantError('Invalid redirect URI or PKCE verifier');
      }
      if (digest(verifier).toString('base64url') !== params.codeChallenge) {
        throw new InvalidGrantError('PKCE verifier does not match');
      }
      const tokens = issueTokens(client.client_id, params.scopes ?? [], secret());
      codes.delete(code);
      return tokens;
    },
    async exchangeRefreshToken(client, token, scopes, target) {
      checkResource(target);
      const key = digest(token).toString('hex');
      const grant = getGrant(store.state.refresh, key, client.client_id);
      if (scopes?.some((scope) => !grant.scopes.includes(scope))) throw new InvalidScopeError('Scope was not authorized');
      return issueTokens(client.client_id, scopes ?? grant.scopes, grant.authorizationId, key);
    },
    async verifyAccessToken(token) {
      const grant = store.state.access.get(digest(token).toString('hex'));
      if (!grant || grant.expiresAt <= Date.now()) throw new InvalidTokenError('Invalid or expired token');
      return { token, clientId: grant.clientId, scopes: grant.scopes, expiresAt: grant.expiresAt / 1000, resource };
    },
    async revokeToken(client, request) {
      const key = digest(request.token).toString('hex');
      const ownsAccess = store.state.access.get(key)?.clientId === client.client_id;
      const ownsRefresh = store.state.refresh.get(key)?.clientId === client.client_id;
      if (ownsAccess || ownsRefresh) {
        store.update(({ access, refresh }) => {
          if (ownsAccess) access.delete(key);
          if (ownsRefresh) refresh.delete(key);
        });
      }
    },
  };

  app.post('/approve', express.urlencoded({ extended: false, limit: '4kb' }), (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (req.get('origin') && req.get('origin') !== issuer.origin) {
      res.status(403).send('Invalid request origin.');
      return;
    }
    const approval = typeof req.body?.approval === 'string' ? approvals.get(req.body.approval) : undefined;
    if (!approval || approval.expiresAt <= Date.now()) {
      res.status(400).send('Authorization request expired. Reconnect from your MCP client.');
      return;
    }
    if (Date.now() >= resetAttemptsAt) {
      failedAttempts = 0;
      resetAttemptsAt = Date.now() + attemptWindow;
    }
    if (failedAttempts >= maxFailedAttempts) {
      res.set('Retry-After', String(Math.ceil((resetAttemptsAt - Date.now()) / 1000)));
      res.status(429).send('Too many attempts. Try again later.');
      return;
    }
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (!timingSafeEqual(digest(password), passwordHash)) {
      failedAttempts++;
      res.status(403).send('Incorrect password. Go back to try again.');
      return;
    }
    failedAttempts = 0;
    approvals.delete(req.body.approval);
    removeExpired(codes);
    const code = secret();
    codes.set(code, { ...approval, expiresAt: Date.now() + codeLifetime });
    const callback = new URL(approval.params.redirectUri);
    callback.searchParams.set('code', code);
    callback.searchParams.set('iss', issuer.href);
    if (approval.params.state !== undefined) callback.searchParams.set('state', approval.params.state);
    res.redirect(303, callback.href);
  });

  app.use(mcpAuthRouter({ provider, issuerUrl: issuer, resourceServerUrl: resource }));

  return (req, res, next) => {
    const header = req.get('authorization');
    const token = readBearerToken(header);
    const grant = token ? store.state.access.get(digest(token).toString('hex')) : undefined;
    if (!grant || grant.expiresAt <= Date.now()) {
      const error = header ? ', error="invalid_token"' : '';
      res.set('WWW-Authenticate', `Bearer resource_metadata="${metadataUrl}"${error}`);
      res.status(401).end();
      return;
    }
    res.locals.mcpAuthIdentity = grant.authorizationId;
    next();
  };
}
