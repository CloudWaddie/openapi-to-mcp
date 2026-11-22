import { createHash, timingSafeEqual } from 'node:crypto';
import axios from 'axios';
import type { Express, RequestHandler } from 'express';
import { configureHostedOAuth } from './hosted-oauth';

const bearerTokenPattern = /^[A-Za-z0-9._~+\/-]+=*$/;
const scopePattern = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export type McpAuthConfig =
  | { mode: 'bearer'; token: string }
  | { mode: 'hosted-oauth'; password: string; publicUrl: string }
  | {
      mode: 'oauth';
      resource: string;
      issuer: string;
      introspectionUrl: string;
      clientId: string;
      clientSecret: string;
      scopes: string[];
    };

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value?.trim()) throw new Error(`${name} is required for MCP OAuth`);
  return value;
}

function readOAuthUrl(name: string, allowQuery = false): string {
  const value = requiredEnv(name).trim();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTPS URL`);
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) ||
      url.username || url.password || value.includes('#') || (!allowQuery && value.includes('?'))) {
    throw new Error(`${name} must be an HTTPS URL without credentials or a fragment (HTTP permitted on loopback)`);
  }
  return value;
}

export function loadMcpAuthConfig(): McpAuthConfig | undefined {
  const token = process.env.MCP_SERVER_BEARER_TOKEN?.trim();
  const oauthVariables = [
    'MCP_OAUTH_RESOURCE_URL', 'MCP_OAUTH_ISSUER', 'MCP_OAUTH_INTROSPECTION_URL',
    'MCP_OAUTH_CLIENT_ID', 'MCP_OAUTH_CLIENT_SECRET', 'MCP_OAUTH_REQUIRED_SCOPES',
  ];
  const externalOAuth = oauthVariables.some((name) => process.env[name]?.trim());
  const password = process.env.MCP_OAUTH_PASSWORD;
  if (password !== undefined && password !== '') {
    if (!password.trim()) throw new Error('MCP_OAUTH_PASSWORD must contain a non-whitespace character');
    if (token || externalOAuth) throw new Error('Configure only one MCP server authentication mode');
    const url = new URL(readOAuthUrl('MCP_PUBLIC_URL'));
    if (url.pathname !== '/') throw new Error('MCP_PUBLIC_URL must be the public origin without /mcp');
    return { mode: 'hosted-oauth', password, publicUrl: url.origin };
  }
  if (process.env.MCP_PUBLIC_URL?.trim() && !externalOAuth && !token) {
    throw new Error('MCP_OAUTH_PASSWORD is required for hosted MCP OAuth');
  }
  if (!externalOAuth) {
    if (token && !bearerTokenPattern.test(token)) {
      throw new Error('MCP_SERVER_BEARER_TOKEN must be a valid Bearer token');
    }
    return token ? { mode: 'bearer', token } : undefined;
  }

  if (token) throw new Error('Configure either MCP server Bearer authentication or OAuth');
  const scopes = (process.env.MCP_OAUTH_REQUIRED_SCOPES ?? '').trim().split(/ +/).filter(Boolean);
  if (scopes.some((scope) => !scopePattern.test(scope))) {
    throw new Error('MCP_OAUTH_REQUIRED_SCOPES must contain space-separated OAuth scopes');
  }

  return {
    mode: 'oauth',
    resource: readOAuthUrl('MCP_OAUTH_RESOURCE_URL'),
    issuer: readOAuthUrl('MCP_OAUTH_ISSUER'),
    introspectionUrl: readOAuthUrl('MCP_OAUTH_INTROSPECTION_URL', true),
    clientId: requiredEnv('MCP_OAUTH_CLIENT_ID'),
    clientSecret: requiredEnv('MCP_OAUTH_CLIENT_SECRET'),
    scopes,
  };
}

function tokenDigest(token: string): Buffer {
  return createHash('sha256').update(token).digest();
}

interface IntrospectionResponse {
  active?: boolean;
  aud?: string | string[];
  iss?: string;
  exp?: number;
  nbf?: number;
  scope?: string;
  token_type?: string;
  sub?: string;
  client_id?: string;
}

function formEncode(value: string): string {
  return new URLSearchParams({ value }).toString().slice('value='.length);
}

export function configureMcpAuth(app: Express, config: McpAuthConfig): RequestHandler {
  if (config.mode === 'hosted-oauth') return configureHostedOAuth(app, config, readBearerToken);
  if (config.mode === 'bearer') {
    const expected = tokenDigest(config.token);
    return (req, res, next) => {
      const token = readBearerToken(req.get('authorization'));
      if (token && timingSafeEqual(tokenDigest(token), expected)) {
        next();
        return;
      }
      res.set('WWW-Authenticate', req.get('authorization') ? 'Bearer error="invalid_token"' : 'Bearer');
      res.status(401).end();
    };
  }

  const resource = new URL(config.resource);
  const metadataPath = '/.well-known/oauth-protected-resource' + (resource.pathname === '/' ? '' : resource.pathname);
  const metadataUrl = new URL(metadataPath, resource.origin).href;
  const metadataRoute = new RegExp('^' + metadataPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$');
  app.get(metadataRoute, (_req, res) => {
    res.json({
      resource: config.resource,
      authorization_servers: [config.issuer],
      bearer_methods_supported: ['header'],
      ...(config.scopes.length ? { scopes_supported: config.scopes } : {}),
    });
  });

  const credentials = Buffer.from(`${formEncode(config.clientId)}:${formEncode(config.clientSecret)}`).toString('base64');
  const introspection = axios.create({
    timeout: 5000,
    maxRedirects: 0,
    maxContentLength: 64 * 1024,
    headers: { Authorization: `Basic ${credentials}`, Accept: 'application/json' },
  });
  const challenge = [
    `resource_metadata="${metadataUrl}"`,
    ...(config.scopes.length ? [`scope="${config.scopes.join(' ')}"`] : []),
  ].join(', ');

  return async (req, res, next) => {
    const authorization = req.get('authorization');
    const token = readBearerToken(authorization);
    let result: IntrospectionResponse | undefined;
    if (token) {
      try {
        const response = await introspection.post<IntrospectionResponse>(
          config.introspectionUrl,
          new URLSearchParams({ token, token_type_hint: 'access_token' }),
        );
        result = response.data;
      } catch {
        res.status(503).json({ error: 'temporarily_unavailable' });
        return;
      }
    }

    const now = Date.now() / 1000;
    const audience = Array.isArray(result?.aud) ? result.aud : [result?.aud];
    if (!token || result?.active !== true || !audience.includes(config.resource) ||
        (result.iss !== undefined && result.iss !== config.issuer) ||
        (result.exp !== undefined && !(typeof result.exp === 'number' && result.exp > now)) ||
        (result.nbf !== undefined && !(typeof result.nbf === 'number' && result.nbf <= now)) ||
        (result.token_type !== undefined && (typeof result.token_type !== 'string' || result.token_type.toLowerCase() !== 'bearer'))) {
      const error = authorization ? ', error="invalid_token"' : '';
      res.set('WWW-Authenticate', `Bearer ${challenge}${error}`);
      res.status(401).end();
      return;
    }

    const grantedScopes = typeof result.scope === 'string' ? result.scope.split(' ') : [];
    if (config.scopes.some((scope) => !grantedScopes.includes(scope))) {
      res.set('WWW-Authenticate', `Bearer ${challenge}, error="insufficient_scope"`);
      res.status(403).end();
      return;
    }
    res.locals.mcpAuthIdentity = typeof result.sub === 'string' && typeof result.client_id === 'string'
      ? JSON.stringify([result.sub, result.client_id])
      : tokenDigest(token).toString('hex');
    next();
  };
}

function readBearerToken(authorization?: string): string | undefined {
  const match = /^Bearer +(.+)$/i.exec(authorization ?? '');
  return match && bearerTokenPattern.test(match[1]) ? match[1] : undefined;
}
