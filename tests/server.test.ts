import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createMcpApp } from '../src/server';
import type { McpConfig } from '../src/config';
import type { ToolFromOpenApi } from '../src/openapi-to-tools';
import { InstructionsMode } from '../src/instructions-loader';
import { z } from 'zod';

describe('server', () => {
  const baseConfig: McpConfig = {
    serverName: 'test-server',
    apiBaseUrl: 'http://api.test',
    port: 3100,
    host: '0.0.0.0',
    openApiSpec: null,
    includeEndpoints: [],
    excludeEndpoints: [],
    toolPrefix: '',
    instructionsFile: null,
    instructionsMode: InstructionsMode.DEFAULT,
    convertHtmlToMarkdown: true,
    apiBasicAuth: null,
    apiBearerToken: null,
  };

  const mockTool: ToolFromOpenApi = {
    name: 'test_tool',
    description: 'Test tool description',
    inputSchema: z.object({}),
    handler: async () => ({ content: [{ type: 'text', text: 'ok' }] }),
  };

  it('creates Express app with MCP endpoints', () => {
    const app = createMcpApp(baseConfig, [mockTool]);
    expect(app).toBeDefined();
  });

  it('accepts instructions parameter', () => {
    const instructions = 'This is a test API server';
    const app = createMcpApp(baseConfig, [mockTool], instructions);
    expect(app).toBeDefined();
  });

  it('works without instructions when not provided', () => {
    const app = createMcpApp(baseConfig, [mockTool]);
    expect(app).toBeDefined();
  });

  describe('MCP endpoint authentication', () => {
    const servers: Server[] = [];

    async function listen(server: Server): Promise<string> {
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      servers.push(server);
      return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    }

    afterEach(async () => {
      await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
        server.closeAllConnections();
      })));
    });

    function initialize(url: string, authorization?: string): Promise<Response> {
      return fetch(url, {
        method: 'POST',
        headers: {
          Accept: 'application/json, text/event-stream',
          'Content-Type': 'application/json',
          ...(authorization ? { Authorization: authorization } : {}),
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
        }),
      });
    }

    it('requires the configured static token and challenges unauthenticated requests', async () => {
      const app = createMcpApp({
        ...baseConfig,
        apiBearerToken: 'upstream-token',
        mcpAuth: { mode: 'bearer', token: 'mcp-test-token' },
      }, [mockTool]);
      const url = (await listen(createServer(app))) + '/mcp';

      const missing = await fetch(url);
      expect(missing.status).toBe(401);
      expect(missing.headers.get('www-authenticate')).toBe('Bearer');
      expect((await fetch(url + '?access_token=mcp-test-token')).status).toBe(401);
      expect((await initialize(url, 'Bearer upstream-token')).status).toBe(401);
      const accepted = await initialize(url, 'bearer mcp-test-token');
      expect(accepted.status).toBe(200);
      expect(await accepted.text()).toContain('"protocolVersion":"2025-11-25"');
    });

    it('runs the hosted OAuth flow with password approval and PKCE', async () => {
      const server = createServer();
      const origin = await listen(server);
      server.on('request', createMcpApp({
        ...baseConfig,
        mcpAuth: { mode: 'hosted-oauth', password: 'owner-test-password', publicUrl: origin },
      }, [mockTool]));
      const resource = origin + '/mcp';
      const post = (path: string, params: Record<string, string>) => fetch(origin + path, {
        method: 'POST', body: new URLSearchParams(params), redirect: 'manual',
      });

      const unauthenticated = await initialize(resource);
      expect(unauthenticated.status).toBe(401);
      expect(unauthenticated.headers.get('www-authenticate')).toContain('/.well-known/oauth-protected-resource/mcp');
      const metadata = await (await fetch(origin + '/.well-known/oauth-authorization-server')).json() as {
        code_challenge_methods_supported: string[]; registration_endpoint: string; authorization_endpoint: string;
      };
      expect(metadata.code_challenge_methods_supported).toEqual(['S256']);

      const redirect = 'http://localhost:5099/callback';
      const registration = await fetch(metadata.registration_endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ redirect_uris: [redirect], token_endpoint_auth_method: 'none' }),
      });
      expect(registration.status).toBe(201);
      const client = await registration.json() as { client_id: string };

      const verifier = 'a'.repeat(43);
      const authorizationUrl = new URL(metadata.authorization_endpoint);
      authorizationUrl.search = new URLSearchParams({
        client_id: client.client_id, redirect_uri: redirect, response_type: 'code',
        code_challenge: createHash('sha256').update(verifier).digest('base64url'),
        code_challenge_method: 'S256', resource, state: 'client-state',
      }).toString();

      const page = await fetch(authorizationUrl);
      expect(page.status).toBe(200);
      const approval = (await page.text()).match(/name="approval" value="([^"]+)"/)?.[1];
      expect(approval).toBeDefined();
      const denied = await post('/approve', { approval: approval!, password: 'wrong-password' });
      expect(denied.status).toBe(403);
      const approved = await post('/approve', { approval: approval!, password: 'owner-test-password' });
      expect(approved.status).toBe(303);
      const callback = new URL(approved.headers.get('location')!);
      expect(callback.searchParams.get('state')).toBe('client-state');
      const exchange = {
        grant_type: 'authorization_code', client_id: client.client_id,
        redirect_uri: redirect, code: callback.searchParams.get('code')!, resource,
      };
      expect((await post('/token', { ...exchange, code_verifier: 'b'.repeat(43) })).status).toBe(400);
      const tokenResponse = await post('/token', { ...exchange, code_verifier: verifier });
      expect(tokenResponse.status).toBe(200);
      const tokens = await tokenResponse.json() as { access_token: string; refresh_token: string };
      expect((await initialize(resource, `Bearer ${tokens.access_token}`)).status).toBe(200);
      expect((await post('/token', { ...exchange, code_verifier: verifier })).status).toBe(400);

      const refresh = { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token, resource };
      const refreshed = await post('/token', refresh);
      expect(refreshed.status).toBe(200);
      expect((await refreshed.json() as { refresh_token: string }).refresh_token).not.toBe(tokens.refresh_token);
      expect((await post('/token', refresh)).status).toBe(400);
    });

    it('advertises OAuth discovery and checks introspected audience, expiry and scope', async () => {
      let origin = '';
      const issuer = await listen(createServer(async (req, res) => {
        let body = '';
        for await (const chunk of req) body += chunk;
        const params = new URLSearchParams(body);
        if (req.method !== 'POST' || req.headers.authorization !== 'Basic cmVzb3VyY2U6c2VjcmV0' ||
            params.get('token_type_hint') !== 'access_token') {
          res.writeHead(400).end();
          return;
        }
        const token = params.get('token');
        if (token === 'unavailable') {
          res.writeHead(500).end();
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
          active: token !== 'revoked',
          aud: token === 'wrong-audience' ? 'https://another.example/mcp' : [origin + '/mcp'],
          exp: Math.floor(Date.now() / 1000) + (token === 'expired' ? -60 : 60),
          scope: token === 'missing-scope' ? 'mcp:other' : 'mcp:tools',
        }));
      }));
      const server = createServer();
      origin = await listen(server);
      const resource = origin + '/mcp';
      server.on('request', createMcpApp({
        ...baseConfig,
        mcpAuth: {
          mode: 'oauth', resource, issuer, introspectionUrl: issuer + '/introspect',
          clientId: 'resource', clientSecret: 'secret', scopes: ['mcp:tools'],
        },
      }, [mockTool]));

      const metadataUrl = origin + '/.well-known/oauth-protected-resource/mcp';
      const missing = await initialize(resource);
      expect(missing.status).toBe(401);
      expect(missing.headers.get('www-authenticate')).toBe(
        `Bearer resource_metadata="${metadataUrl}", scope="mcp:tools"`,
      );
      expect(await (await fetch(metadataUrl)).json()).toEqual({
        resource,
        authorization_servers: [issuer],
        bearer_methods_supported: ['header'],
        scopes_supported: ['mcp:tools'],
      });

      for (const token of ['wrong-audience', 'expired', 'revoked']) {
        const response = await initialize(resource, `Bearer ${token}`);
        expect(response.status).toBe(401);
        expect(response.headers.get('www-authenticate')).toContain('error="invalid_token"');
      }
      const insufficient = await initialize(resource, 'Bearer missing-scope');
      expect(insufficient.status).toBe(403);
      expect(insufficient.headers.get('www-authenticate')).toContain('error="insufficient_scope"');
      expect((await initialize(resource, 'Bearer unavailable')).status).toBe(503);
      expect((await initialize(resource, 'Bearer active')).status).toBe(200);
    });
  });
});
