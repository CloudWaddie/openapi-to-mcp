import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

  describe('MCP over HTTP', () => {
    const servers: Server[] = [];
    const temporaryDirectories: string[] = [];

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
      for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
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

    it('lists default tools and lets clients discover and call other allowed tools', async () => {
      const handler = jest.fn(async ({ city }: Record<string, unknown>, context?: Parameters<ToolFromOpenApi['handler']>[1]) => {
        await context?.onEvent?.('data: forecast pending', 1);
        return { content: [{ type: 'text' as const, text: `Forecast for ${city}` }] };
      });
      const hiddenTool: ToolFromOpenApi = {
        name: 'weather_forecast',
        description: 'Look up the weather for a city',
        inputSchema: z.object({ city: z.string() }),
        handler,
      };
      const app = createMcpApp({
        ...baseConfig,
        toolDiscovery: true,
        defaultToolNames: [mockTool.name],
        mcpAuth: { mode: 'bearer', token: 'discovery-token' },
      }, [mockTool, hiddenTool]);
      const url = (await listen(createServer(app))) + '/mcp';

      const notifications: unknown[] = [];
      async function request(method: string, params?: Record<string, unknown>) {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            Authorization: 'Bearer discovery-token',
            Accept: 'application/json, text/event-stream',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        });
        expect(response.status).toBe(200);
        const body = await response.text();
        const messages = body.split('\n').filter((line) => line.startsWith('data: ')).map((line) => JSON.parse(line.slice(6)));
        notifications.push(...messages.filter((message) => message.method === 'notifications/progress'));
        return messages.length ? messages.at(-1) : JSON.parse(body);
      }

      const list = await request('tools/list');
      expect(list.result.tools.map(({ name }: { name: string }) => name)).toEqual(['test_tool', 'search_tools', 'call_tool']);
      const search = await request('tools/call', { name: 'search_tools', arguments: { query: 'weather forecast' } });
      expect(JSON.parse(search.result.content[0].text).tools).toEqual([
        expect.objectContaining({
          name: hiddenTool.name,
          inputSchema: expect.objectContaining({ required: ['city'] }),
        }),
      ]);
      const invalid = await request('tools/call', { name: 'call_tool', arguments: { name: hiddenTool.name } });
      expect(invalid.result.isError).toBe(true);
      const unknown = await request('tools/call', { name: 'call_tool', arguments: { name: 'unavailable' } });
      expect(unknown.result.isError).toBe(true);
      expect(handler).not.toHaveBeenCalled();
      const valid = await request('tools/call', {
        name: 'call_tool', arguments: { name: hiddenTool.name, arguments: { city: 'Adelaide' } }, _meta: { progressToken: 'forecast' },
      });
      expect(valid.result.content[0].text).toBe('Forecast for Adelaide');
      expect(handler).toHaveBeenCalledWith({ city: 'Adelaide' }, expect.any(Object));
      expect(notifications).toContainEqual(expect.objectContaining({
        method: 'notifications/progress',
        params: { progressToken: 'forecast', progress: 1, message: 'data: forecast pending' },
      }));
    });

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

    it('runs hosted OAuth and preserves clients and token rotation across restarts', async () => {
      const server = createServer();
      const origin = await listen(server);
      const directory = mkdtempSync(join(tmpdir(), 'mcp-oauth-test-'));
      temporaryDirectories.push(directory);
      const storeFile = join(directory, 'oauth-state.json');
      const config: McpConfig = {
        ...baseConfig,
        mcpAuth: { mode: 'hosted-oauth', password: 'owner-test-password', publicUrl: origin, storeFile },
      };
      const app = createMcpApp(config, [mockTool]);
      expect(app.get('trust proxy')).toBe(1);
      server.on('request', app);
      const resource = origin + '/mcp';
      const post = (path: string, params: Record<string, string>, requestOrigin = origin) => fetch(origin + path, {
        method: 'POST', body: new URLSearchParams(params), redirect: 'manual',
        headers: { Origin: requestOrigin, 'X-Forwarded-For': '192.0.2.10' },
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
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '192.0.2.10' },
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
      expect(page.headers.get('referrer-policy')).toBe('origin');
      const approval = (await page.text()).match(/name="approval" value="([^"]+)"/)?.[1];
      expect(approval).toBeDefined();
      const denied = await post('/approve', { approval: approval!, password: 'wrong-password' });
      expect(denied.status).toBe(403);
      const crossOrigin = await post('/approve', { approval: approval!, password: 'owner-test-password' }, 'https://other.example');
      expect(crossOrigin.status).toBe(403);
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

      const persisted = readFileSync(storeFile, 'utf8');
      expect(persisted).toContain(client.client_id);
      expect(persisted).not.toContain(tokens.access_token);
      expect(persisted).not.toContain(tokens.refresh_token);
      server.removeAllListeners('request');
      server.on('request', createMcpApp(config, [mockTool]));
      expect((await initialize(resource, `Bearer ${tokens.access_token}`)).status).toBe(200);

      const refresh = { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: tokens.refresh_token, resource };
      const refreshed = await post('/token', refresh);
      expect(refreshed.status).toBe(200);
      const rotated = await refreshed.json() as { refresh_token: string };
      expect(rotated.refresh_token).not.toBe(tokens.refresh_token);
      server.removeAllListeners('request');
      server.on('request', createMcpApp(config, [mockTool]));
      expect((await post('/token', refresh)).status).toBe(400);
      expect((await post('/token', { ...refresh, refresh_token: rotated.refresh_token })).status).toBe(200);
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
