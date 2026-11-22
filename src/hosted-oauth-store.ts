import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import type { OAuthClientInformationFull } from '../node_modules/@modelcontextprotocol/sdk/dist/cjs/shared/auth';

const grantSchema = z.object({
  clientId: z.string(),
  scopes: z.array(z.string()),
  authorizationId: z.string(),
  expiresAt: z.number().finite(),
});

export type StoredGrant = z.infer<typeof grantSchema>;

type OAuthState = {
  clients: Map<string, OAuthClientInformationFull>;
  access: Map<string, StoredGrant>;
  refresh: Map<string, StoredGrant>;
};

const entryKey = z.string().regex(/^[a-f0-9]{64}$/);
const stateSchema = z.object({
  version: z.literal(1),
  resource: z.string(),
  clients: z.array(z.object({
    client_id: z.string(),
    client_id_issued_at: z.number().optional(),
    client_name: z.string().optional(),
    redirect_uris: z.array(z.string()).min(1),
    token_endpoint_auth_method: z.literal('none'),
    grant_types: z.array(z.string()),
    response_types: z.array(z.string()),
  })),
  access: z.array(z.tuple([entryKey, grantSchema])),
  refresh: z.array(z.tuple([entryKey, grantSchema])),
});

export function openHostedOAuthStore(file: string, resource: string) {
  const filename = path.resolve(file);
  let state: OAuthState;
  let initialize = false;
  try {
    const stored = stateSchema.parse(JSON.parse(readFileSync(filename, 'utf8')));
    if (stored.resource !== resource) throw new Error(`OAuth state at ${filename} belongs to a different MCP_PUBLIC_URL`);
    state = {
      clients: new Map(stored.clients.map((client) => [client.client_id, client])),
      access: new Map(stored.access),
      refresh: new Map(stored.refresh),
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw new Error(`Cannot load hosted OAuth state at ${filename}: ${error instanceof Error ? error.message : String(error)}`);
    }
    initialize = true;
    state = { clients: new Map(), access: new Map(), refresh: new Map() };
  }

  function save(next: OAuthState): void {
    const temporary = `${filename}.${randomUUID()}.tmp`;
    try {
      writeFileSync(temporary, JSON.stringify({
        version: 1,
        resource,
        clients: [...next.clients.values()],
        access: [...next.access],
        refresh: [...next.refresh],
      }), { mode: 0o600, flag: 'wx', flush: true });
      renameSync(temporary, filename);
    } finally {
      rmSync(temporary, { force: true });
    }
  }

  mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  if (initialize) save(state);

  return {
    get state(): OAuthState {
      return state;
    },
    update(change: (next: OAuthState) => void): void {
      const next = {
        clients: new Map(state.clients),
        access: new Map(state.access),
        refresh: new Map(state.refresh),
      };
      change(next);
      save(next);
      state = next;
    },
  };
}
