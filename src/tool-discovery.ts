import path from 'node:path';
import { z } from 'zod';
import type { ToolFromOpenApi } from './openapi-to-tools';

const { toJsonSchemaCompat } = require(path.join(
  __dirname, '..', 'node_modules', '@modelcontextprotocol', 'sdk', 'dist/cjs/server/zod-json-schema-compat.js',
)) as {
  toJsonSchemaCompat: (schema: z.ZodObject<z.ZodRawShape>, options: {
    strictUnions: boolean;
    pipeStrategy: 'input';
  }) => Record<string, unknown>;
};

function formatResult(value: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value) }] };
}

function errorResult(message: string) {
  return { ...formatResult({ error: message }), isError: true };
}

export function createDiscoveredTools(
  catalog: ToolFromOpenApi[],
  defaultNames: string[],
): ToolFromOpenApi[] {
  const byName = new Map(catalog.map((tool) => [tool.name, tool]));
  const defaults = new Set(defaultNames);
  const visibleTools = catalog.filter(({ name }) => defaults.has(name));
  const entries = catalog.map((tool) => ({
    tool,
    name: tool.name.toLowerCase(),
    description: tool.description.toLowerCase(),
  }));

  function availableName(base: string): string {
    let name = base;
    for (let suffix = 2; byName.has(name); suffix++) name = `${base}_${suffix}`;
    return name;
  }

  const searchName = availableName('search_tools');
  const callName = availableName('call_tool');
  const searchSchema = z.object({
    query: z.string().trim().min(1).max(200).describe('Keywords for the operation you want to perform.'),
    limit: z.number().int().min(1).max(10).optional().describe('Maximum matches. Defaults to 5.'),
  });
  const callSchema = z.object({
    name: z.string().min(1).max(128).describe(`Exact tool name returned by ${searchName}.`),
    arguments: z.record(z.unknown()).optional().describe('Arguments matching the tool inputSchema.'),
  });

  return [
    ...visibleTools,
    {
      name: searchName,
      description: `Search available API tools by name or keywords. Results include each tool's input schema. Use ${callName} to invoke a result.`,
      inputSchema: searchSchema,
      async handler(args) {
        const { query, limit = 5 } = searchSchema.parse(args);
        const text = query.toLowerCase();
        const terms = [...new Set(text.match(/[a-z0-9]+/g) ?? [text])];
        const matches = entries.map((entry) => {
          let score = entry.name === text ? 1000 : 0;
          for (const term of terms) {
            if (entry.name.includes(term)) score += 4;
            else if (entry.description.includes(term)) score++;
          }
          return { tool: entry.tool, score };
        }).filter(({ score }) => score > 0).sort((a, b) => b.score - a.score);
        return formatResult({
          total: matches.length,
          tools: matches.slice(0, limit).map(({ tool }) => ({
            name: tool.name,
            description: tool.description,
            inputSchema: toJsonSchemaCompat(tool.inputSchema, { strictUnions: true, pipeStrategy: 'input' }),
          })),
        });
      },
    },
    {
      name: callName,
      description: `Run an API tool discovered through ${searchName}. Use the exact name and supply arguments that match its input schema.`,
      inputSchema: callSchema,
      async handler(args, context) {
        const { name, arguments: input = {} } = callSchema.parse(args);
        const tool = byName.get(name);
        if (!tool) return errorResult(`Unknown tool "${name}". Search for an available tool using ${searchName}.`);
        const parsed = tool.inputSchema.safeParse(input);
        if (!parsed.success) {
          return errorResult(parsed.error.issues.map((issue) =>
            `${issue.path.join('.') || 'arguments'}: ${issue.message}`,
          ).join('; '));
        }
        return tool.handler(parsed.data, context);
      },
    },
  ];
}
