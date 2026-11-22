import { Readable } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';
import { z } from 'zod';

const maxUploadBytes = 8 * 1024 * 1024;
const maxStreamBytes = 8 * 1024 * 1024;
const idleTimeoutMs = 30_000;

export const uploadSchema = z.object({
  filename: z.string().min(1),
  data: z.string().max(Math.ceil(maxUploadBytes / 3) * 4).regex(/^[A-Za-z0-9+/]*={0,2}$/)
    .refine((data) => {
      const decoded = Buffer.from(data, 'base64');
      return decoded.length <= maxUploadBytes && decoded.toString('base64').replace(/=+$/, '') === data.replace(/=+$/, '');
    }, 'Invalid base64 or upload exceeds 8 MiB')
    .describe('File content encoded as base64'),
  contentType: z.string().optional(),
});

export function formBody(
  values: Record<string, unknown>,
  multipart: boolean,
  fileFields: Set<string>,
): FormData | URLSearchParams {
  const form = multipart ? new FormData() : new URLSearchParams();
  for (const [name, value] of Object.entries(values)) {
    for (const item of Array.isArray(value) ? value : [value]) {
      if (item == null) continue;
      if (form instanceof FormData && fileFields.has(name)) {
        const file = uploadSchema.parse(item);
        form.append(name, new Blob([Buffer.from(file.data, 'base64')], {
          type: file.contentType ?? 'application/octet-stream',
        }), file.filename);
      } else {
        form.append(name, typeof item === 'object' ? JSON.stringify(item) : String(item));
      }
    }
  }
  return form;
}

export function encodePathValue(value: unknown, allowSlashes: boolean): string {
  const text = String(value);
  const segments = text.split('/');
  if (segments.some((segment) => segment === '.' || segment === '..')) {
    throw new Error('Path parameters cannot contain dot segments');
  }
  return allowSlashes ? segments.map(encodeURIComponent).join('/') : encodeURIComponent(text);
}

export async function readUpstreamResponse(
  value: unknown,
  eventStream: boolean,
  onEvent?: (event: string, count: number) => Promise<void>,
): Promise<unknown> {
  if (!(value instanceof Readable)) return value;

  const decoder = new StringDecoder('utf8');
  let bytes = 0;
  let text = '';
  let pending = '';
  let count = 0;
  let timer: NodeJS.Timeout | undefined;
  function resetIdleTimer() {
    clearTimeout(timer);
    timer = setTimeout(() => value instanceof Readable && value.destroy(new Error('Upstream stream timed out')), idleTimeoutMs);
    timer.unref();
  }
  resetIdleTimer();
  try {
    for await (const chunk of value) {
      resetIdleTimer();
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.length;
      if (eventStream && bytes > maxStreamBytes) throw new Error('Upstream event stream exceeded 8 MiB');
      const decoded = decoder.write(buffer);
      text += decoded;
      if (eventStream) {
        const events = (pending + decoded).split(/\r\n\r\n|\n\n|\r\r/);
        pending = events.pop() ?? '';
        for (const event of events) {
          if (/^data:/m.test(event)) await onEvent?.(event, ++count);
        }
        if (events.some((event) => /^data:[ \t]*\[DONE\][ \t]*$/m.test(event))) break;
      }
    }
    text += decoder.end();
  } finally {
    clearTimeout(timer);
    value.destroy();
  }
  if (!eventStream && text) {
    try { return JSON.parse(text); } catch { return text; }
  }
  return text;
}
