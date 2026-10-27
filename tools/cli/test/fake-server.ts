import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface Seen {
  method: string;
  path: string;
  authorization: string | undefined;
  body: unknown;
}

export interface Fake {
  url: string;
  seen: Seen[];
  /** Next response; default is 200 {ok:true}. */
  reply: (status: number, body: unknown) => void;
  close: () => Promise<void>;
}

export async function startFake(): Promise<Fake> {
  const seen: Seen[] = [];
  let next: { status: number; body: unknown } = { status: 200, body: { ok: true } };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      seen.push({
        method: req.method ?? '',
        path: req.url ?? '',
        authorization: req.headers.authorization,
        body: raw === '' ? undefined : JSON.parse(raw),
      });
      res.writeHead(next.status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(next.body));
      next = { status: 200, body: { ok: true } };
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    seen,
    reply: (status, body) => {
      next = { status, body };
    },
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
