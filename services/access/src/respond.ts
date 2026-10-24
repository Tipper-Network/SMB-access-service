import type { FastifyReply } from 'fastify';

// Handlers run their database work inside a transaction and RETURN an outcome. The HTTP
// response is sent only after the transaction has committed. Never call reply.send() inside
// a transaction callback: the client could see "201 Created" for a write that later rolls back.

export interface Outcome {
  status: number;
  body: unknown;
}

/** Successful outcome. The HTTP response is not sent until `respond` runs after the transaction commits. */
export const ok = (body: unknown, status = 200): Outcome => ({ status, body });
/** Error outcome. `error` is a stable code, not a database message. */
export const fail = (status: number, error: string): Outcome => ({ status, body: { error } });

/**
 * Sends the outcome after `work` resolves. Call this around a transaction so a rollback cannot follow a 201.
 * @param reply - Fastify reply
 * @param work - Transaction that returns an `Outcome`
 */
export async function respond(reply: FastifyReply, work: Promise<Outcome>) {
  const out = await work;
  return reply.code(out.status).send(out.body);
}
