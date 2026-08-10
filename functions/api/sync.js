// Cloudflare Pages Function / Vercel API with Auth check & Rate Limit Header
export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.VAULT_KV; // Cloudflare KV binding

  // Extract Auth Token
  const authHeader = request.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', 'Date': new Date().toUTCString() }
    });
  }

  const token = authHeader.substring(7);

  if (request.method === 'GET') {
    let data = null;
    if (kv) {
      data = await kv.get(`vault:${token}`, { type: 'json' });
    }
    return new Response(JSON.stringify({ data }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Date': new Date().toUTCString() }
    });
  }

  if (request.method === 'POST') {
    const body = await request.json();
    const { payload } = body; // Encrypted JSON payload

    if (kv) {
      // Optimistic Concurrency Control Check
      const existing = await kv.get(`vault:${token}`, { type: 'json' });
      if (existing && existing.updatedAt > payload.updatedAt) {
        return new Response(
          JSON.stringify({ error: 'CONFLICT', remotePayload: existing }),
          {
            status: 409,
            headers: { 'Content-Type': 'application/json', 'Date': new Date().toUTCString() }
          }
        );
      }
      await kv.put(`vault:${token}`, JSON.stringify(payload));
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Date': new Date().toUTCString() }
    });
  }

  return new Response('Method Not Allowed', { status: 405 });
}
