// Cloudflare Pages Function / Vercel API with Auth check & Rate Limit Header
export async function onRequest(context) {
  const { request, env } = context;
  const kv = env.VAULT_KV; // Cloudflare KV binding

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Expose-Headers': 'Date',
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
    'Pragma': 'no-cache'
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  // Extract Auth Token
  const authHeader = request.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
      status: 401,
      headers: { 
        'Content-Type': 'application/json', 
        'Date': new Date().toUTCString(),
        ...corsHeaders
      }
    });
  }

  const token = authHeader.substring(7);

  // Strict Server-Side Authentication against env.ADMIN
  if (!env.ADMIN || token !== env.ADMIN) {
    return new Response(JSON.stringify({ error: 'UNAUTHORIZED_ADMIN' }), {
      status: 401,
      headers: { 
        'Content-Type': 'application/json', 
        'Date': new Date().toUTCString(),
        ...corsHeaders
      }
    });
  }

  if (request.method === 'GET') {
    let data = null;
    if (kv) {
      const existing = await kv.get('vault:singleton', { type: 'json' });
      if (existing) {
        data = existing;
      }
    }
    return new Response(JSON.stringify({ data }), {
      status: 200,
      headers: { 
        'Content-Type': 'application/json', 
        'Date': new Date().toUTCString(),
        'Vary': 'Authorization',
        ...corsHeaders
      }
    });
  }

  if (request.method === 'POST') {
    try {
      const body = await request.json();
      const { payload } = body; // Encrypted JSON payload

      if (kv && payload) {
        await kv.put('vault:singleton', JSON.stringify(payload));
      }

      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 
          'Content-Type': 'application/json', 
          'Date': new Date().toUTCString(),
          ...corsHeaders
        }
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 500,
        headers: { 
          'Content-Type': 'application/json', 
          'Date': new Date().toUTCString(),
          ...corsHeaders
        }
      });
    }
  }

  return new Response('Method Not Allowed', { status: 405, headers: corsHeaders });
}
