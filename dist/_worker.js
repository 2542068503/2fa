export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // API Endpoint for Cloud KV 2FA Vault Sync
    if (url.pathname === '/api/sync') {
      const kv = env.VAULT_KV;
      const authHeader = request.headers.get('Authorization') || '';

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

      const token = authHeader.substring(7).trim();

      // Check if ADMIN environment variable is configured in Cloudflare Pages
      if (!env.ADMIN) {
        return new Response(JSON.stringify({ error: 'MISSING_ENV_ADMIN', message: 'Cloudflare Pages 未配置 ADMIN 环境变量' }), {
          status: 500,
          headers: { 
            'Content-Type': 'application/json', 
            'Date': new Date().toUTCString(),
            ...corsHeaders
          }
        });
      }

      const expectedAdmin = String(env.ADMIN).trim();

      // Strict Server-Side Authentication against env.ADMIN
      if (token !== expectedAdmin) {
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
          const { payload } = body;

          if (kv && payload) {
            // Save payload directly to singleton namespace
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
    }

    // Serve Static Assets for all non-API routes
    return env.ASSETS.fetch(request);
  }
};
