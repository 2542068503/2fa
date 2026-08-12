export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // API Endpoint for Cloud KV 2FA Vault Sync
    if (url.pathname === '/api/sync') {
      const kv = env.VAULT_KV;
      const authHeader = request.headers.get('Authorization') || '';
      
      if (!authHeader.startsWith('Bearer ')) {
        return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
          status: 401,
          headers: { 
            'Content-Type': 'application/json', 
            'Access-Control-Allow-Origin': '*',
            'Date': new Date().toUTCString()
          }
        });
      }

      const token = authHeader.substring(7);

      if (request.method === 'GET') {
        let data = null;
        if (kv) {
          const existing = await kv.get('vault:singleton', { type: 'json' });
          if (existing) {
            data = existing.payload;
          }
        }
        return new Response(JSON.stringify({ data }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Date': new Date().toUTCString(),
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store',
            'Vary': 'Authorization'
          }
        });
      }

      if (request.method === 'POST') {
        try {
          const body = await request.json();
          const { payload, newAuthHash } = body;

          if (kv && payload) {
            const existing = await kv.get('vault:singleton', { type: 'json' });
            
            // If vault exists, verify the old authHash matches the Authorization token
            if (existing && existing.authHash && existing.authHash !== token) {
              return new Response(
                JSON.stringify({ error: 'UNAUTHORIZED_HASH' }),
                {
                  status: 401,
                  headers: { 
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                  }
                }
              );
            }

            // Save new payload and either the newAuthHash (if changing password) or the existing token
            const vaultData = {
              authHash: newAuthHash || token,
              payload: payload
            };

            await kv.put('vault:singleton', JSON.stringify(vaultData));
          }

          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { 
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      }

      if (request.method === 'OPTIONS') {
        return new Response(null, {
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
          }
        });
      }
    }

    // Serve Static Assets for all non-API routes
    return env.ASSETS.fetch(request);
  }
};
