export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    let targetUrl;
    if (url.pathname.includes('/health')) {
      return new Response(JSON.stringify({status: 'ok'}), {
        headers: {'Content-Type': 'application/json'}
      });
    } else if (url.pathname.includes('/quote')) {
      targetUrl = 'https://api.jup.ag/swap/v1/quote' + url.search;
    } else if (url.pathname.includes('/swap')) {
      targetUrl = 'https://api.jup.ag/swap/v1/swap';
    } else {
      return new Response('Not found', {status: 404});
    }
    
    const response = await fetch(targetUrl, {
      method: request.method,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: request.method !== 'GET' ? await request.text() : undefined,
    });
    
    const text = await response.text();
    return new Response(text, {
      status: response.status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }
};