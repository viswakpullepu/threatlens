export default async function handler(req, res) {
  try {
    const { handleRequest } = await import('../server.mjs');
    return await handleRequest(req, res);
  } catch (err) {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      status: 'VERCEL_HANDLER_DEBUG',
      error: err.message,
      stack: err.stack,
      url: req.url
    }));
  }
}

