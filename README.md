# VeilBrowse

A browser-style privacy proxy designed around a simple principle:

> Browsing data should not be persistently stored by the proxy.

## Current architecture

- Express server
- Streaming responses for non-HTML resources
- HTML/CSS URL rewriting
- No persistent database
- No server-side browsing history
- No server-side cookie jar
- No analytics
- No response cache
- `Cache-Control: no-store`
- Basic SSRF protection for private/local destinations
- 30-second upstream timeout

## Important privacy limitation

"No data stored" does **not** mean anonymous browsing.

The destination website can still receive request information, and the hosting provider/network infrastructure may retain logs outside this application's control. This project intentionally does not add its own application-level history, analytics, cookies, or cache.

## Development

```bash
npm install
npm run dev
```

Then open `http://localhost:3000`.

## Roadmap

1. Improve URL rewriting and navigation compatibility.
2. Add robust cookie isolation without persistent storage.
3. Handle redirects and forms consistently.
4. Improve JavaScript compatibility for modern sites.
5. Add stronger SSRF/DNS-rebinding protection.
6. Add security headers and content isolation.
7. Add automated integration tests for common websites.
8. Optimize connection reuse and streaming latency.

This is a privacy-oriented browsing tool, not a guarantee of anonymity or protection from malicious websites.
