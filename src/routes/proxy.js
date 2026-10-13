import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { randomUUID } from 'node:crypto';

const sessions = new Map();
const sessionLifetime = 60 * 60 * 1000;
const maxScriptLength = 64 * 1024;

function isPublicAddress(address) {
    if (isIP(address) === 4) {
        const octets = address.split('.').map(Number);
        const [first, second, third] = octets;

        return !(first === 0 || first === 10 || first === 127 || first >= 224 ||
            (first === 100 && second >= 64 && second <= 127) ||
            (first === 169 && second === 254) ||
            (first === 172 && second >= 16 && second <= 31) ||
            (first === 192 && (second === 0 || second === 168) && (second !== 0 || third === 0)) ||
            (first === 198 && (second === 18 || second === 19 || (second === 51 && third === 100))));
    }

    if (isIP(address) === 6) {
        const normalized = address.toLowerCase();
        return !(normalized === '::' || normalized === '::1' || normalized.startsWith('fc') ||
            normalized.startsWith('fd') || /^fe[89ab]/.test(normalized) || normalized.startsWith('ff') ||
            normalized.startsWith('::ffff:'));
    }

    return false;
}

async function validateTarget(value) {
    let target;
    try {
        target = new URL(value);
    } catch {
        throw new Error('Enter a valid absolute URL.');
    }

    if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password)
        throw new Error('Only public HTTP and HTTPS URLs are supported.');

    const hostname = target.hostname.toLowerCase();
    if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal'))
        throw new Error('Local and private network addresses are not available through this proxy.');

    const addresses = isIP(hostname) ? [{ address: hostname }] : await lookup(hostname, { all: true });
    if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address)))
        throw new Error('Local and private network addresses are not available through this proxy.');

    return target;
}

function getSessionId(req) {
    const cookie = req.headers.cookie?.split(';').map((part) => part.trim()).find((part) => part.startsWith('proxy.sid='));
    return cookie?.slice('proxy.sid='.length);
}

function proxiedUrl(target) {
    return `/proxy?url=${encodeURIComponent(target.href)}`;
}

function rewriteCss(css, baseUrl) {
    return css.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (match, quote, value) => {
        if (/^(data:|blob:|#|javascript:)/i.test(value)) return match;
        try {
            return `url(${quote}${proxiedUrl(new URL(value, baseUrl))}${quote})`;
        } catch {
            return match;
        }
    }).replace(/@import\s+(['"])(.*?)\1/gi, (match, quote, value) => {
        try {
            return `@import ${quote}${proxiedUrl(new URL(value, baseUrl))}${quote}`;
        } catch {
            return match;
        }
    });
}

function rewriteHtml(html, target, script) {
    html = html.replace(/\b(href|src|action|poster|data|formaction)\s*=\s*(["'])(.*?)\2/gi, (match, name, quote, value) => {
        if (/^(#|data:|blob:|javascript:|mailto:|tel:)/i.test(value)) return match;
        try {
            return `${name}=${quote}${proxiedUrl(new URL(value.replace(/&amp;/g, '&'), target))}${quote}`;
        } catch {
            return match;
        }
    });

    html = html.replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style\s*>)/gi, (_, start, css, end) => `${start}${rewriteCss(css, target)}${end}`);
    html = html.replace(/\bstyle=(['"])(.*?)\1/gi, (_, quote, css) => `style=${quote}${rewriteCss(css, target)}${quote}`);

    if (script) {
        const safeScript = JSON.stringify(script).replace(/</g, '\\u003c');
        const injected = `<script>eval(${safeScript})</script>`;
        if (/<\/head\s*>/i.test(html)) html = html.replace(/<\/head\s*>/i, `${injected}</head>`);
        else html = `${injected}${html}`;
    }

    return html;
}

function isSameOriginPost(req) {
    try {
        return new URL(req.get('origin')).host === req.get('host');
    } catch {
        return false;
    }
}

export default async (req, res) => {
    try {
        if (req.method === 'POST' && typeof req.query.url !== 'string') {
            if (!isSameOriginPost(req)) return res.status(403).send('Cross-origin requests are not allowed.');

            const script = typeof req.body.script === 'string' ? req.body.script : '';
            if (script.length > maxScriptLength) return res.status(413).send('JavaScript must be 64 KB or smaller.');

            let target;
            try {
                target = await validateTarget(req.body.url);
            } catch (error) {
                return res.status(400).send(error.message);
            }

            let sessionId = getSessionId(req);
            if (!sessionId) sessionId = randomUUID();
            sessions.set(sessionId, { script, updated: Date.now() });
            res.cookie('proxy.sid', sessionId, { httpOnly: true, sameSite: 'lax', secure: req.secure, path: '/proxy' });
            return res.redirect(303, proxiedUrl(target));
        }

        if (!['GET', 'HEAD', 'POST'].includes(req.method)) return res.status(405).send('Method not allowed.');

        const targetValue = req.query.url;
        if (typeof targetValue !== 'string') return res.status(400).send('A URL is required.');

        let target;
        try {
            target = await validateTarget(targetValue);
        } catch (error) {
            return res.status(400).send(error.message);
        }
        const now = Date.now();
        for (const [id, session] of sessions) {
            if (now - session.updated > sessionLifetime) sessions.delete(id);
        }

        const sessionId = getSessionId(req);
        const session = sessions.get(sessionId);
        if (session) session.updated = now;

        const requestOptions = { method: req.method, redirect: 'manual', signal: AbortSignal.timeout(15000) };
        if (req.method === 'POST') {
            const contentType = req.get('content-type') || '';
            if (Buffer.isBuffer(req.body)) {
                requestOptions.body = req.body;
            } else if (contentType.includes('application/x-www-form-urlencoded')) {
                requestOptions.body = new URLSearchParams(req.body || {}).toString();
            } else if (contentType.includes('application/json')) {
                requestOptions.body = JSON.stringify(req.body || {});
            } else if (Number(req.get('content-length') || 0) > 0) {
                return res.status(415).send('This form submission type is not supported.');
            }
            if (contentType) requestOptions.headers = { 'content-type': contentType };
        }

        const response = await fetch(target, requestOptions);
        if ([301, 302, 303, 307, 308].includes(response.status) && response.headers.has('location')) {
            const redirectTarget = await validateTarget(new URL(response.headers.get('location'), target).href);
            return res.redirect(response.status, proxiedUrl(redirectTarget));
        }

        const contentType = response.headers.get('content-type') || 'application/octet-stream';
        res.status(response.status).set('content-type', contentType);

        if (contentType.includes('text/html')) {
            const html = rewriteHtml(await response.text(), target, session?.script || '');
            return res.send(html);
        }
        if (contentType.includes('text/css')) {
            return res.send(rewriteCss(await response.text(), target));
        }

        return res.send(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
        console.error('proxy request failed:', error);
        if (!res.headersSent) res.status(502).send('The requested website could not be loaded.');
    }
};