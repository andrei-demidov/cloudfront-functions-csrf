/*
A stateless and serverless CSRF protection solution for Amazon CloudFront.

This function must be triggered on *Viewer Request* event.

Customizing at the edge with CloudFront Functions
https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html

JavaScript runtime features for CloudFront Functions
https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-javascript-runtime-features.html
*/

var crypto = require('crypto');

// The signing key. The minimum length for an SHA-256 HMAC key is 32 bytes. A key longer than 32 
// bytes does not significantly increase the function strength unless the randomness of the key 
// is considered weak.
var signingKey = "PUT_YOUR_SECRET_KEY_HERE";
// A list of paths to exclude from the CSRF protection.
// It is needed for paths that receive callbacks from any external services via
// "unsafe" methods (see below).
var excludePaths = [];
// In debug mode, log messages will be sent to the console.
var debug = false;
// The signing algorithm; currently only HS256 is supported by CloudFront.
var signingAlg = "HS256";
// The GET and other "safe" requests are ignored since these requests ought never 
// to have any potentially dangerous side effects and a CSRF attack with a GET request 
// ought to be harmless.
var csrfRequestMethods = ['POST', 'PUT', 'DELETE', 'PATCH'];
// The name of the csrf header parameter.
var csrfTokenHeaderName = "x-csrf-token";
// The name of the csrf url query parameter if it's not sent in headers.
var csrfTokenQuerystringName = "csrf_token";
// The name of the cookie that contains the token.
// It should start with the "__Host-" prefix to lock the cookie to the domain.
var csrfTokenCookieName = "__Host-csrf_token";

// If CSRF verification fails, HTTP 403 will be returned.
var response403 = {
    statusCode: 403,
    statusDescription: "Forbidden"
};

// Function that sends messages to console in debug mode.
function debugMessage(message) {
    if (debug) {
        console.log(message);
    }
}

// Function that cryptographically signs a string.
function signString(input, key, alg) {
    if (alg === "HS256") {
        return crypto.createHmac('sha256', key).update(input).digest('base64url');
    } else {
        throw new Error("Signing algorithm '" + alg + "' is not recognized.");
    }
}

// Function that validates a token.
function validateCsrfToken(token, key, alg) {
    var parts = token.split(".");
    if (parts.length === 2 && parts[0] && signString(parts[0], key, alg) === parts[1]) {
        return true;
    }
    return false;
}

// Function that verifies that the request came from an allowed origin.
function verifyOrigin(request) {
    // The host header must be present in the request.
    if (!('host' in request.headers)) {
        return false;
    }
    
    // CSRF validation fails if the request came from an origin other then the
    // current one which is specified in the host header of the request.
    var allowed_origin = 'https://' + request.headers['host'].value + '/';
    var provided_origin = null;
    
    if ('origin' in request.headers && request.headers['origin'].value 
        && request.headers['origin'].value !== 'null') {
        // The Origin request header indicates the origin (scheme, hostname, 
        // and port) that caused the request. For example, if a user agent needs to 
        // request resources included in a page, or fetched by scripts that it executes, 
        // then the origin of the page may be included in the request.
        //
        // Origin: null
        // Origin: <scheme>://<hostname>
        // Origin: <scheme>://<hostname>:<port></port>
        //
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin
        provided_origin = request.headers['origin'].value + '/';
    } else if ('referer' in request.headers && request.headers['referer'].value) {
        // The Referer HTTP request header contains the absolute or partial address
        // from which a resource has been requested.
        //
        // Referer: https://developer.mozilla.org/en-US/docs/Web/JavaScript
        // Referer: https://example.com/page?q=123
        // Referer: https://example.com/
        //
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
        provided_origin = request.headers['referer'].value.substring(0, allowed_origin.length);
    }
    
    if (provided_origin && provided_origin !== allowed_origin) {
        return false
    }
    
    return true;
}

// Function that removes the CSRF tokens from the request before it's 
// forwarded to the origin.
function removeCsrfTokensFromRequest(request) {
    if (csrfTokenCookieName in request.cookies) {
        delete request.cookies[csrfTokenCookieName];
    }
    if (csrfTokenHeaderName in request.headers) {
        delete request.headers[csrfTokenHeaderName];
    }
    if (csrfTokenQuerystringName in request.querystring) {
        delete request.querystring[csrfTokenQuerystringName];
    }
}

function handler(event) {
    var request = event.request;
    
    // CSRF protection is implemented only for the "unsafe" methods; some paths may be excluded.
    if (csrfRequestMethods.includes(request.method) && !excludePaths.includes(request.uri)) {
        // Verifying the Origin
        if (!verifyOrigin(request)) {
            debugMessage("Origin mismatch.");
            return response403;
        }

        try {
            // CSRF cookie must be provided.
            var csrfTokenCookie = request.cookies[csrfTokenCookieName].value;
        } catch (e) {
            debugMessage("CSRF cookie wasn't provided.");
            return response403;
        }

        try {
            // First check if there's CSRF token in headers.
            var csrfTokenRequest = request.headers[csrfTokenHeaderName].value;
        } catch (e) {
            // No CSRF token in headers; checking the querystring.
            try {
                var csrfTokenRequest = request.querystring[csrfTokenQuerystringName].value;
            } catch (e) {
                debugMessage("CSRF token header/querystring parameter wasn't provided.");
                return response403;
            }
        }
        
        var isTokenValid = validateCsrfToken(csrfTokenCookie, signingKey, signingAlg);
        if (!isTokenValid || csrfTokenCookie !== csrfTokenRequest) {
            debugMessage("CSRF verification failed.");
            return response403;
        }
    }
    
    // Remove the token from cookies, headers and query string so it won't 
    // be forwarded to the origin.
    removeCsrfTokensFromRequest(request);
    
    return request;
}