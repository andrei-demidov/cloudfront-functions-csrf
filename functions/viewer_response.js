/*
A stateless and serverless CSRF protection solution for Amazon CloudFront.

This function must be triggered on *Viewer Response* event.

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
// The signing algorithm; currently only HS256 is supported by CloudFront
var signingAlg = "HS256";
// The length of the token
var tokenLength = 32;
// The name of the cookie that contains the token
// It should start with the "__Host-" prefix to lock the cookie to the domain
var csrfTokenCookieName = "__Host-csrf_token";

// Function that cryptographically signs a string.
function signString(input, key, alg) {
    if (alg === "HS256") {
        return crypto.createHmac('sha256', key).update(input).digest('base64url');
    } else {
        throw new Error("Signing algorithm '" + alg + "' is not recognized.");
    }
}

// Function that generates a pseudo-random string
function getRandomString(length) {
    var characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    var token = "";
    for (var i = 0; i < length; i++) {
        token += characters[Math.floor(Math.random() * characters.length)];
    }
    return token;
}

// Function that creates a signed CSRF token.
function createCsrfToken(length, key, alg) {
    var token = getRandomString(length);
    var signature = signString(token, key, alg);
    return token + "." + signature;
}

function handler(event) {
    var response = event.response;

    // Creating a new CSRF token for each request.
    var csrfToken = createCsrfToken(tokenLength, signingKey, signingAlg);
    // Sending the token to the viewer as a cookie with the following parameters:
    // 1. "Secure" — it will only be sent to the server via HTTPS;
    // 2. "SameSite=Strict" — it will only be sent to the server in a first-party context 
    // (i.e., if the site for the cookie matches the site currently shown in the browser's 
    // URL bar)
    // 3. No domain is specified and the name of the cookies starts with "__Host-" which 
    // means that this cookie won't be accessible from subdomains
    response.cookies[csrfTokenCookieName] = {
        value: csrfToken,
        attributes: "Secure; SameSite=Strict; Path=/"
    };

    return response;
}