# cloudfront-functions-csrf

This is a stateless and serverless implementation of a protection against [Cross Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf) — an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated.

The code is writted in JavaScript and can be deployed on [Amazon CloudFront](https://aws.amazon.com/cloudfront/) with [CloudFront Functions](https://aws.amazon.com/blogs/aws/introducing-cloudfront-functions-run-your-code-at-the-edge-with-low-latency-at-any-scale/).

## Installation

### Create the functions

Create two functions in the [Functions page](https://console.aws.amazon.com/cloudfront/v3/home#/functions) of the CloudFront console:

1. *ViewerRequest* with the contents of *viewer_request.js*
2. *ViewerResponse* with the contents of *viewer_response.js*

Change the value of the *signingKey* variable in each function to a 32 bytes key that will be used for cryptographic signing.

###  Publish the functions

Publish both functions by choosing the Publish tab on the function page and then clicking the Publish button.

### Associate functions with the CloudFront distribution

On the function page, choose the Associate tab. Then do the following:

For *Distribution*, choose the distribution to associate the function with.

For *Event type*, choose when you want this function to run:

The *ViewerRequest* function must be run on *Viewer Request* event.

The *ViewerResponse* function must be run on *Viewer Response* event.

For *Cache behavior*, choose the cache behavior that you would like to be protected.

Choose Add association. Then, in the Associate function to cache behavior pop-up window, choose Associate.

## Usage

The CloudFront functions now set and validate the CSRF tokens and the last thing to do is to make sure that your front-end sends the CSRF token along with each "unsafe" request (POST, PUT, DELETE and PATCH).

### HTML forms

Add the following code to all pages that contain HTML forms. Should the CSRF token be invalid, the request will be terminated at the edge and the client will receive HTTP 403.

```javascript
<script>
// The name of the cookie that contains the token.
const csrfTokenCookieName = "__Host-csrf_token";
// The name of the csrf url query parameter.
const csrfTokenQuerystringName = "csrf_token";
// The function that retrieves the CSRF token value from the cookies. 
function getCsrfToken() {
    return document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${csrfTokenCookieName}=`))
    ?.split("=")[1];
}
window.addEventListener("DOMContentLoaded", () => {
    // Adding the CSRF token to each form on this page before they are submitted
    document.querySelectorAll("form[method=POST]").forEach(function(form) {
        form.addEventListener("submit", () => {
            const token = getCsrfToken();
            if (token) {
                form.action = `${form.action}?${csrfTokenQuerystringName}=${token}`;
            } else {
                alert("The CSRF token cookie is missing.");
            }
        });
    });
});
</script>
```

### JavaScript requests (recommended)

Add the following code to all pages that send "unsafe" requests with JavaScript:

```javascript
<script>
// The name of the cookie that contains the token.
const csrfTokenCookieName = "__Host-csrf_token";
// The name of the csrf header parameter.
const csrfTokenHeaderName = "x-csrf-token";
// The function that retrieves the CSRF token value from the cookies.
function getCsrfToken() {
    return document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${csrfTokenCookieName}=`))
    ?.split("=")[1];
}
</script>
```

When sending the requests, add a custom header *x-csrf-token* with the value that the *getCsrfToken* function returns. Should the CSRF token be invalid, the request will be terminated at the edge and the client will receive HTTP 403.