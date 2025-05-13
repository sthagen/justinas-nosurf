# Trusted origin checks in nosurf

Before version 1.2.0, nosurf did not correctly apply trusted origin checks for non-safe HTTP requests.
This resulted in [CVE-2025-46721](https://www.cve.org/CVERecord?id=CVE-2025-46721).

To alleviate this, existing checks for the `Referer` header were fixed,
and additional methods of checking the origin of requests were added.

As this was technically a breaking change in nosurf, this document attempts to shed light on how origin checks function in nosurf,
and how users can avoid potential breakage.


<!-- vim-markdown-toc GFM -->

* [How does nosurf check the origin?](#how-does-nosurf-check-the-origin)
    * [1. `Sec-Fetch-Site` header](#1-sec-fetch-site-header)
    * [2. `Origin` or `Referer` headers](#2-origin-or-referer-headers)
* [What do I need to do after upgrading to 1.2.0?](#what-do-i-need-to-do-after-upgrading-to-120)
* [What are the risks of not upgrading to 1.2.0?](#what-are-the-risks-of-not-upgrading-to-120)

<!-- vim-markdown-toc -->

## How does nosurf check the origin?

### 1. `Sec-Fetch-Site` header

[`Sec-Fetch-Site`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site) is a request header
sent by [all modern browsers](https://caniuse.com/mdn-http_headers_sec-fetch-site).
If the incoming request contains a `Sec-Fetch-Site` header with the value `same-origin`,
nosurf lets the request through (subject to further verification of the CSRF token).

### 2. `Origin` or `Referer` headers

If the `Sec-Fetch-Site` header is not present on the incoming request, or has a value other than `same-origin`,
nosurf must directly compare the website's origin against the origin the request was made from.

Web content's [origin](https://developer.mozilla.org/en-US/docs/Glossary/Origin) consists of
a *scheme* (usually `http` or `https`), followed by the host (e.g. `example.com`), optionally followed by a port
(if a non-standard HTTP/HTTPS port is used).
This raises a problem for nosurf: because TLS may be terminated before it reaches the Go application
(e.g. by a load balancer or a reverse proxy),
in the general case nosurf can not tell whether the website is being served over HTTPS.
However, that information is mandatory in order to know the full "self" origin of the website.

By default, nosurf will assume that the website is using HTTPS.
This avoids breakage in most production scenarios, but (in conjunction with `Sec-Fetch-Site` not being present),
can cause errors in local development scenarios.
To this end, nosurf provides a [`SetIsTLSFunc`](https://pkg.go.dev/github.com/justinas/nosurf#CSRFHandler.SetIsTLSFunc) method.
This method requires a user-supplied delegate function, a boolean value indicating whether an incoming request is considered secure.

After constructing a full "self" origin from this boolean indicator and the information found in the `Host` header,
nosurf will compare the value of the `Origin` header on the incoming request against the self-origin.
If the origins are equal, request will proceed with further CSRF token checks.
If the origins aren't equal, nosurf will invoke the user-supplied delegate (if any) set by calling 
[`SetIsAllowedOriginFunc`](https://pkg.go.dev/github.com/justinas/nosurf#CSRFHandler.SetIsAllowedOriginFunc).
If the delegate returns `false`, the request will be considered cross-origin and get aborted.

In the unlikely case where `Origin` header does not exist,
nosurf will perform the same validations documented above on the `Referer` header.

In the very unlikely case that no `Referer` header is present either, the request will be aborted.

## What do I need to do after upgrading to 1.2.0?

* If your website does not utilize mutating cross-origin requests, and you have no visitors using grossly outdated browsers,
  the check for `Sec-Fetch-Site` will be sufficient, and you do not need to make any changes to your code.
* If you expect your site to be visited by user with outdated browsers that do not implement the `Sec-Fetch-Site` header,
  but the site is served via HTTPS and you do not expect cross-origin requests, you do not need to make any changes to your code.
* If you are serving via plaintext HTTP (some or all of the time), when configuring nosurf, you must call `SetIsTLSFunc()`,
  passing it a function that correctly determines this per individual request.
* If you expect cross-origin requests, you must call `SetIsAllowedOriginFunc()`,
  passing it a function that validates whether the origin is allowed to issue non-safe requests to your website.

## What are the risks of not upgrading to 1.2.0?

You may be susceptible to cross-site request forgery due to [CVE-2025-46721](https://www.cve.org/CVERecord?id=CVE-2025-46721).

However, as nosurf's CSRF token validation logic is thought to be sound,
all known exploits require the attacker to have control over the HTML content of a page on your website,
or on a page hosted on a subdomain under your website's domain (e.g. `attacker.example.com` if your website is `example.com`)
in order to extract or override the CSRF token set in the cookie by nosurf.

Despite the minimal risk, I recommend that you upgrade nosurf to the latest version.
