# OAuth2AuthCodePKCE client

A zero dependency OAuth 2.0 client supporting *only* the authorization code
grant ([RFC 6749 § 4.1][]) with PKCE ([RFC 7636][]) for client side protection.

[RFC 6749 § 4.1]: https://tools.ietf.org/html/rfc6749#section-4.1
[RFC 7636]: https://tools.ietf.org/html/rfc7636

Currently the only Type/JavaScript implementation in public existence.

1 file implementation for easy auditing.

## Installation

`npm install @bity/oauth2-auth-code-pkce`

## Usage

Run `npm run serve:examples` and navigate to 
http://localhost:8080/examples/as-an-es6-browser-module.html

This page acts as a test panel for various scenarios. Play around! :)

Modify the example to use the correct configuration.

## Module systems supported

Module system|File
---|---
ESModules (import/export)|index.js
CommonJS2 (require e.g. nodejs)|oauth2-auth-code-pkce.js
TypeScript|index.ts
