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

See the source code of `tests/panel.html`. It's commented with helpful
information.

Run `npm run serve:tests` and navigate to 
http://localhost:8080/tests/panel.html

This page acts as a test panel for various scenarios. Play around! :)

Modify the example to use the correct configuration.

## Exposing other query string parameters on return

Some OAuth servers will return additional parameters to the requester. In order
to access these they must be explicitly asked for:

```
config.explicitlyExposedTokens = ['open_id'];
```

Then this will be available as a property:
`accessContext.explicitlyExposedTokens.open_id`.

## Extra parameters which other OAuth servers require

It is probable you will encounter an OAuth server which requires some additional
parameters. In order to pass extra parameters, add the following to the
configuration:

```
config.extraAuthorizationParameters = { 'some_query_string_param': 'value', ... };
```

If you have values which need to be computed at run-time and then passed, you
can pass them like so:

```
oauth2.fetchAuthorizationCode({ 'another_query_string_param': computedValue });
```

## Module systems supported

| Module system                   | File                      |
|:--------------------------------|:--------------------------|
| Browser (window)                | index.umd.js              |
| CommonJS (require e.g. nodejs)  | index.js                  |
| TypeScript                      | index.ts                  |

## Development

### Publishing to NPM

Grab the NPM-generated `bity-oauth2-auth-code-pkce-*.tgz` tarball from CI and
then use `npm publish $tarball` to publish it to NPM.
