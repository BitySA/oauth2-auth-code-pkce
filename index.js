/**
 * An implementation of rfc6749#section-4.1 and rfc7636.
 */
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
;
;
/**
 * To store the OAuth client's data between websites due to redirection.
 */
export var LOCALSTORAGE_ID = "oauth2authcodepkce";
export var LOCALSTORAGE_STATE = LOCALSTORAGE_ID + "-state";
/**
 * The maximum length for a code verifier for the best security we can offer.
 */
export var RECOMMENDED_CODE_VERIFIER_LENGTH = 128;
/**
 * A sensible length for the state's length, for anti-csrf.
 */
export var RECOMMENDED_STATE_LENGTH = 32;
/**
 * Character set to generate code verifier defined in rfc7636.
 */
var PKCE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
/**
 * OAuth 2.0 client that ONLY supports authorization code flow, with PKCE.
 *
 * Many applications structure their OAuth usage in different ways. This class
 * aims to provide both flexible and easy ways to use this configuration of
 * OAuth.
 *
 * See `example.ts` for how you'd typically use this.
 *
 * For others, review this class's methods.
 */
var OAuth2AuthCodePKCE = /** @class */ (function () {
    function OAuth2AuthCodePKCE(config) {
        this.state = {};
        this.config = config;
        this.recoverState();
        if (this.captureGrantCodeAndNotifyIfReturning()) {
            this.getAccessToken();
        }
        return this;
    }
    /**
     * If the state or config are missing, it means the client is in a bad state.
     * This should never happen, but the check is there just in case.
     */
    OAuth2AuthCodePKCE.prototype.assertStateAndConfigArePresent = function () {
        if (!this.state || !this.config) {
            console.error('state:', this.state, 'config:', this.config);
            throw new Error('state or config is not set.');
        }
    };
    /**
     * If there is an error, it will be passed back as a rejected Promies.
     * If there is no code, the user should be redirected via
     * [fetchAuthorizationGrant].
     */
    OAuth2AuthCodePKCE.prototype.captureGrantCodeAndNotifyIfReturning = function () {
        var error = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'error');
        if (error) {
            return false;
        }
        var code = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'code');
        if (!code) {
            return false;
        }
        var state = JSON.parse(localStorage.getItem(LOCALSTORAGE_STATE) || '{}');
        var stateQueryParam = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'state');
        if (stateQueryParam !== state.stateQueryParam) {
            console.warn("state query string parameter doesn't match the one sent! Possible malicious activity somewhere.");
            return false;
        }
        state.authorizationGrantCode = code;
        localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(state));
        this.setState(state);
        return true;
    };
    /**
     * Fetch an access token from the remote service. You may pass a custom
     * authorization grant code for any reason, but this is non-standard usage.
     *
     * This method should never return undefined, but was put here to satisfy the
     * TypeScript typechecker.
     */
    OAuth2AuthCodePKCE.prototype.fetchAccessTokenWithGrant = function (codeOverride) {
        var _this = this;
        this.assertStateAndConfigArePresent();
        var _a = this.state, _b = _a.authorizationGrantCode, authorizationGrantCode = _b === void 0 ? codeOverride : _b, _c = _a.codeVerifier, codeVerifier = _c === void 0 ? '' : _c;
        var _d = this.config, clientId = _d.clientId, onInvalidGrant = _d.onInvalidGrant, redirectUrl = _d.redirectUrl;
        if (!codeVerifier) {
            console.warn('No code verifier is being sent.');
        }
        else if (!authorizationGrantCode) {
            console.warn('No authorization grant code is being passed.');
        }
        var url = this.config.tokenUrl;
        var body = "grant_type=authorization_code&"
            + ("code=" + encodeURIComponent(authorizationGrantCode || '') + "&")
            + ("redirect_uri=" + encodeURIComponent(redirectUrl) + "&")
            + ("client_id=" + encodeURIComponent(clientId) + "&")
            + ("code_verifier=" + codeVerifier);
        return fetch(url, {
            method: 'POST',
            body: body,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        })
            .then(function (res) { return res.status === 400 ? Promise.reject(res.json()) : res.json(); })
            .then(function (_a) {
            var access_token = _a.access_token, expires_in = _a.expires_in, refresh_token = _a.refresh_token;
            var accessToken = {
                value: access_token,
                expiry: (new Date(Date.now() + (parseInt(expires_in) * 1000))).toString()
            };
            _this.state.accessToken = accessToken;
            if (refresh_token) {
                var refreshToken = {
                    value: refresh_token
                };
                _this.state.refreshToken = refreshToken;
            }
            localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(_this.state));
            return accessToken;
        })
            .catch(function (jsonPromise) { return jsonPromise.then(function (json) { return Promise.reject(json); }); })
            .catch(function (data) {
            console.log(data);
            var error = data.error || 'There was a network error.';
            switch (error) {
                case 'invalid_grant':
                    onInvalidGrant(function () { return _this
                        .fetchAuthorizationGrant()
                        .catch(function (error) { return console.error(error); }); });
                default:
                    break;
            }
            return Promise.reject(error);
        });
    };
    /**
     * Fetch an authorization grant via redirection. In a sense this function
     * doesn't return because of the redirect behavior (uses `location.replace`).
     */
    OAuth2AuthCodePKCE.prototype.fetchAuthorizationGrant = function () {
        return __awaiter(this, void 0, void 0, function () {
            var _a, clientId, redirectUrl, scopes, _b, codeChallenge, codeVerifier, stateQueryParam, url;
            return __generator(this, function (_c) {
                switch (_c.label) {
                    case 0:
                        this.assertStateAndConfigArePresent();
                        _a = this.config, clientId = _a.clientId, redirectUrl = _a.redirectUrl, scopes = _a.scopes;
                        return [4 /*yield*/, OAuth2AuthCodePKCE
                                .generatePKCECodes()];
                    case 1:
                        _b = _c.sent(), codeChallenge = _b.codeChallenge, codeVerifier = _b.codeVerifier;
                        stateQueryParam = OAuth2AuthCodePKCE
                            .generateRandomState(RECOMMENDED_STATE_LENGTH);
                        this.state = __assign(__assign({}, this.state), { codeChallenge: codeChallenge,
                            codeVerifier: codeVerifier,
                            stateQueryParam: stateQueryParam });
                        localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(this.state));
                        url = this.config.authorizationUrl
                            + "?response_type=code&"
                            + ("client_id=" + encodeURIComponent(clientId) + "&")
                            + ("redirect_uri=" + encodeURIComponent(redirectUrl) + "&")
                            + ("scope=" + encodeURIComponent(scopes.join(' ')) + "&")
                            + ("state=" + stateQueryParam + "&")
                            + ("code_challenge=" + encodeURIComponent(codeChallenge) + "&")
                            + "code_challenge_method=S256";
                        location.replace(url);
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Tries to get the current access token. If there is none
     * it will fetch another one. If it is expired, it will fire
     * [onAccessTokenExpiry] but it's up to the user to call the refresh token
     * function. This is because sometimes not using the refresh token facilities
     * is easier.
     *
     * Typically you always want to use this over [fetchAccessTokenWithGrant].
     */
    OAuth2AuthCodePKCE.prototype.getAccessToken = function () {
        var _this = this;
        this.assertStateAndConfigArePresent();
        var onAccessTokenExpiry = this.config.onAccessTokenExpiry;
        var _a = this.state, accessToken = _a.accessToken, authorizationGrantCode = _a.authorizationGrantCode, refreshToken = _a.refreshToken;
        if (!authorizationGrantCode) {
            return Promise.reject({ error: 'no_auth_code' });
        }
        if (!accessToken) {
            console.log('Getting access token with grant');
            return this.fetchAccessTokenWithGrant();
        }
        // If there's no refresh token, attempt with the auth grant code.
        if (!refreshToken && (new Date()) >= (new Date(accessToken.expiry))) {
            console.log('Renewing access token with grant');
            return onAccessTokenExpiry(function () { return _this.fetchAccessTokenWithGrant(); });
        }
        if ((new Date()) >= (new Date(accessToken.expiry))) {
            console.log('Renewing access token with refresh token');
            return onAccessTokenExpiry(function () { return _this.refreshAccessToken(); });
        }
        console.log('Access token is accessible and valid');
        return Promise.resolve(accessToken);
    };
    /**
     * Refresh an access token from the remote service.
     */
    OAuth2AuthCodePKCE.prototype.refreshAccessToken = function () {
        var _this = this;
        this.assertStateAndConfigArePresent();
        var _a = this.config, onInvalidGrant = _a.onInvalidGrant, tokenUrl = _a.tokenUrl;
        var refreshToken = this.state.refreshToken;
        if (!refreshToken) {
            console.warn('No refresh token is present.');
        }
        var url = tokenUrl;
        var body = "grant_type=refresh_token&"
            + ("refresh_token=" + refreshToken);
        return fetch(url, {
            method: 'POST',
            body: body,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        })
            .then(function (res) { return res.status === 400 ? Promise.reject(res.json()) : res.json(); })
            .then(function (_a) {
            var access_token = _a.access_token, expires_in = _a.expires_in, refresh_token = _a.refresh_token;
            var accessToken = {
                value: access_token,
                expiry: (new Date(Date.now() + parseInt(expires_in))).toString()
            };
            _this.state.accessToken = accessToken;
            if (refresh_token) {
                var refreshToken_1 = {
                    value: refresh_token
                };
                _this.state.refreshToken = refreshToken_1;
            }
            localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(_this.state));
            return accessToken;
        })
            .catch(function (jsonPromise) { return Promise.reject(jsonPromise); })
            .catch(function (data) {
            var error = data.error || 'There was a network error.';
            switch (error) {
                case 'invalid_grant':
                    onInvalidGrant(function () { return _this
                        .fetchAuthorizationGrant()
                        .catch(function (error) { return console.error(error); }); });
                default:
                    break;
            }
            return Promise.reject(error);
        });
    };
    OAuth2AuthCodePKCE.prototype.recoverState = function () {
        this.state = JSON.parse(localStorage.getItem(LOCALSTORAGE_STATE) || '{}');
        return this;
    };
    OAuth2AuthCodePKCE.prototype.setState = function (state) {
        this.state = state;
        localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(state));
        return this;
    };
    /**
     * Implements *base64url-encode*, which is NOT the same as regular base64
     * encoding.
     */
    OAuth2AuthCodePKCE.base64urlEncode = function (value) {
        var base64 = btoa(value);
        base64 = base64.replace(/\+/g, '-');
        base64 = base64.replace(/\//g, '_');
        base64 = base64.replace(/=/g, '');
        return base64;
    };
    /**
     * Extracts a query string parameter.
     */
    OAuth2AuthCodePKCE.extractParamFromUrl = function (url, param) {
        var queryString = url.split('?');
        if (queryString.length < 2) {
            return '';
        }
        var parts = queryString[1]
            .split('&')
            .reduce(function (a, s) { return a.concat(s.split('=')); }, []);
        if (parts.length < 2) {
            return '';
        }
        var paramIdx = parts.indexOf(param);
        return paramIdx >= 0 ? parts[paramIdx + 1] : '';
    };
    /**
     * Generates a code_verifier and code_challenge, as specified in rfc7636.
     */
    OAuth2AuthCodePKCE.generatePKCECodes = function () {
        var output = new Uint32Array(RECOMMENDED_CODE_VERIFIER_LENGTH);
        crypto.getRandomValues(output);
        var codeVerifier = OAuth2AuthCodePKCE.base64urlEncode(Array
            .from(output)
            .map(function (num) { return PKCE_CHARSET[num % PKCE_CHARSET.length]; })
            .join(''));
        return crypto
            .subtle
            .digest('SHA-256', (new TextEncoder()).encode(codeVerifier))
            .then(function (buffer) {
            var hash = new Uint8Array(buffer);
            var binary = '';
            var hashLength = hash.byteLength;
            for (var i = 0; i < hashLength; i++) {
                binary += String.fromCharCode(hash[i]);
            }
            return binary;
        })
            .then(OAuth2AuthCodePKCE.base64urlEncode)
            .then(function (codeChallenge) { return ({ codeChallenge: codeChallenge, codeVerifier: codeVerifier }); });
    };
    /**
     * Generates random state to be passed for anti-csrf.
     */
    OAuth2AuthCodePKCE.generateRandomState = function (lengthOfState) {
        var output = new Uint32Array(lengthOfState);
        crypto.getRandomValues(output);
        return Array
            .from(output)
            .map(function (num) { return PKCE_CHARSET[num % PKCE_CHARSET.length]; })
            .join('');
    };
    return OAuth2AuthCodePKCE;
}());
export { OAuth2AuthCodePKCE };
