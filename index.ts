/**
 * An implementation of rfc6749#section-4.1 and rfc7636.
 */

export interface Configuration {
  authorizationUrl: URL;
  clientId: string;
  endpoints: URL[];
  redirectUrl: URL;
  scopes: string[];
  tokenUrl: URL;
}

export interface PKCECodes {
  codeChallenge: string;
  codeVerifier: string;
}

export interface State {
  authorizationGrantCode?: string;
  codeChallenge?: string;
  codeVerifier?: string;
  token?: Token;
  stateQueryParam?: string;
}

export interface Token {
  value: string;
  expiry: string;
};

export type URL = string;

/**
 * To store the OAuth client's data between websites due to redirection.
 */
export const LOCALSTORAGE_ID = `oauth2authcodepkce`;
export const LOCALSTORAGE_CONFIG = `${LOCALSTORAGE_ID}-config`;
export const LOCALSTORAGE_STATE = `${LOCALSTORAGE_ID}-state`;

/**
 * The maximum length for a code verifier for the best security we can offer.
 */
export const RECOMMENDED_CODE_VERIFIER_LENGTH = 128;

/**
 * A sensible length for the state's length, for anti-csrf.
 */
export const RECOMMENDED_STATE_LENGTH = 32;

/**
 * Character set to generate code verifier defined in rfc7636.
 */
const PKCE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

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
export class OAuth2AuthCodePKCE {
  private config?: Configuration;
  private state: State = {};

  /**
   * If the state or config are missing, it means the client is in a bad state.
   * This should never happen, but the check is there just in case.
   */
  public assertStateAndConfigArePresent() {
    if (!this.state || !this.config) {
      console.error('state:', this.state, 'config:', this.config);
      throw new Error('state or config is not set.');
    }
  }
 
  /**
   * Fetch an access token from the remote service. You may pass a custom
   * authorization grant code for any reason, but this is non-standard usage.
   *
   * This method should never return undefined, but was put here to satisfy the
   * TypeScript typechecker.
   */
  public fetchAccessToken(codeOverride?: string): Promise<Token | undefined> {
    this.assertStateAndConfigArePresent();
  
    const { authorizationGrantCode = codeOverride, codeVerifier = '' } = this.state;
    const { redirectUrl, clientId } = this.config;

    if (!codeVerifier) {
      console.warn('No code verifier is being sent.');
    } else if (!authorizationGrantCode) {
      console.warn('No authorization grant code is being passed.');
    }

    const url = this.config.tokenUrl;
    const body = `grant_type=authorization_code&`
      + `code=${encodeURIComponent(authorizationGrantCode || '')}&`
      + `redirect_uri=${encodeURIComponent(redirectUrl)}&`
      + `client_id=${encodeURIComponent(clientId)}&`
      + `code_verifier=${codeVerifier}`;

    return fetch(url, {
      method: 'POST',
      body,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })
    .then(res => res.status === 400 ? Promise.reject(res.json()) : res.json())
    .then(({ access_token, expires_in }) => ({
      value: access_token,
      expiry: (new Date(Date.now() + parseInt(expires_in))).toString()
    }))
    .then((token: Token) => {
      this.state.token = token;
      localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(this.state));
      return token;
    })
    .catch(jsonPromise => Promise.reject(jsonPromise))
    .catch(data => {
      switch (data.error) {
        case 'invalid_grant':
          return this.fetchAuthorizationGrant();
        default:
          break;
      }
      return Promise.reject(data.error);
    });
  }

  /**
   * Fetch an authorization grant via redirection. In a sense this function
   * doesn't return because of the redirect behavior (uses `location.replace`).
   */
  public async fetchAuthorizationGrant(): Promise<undefined> {
    this.assertStateAndConfigArePresent();

    const { clientId, redirectUrl, scopes } = this.config;
    const { codeChallenge, codeVerifier } = await OAuth2AuthCodePKCE
      .generatePKCECodes();
    const stateQueryParam = OAuth2AuthCodePKCE
      .generateRandomState(RECOMMENDED_STATE_LENGTH);

    this.state = {
      ...this.state, 
      codeChallenge,
      codeVerifier,
      stateQueryParam
    };

    localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(this.state));

    const url = this.config.authorizationUrl
      + `?response_type=code&`
      + `client_id=${encodeURIComponent(clientId)}&`
      + `redirect_uri=${encodeURIComponent(redirectUrl)}&`
      + `scope=${encodeURIComponent(scopes.join(' '))}&`
      + `state=${stateQueryParam}&`
      + `code_challenge=${encodeURIComponent(codeChallenge)}&`
      + `code_challenge_method=S256`;

    location.replace(url);

    // Placed here to satifsy TypeScript compiler.
    return undefined;
  }

  /**
   * Tries to get the current access token. If there is none, or it has expired,
   * it will fetch another one.
   *
   * Typically you always want to use this over [fetchAccessToken].
   */
  public getAccessToken(): Promise<Token | undefined> {
    const { token } = this.state;
    if (!token ||  (new Date()) >= (new Date(token.expiry))) {
      return this.fetchAccessToken();
    }
    return Promise.resolve(token);
  }

  public recoverState(): this {
    this.state = JSON.parse(localStorage.getItem(LOCALSTORAGE_STATE) || '{}');
    return this;
  }


  public setState(state: State): this {
    this.state = state;
    localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(state));
    return this;
  }

  public setConfig(config: Configuration): this {
    this.config = config;
    localStorage.setItem(LOCALSTORAGE_CONFIG, JSON.stringify(config));
    return this;
  }

  /**
   * Implements *base64url-encode*, which is NOT the same as regular base64
   * encoding.
   */
  static base64urlEncode(value: string): string {
    let base64 = btoa(value);
    base64 = base64.replace(/\+/g, '-');
    base64 = base64.replace(/\//g, '_');
    base64 = base64.replace(/=/g, '');
    return base64;
  }

  /**
   * Extracts a query string parameter.
   */
  static extractParamFromUrl(url: URL, param: string): string {
    const queryString = url.split('?');
    if (queryString.length < 2) {
       return '';
    }

    const parts = queryString[1]
      .split('&')
      .reduce((a: string[], s: string) => a.concat(s.split('=')), []);

    if (parts.length < 2) {
      return '';
    }

    const paramIdx = parts.indexOf(param);
    return paramIdx >= 0 ? parts[paramIdx + 1] : '';
  }

  /**
   * Generates a code_verifier and code_challenge, as specified in rfc7636.
   */
  static generatePKCECodes(): PromiseLike<PKCECodes> {
    const encoder = new TextEncoder();
    const output = new Uint32Array(RECOMMENDED_CODE_VERIFIER_LENGTH);
    crypto.getRandomValues(output);
    const codeVerifier = OAuth2AuthCodePKCE.base64urlEncode(Array
      .from(output)
      .map((num: number) => PKCE_CHARSET[num % PKCE_CHARSET.length])
      .join(''));

    return crypto
      .subtle
      .digest('SHA-256', (new TextEncoder()).encode(codeVerifier))
      .then((buffer: ArrayBuffer) => {
        let hash = new Uint8Array(buffer);
        let binary = '';
        let hashLength = hash.byteLength;
        for (let i: number = 0; i < hashLength; i++) {
          binary += String.fromCharCode(hash[i]);
        }
        return binary;
      })
      .then(OAuth2AuthCodePKCE.base64urlEncode)
      .then((codeChallenge: string) => ({ codeChallenge, codeVerifier }));
  }

  /**
   * Generates random state to be passed for anti-csrf.
   */
  static generateRandomState(lengthOfState: number): string {
    const output = new Uint32Array(lengthOfState);
    crypto.getRandomValues(output);
    return Array
      .from(output)
      .map((num: number) => PKCE_CHARSET[num % PKCE_CHARSET.length])
      .join('');
  }

  /**
   * If there is an error, it will be passed back as a rejected Promies.
   * If there is no code, the user should be redirected via
   * [fetchAuthorizationGrant].
  static isComingBackFromAuthServer(): Promise<OAuth2AuthCodePKCE> {
    const error = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'error');
    if (error) {
      return Promise.reject(error);
    }

    const code = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'code');
    if (!code) {
      return Promise.reject();
    }

    const config = JSON.parse(localStorage.getItem(LOCALSTORAGE_CONFIG) || '{}');
    const state = JSON.parse(localStorage.getItem(LOCALSTORAGE_STATE) || '{}');

    const stateQueryParam = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'state');
    if (stateQueryParam !== state.stateQueryParam) {
      return Promise.reject('Returned state query param does not match original.');
    }

    state.authorizationGrantCode = code;
    localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(state));

    return Promise.resolve((new OAuth2AuthCodePKCE())
      .setConfig(config)
      .setState(state));
  }
}
