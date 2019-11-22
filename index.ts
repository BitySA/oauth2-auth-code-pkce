/**
 * An implementation of rfc6749#section-4.1 and rfc7636.
 */

export interface Configuration {
  authorizationUrl: URL;
  clientId: string;
  onAccessTokenExpiry: (refreshAccessToken: () => Promise<AccessToken>) => Promise<AccessToken | undefined>;
  onInvalidGrant: (refreshGrantOrRefreshToken: () => Promise<void>) => void;
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
  accessToken?: AccessToken;
  refreshToken?: RefreshToken;
  stateQueryParam?: string;
}

export interface RefreshToken {
  value: string;
};

export interface AccessToken {
  value: string;
  expiry: string;
};

export type URL = string;

/**
 * To store the OAuth client's data between websites due to redirection.
 */
export const LOCALSTORAGE_ID = `oauth2authcodepkce`;
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

  constructor(config: Configuration) {
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
  private assertStateAndConfigArePresent() {
    if (!this.state || !this.config) {
      console.error('state:', this.state, 'config:', this.config);
      throw new Error('state or config is not set.');
    }
  }

  /**
   * If there is an error, it will be passed back as a rejected Promies.
   * If there is no code, the user should be redirected via
   * [fetchAuthorizationGrant].
   */
  private captureGrantCodeAndNotifyIfReturning(): boolean {
    const error = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'error');
    if (error) {
      return false;
    }

    const code = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'code');
    if (!code) {
      return false;
    }

    const state = JSON.parse(localStorage.getItem(LOCALSTORAGE_STATE) || '{}');

    const stateQueryParam = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'state');
    if (stateQueryParam !== state.stateQueryParam) {
      console.warn("state query string parameter doesn't match the one sent! Possible malicious activity somewhere.");
      return false;
    }

    state.authorizationGrantCode = code;
    localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(state));

    this.setState(state);
    return true;
  }
 
  /**
   * Fetch an access token from the remote service. You may pass a custom
   * authorization grant code for any reason, but this is non-standard usage.
   *
   * This method should never return undefined, but was put here to satisfy the
   * TypeScript typechecker.
   */
  private fetchAccessTokenWithGrant(
    codeOverride?: string
  ): Promise<AccessToken> {
    this.assertStateAndConfigArePresent();
  
    const {
      authorizationGrantCode = codeOverride,
      codeVerifier = ''
    } = this.state;
    const { clientId, onInvalidGrant, redirectUrl } = this.config;

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
    .then(({ access_token, expires_in, refresh_token }) => {
      const accessToken: AccessToken = {
        value: access_token,
        expiry: (new Date(Date.now() + (parseInt(expires_in) * 1000))).toString()
      };
      this.state.accessToken = accessToken;

      if (refresh_token) {
        const refreshToken: RefreshToken = {
          value: refresh_token
        };
        this.state.refreshToken = refreshToken;
      }

      localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(this.state));
      return accessToken;
    })
    .catch((jsonPromise) => jsonPromise.then((json: any) => Promise.reject(json)))
    .catch((data) => {
      console.log(data);
      const error = data.error || 'There was a network error.';
      switch (error) {
        case 'invalid_grant':
          onInvalidGrant(() => this
            .fetchAuthorizationGrant()
            .catch(error => console.error(error))
          );
        default:
          break;
      }
      return Promise.reject(error);
    });
  }

  /**
   * Fetch an authorization grant via redirection. In a sense this function
   * doesn't return because of the redirect behavior (uses `location.replace`).
   */
  public async fetchAuthorizationGrant(): Promise<void> {
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
  }

  /**
   * Tries to get the current access token. If there is none
   * it will fetch another one. If it is expired, it will fire
   * [onAccessTokenExpiry] but it's up to the user to call the refresh token
   * function. This is because sometimes not using the refresh token facilities
   * is easier.
   *
   * Typically you always want to use this over [fetchAccessTokenWithGrant].
   */
  public getAccessToken(): Promise<AccessToken | undefined> {
    this.assertStateAndConfigArePresent();

    const { onAccessTokenExpiry } = this.config;
    const { accessToken, authorizationGrantCode, refreshToken } = this.state;
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
      return onAccessTokenExpiry(() => this.fetchAccessTokenWithGrant());
    }

    if ((new Date()) >= (new Date(accessToken.expiry))) {
      console.log('Renewing access token with refresh token');
      return onAccessTokenExpiry(() => this.refreshAccessToken());
    }

    console.log('Access token is accessible and valid');
    return Promise.resolve(accessToken);
  }

  /**
   * Refresh an access token from the remote service.
   */
  public refreshAccessToken(): Promise<AccessToken> {
    this.assertStateAndConfigArePresent();
  
    const { onInvalidGrant, tokenUrl } = this.config;
    const { refreshToken } = this.state;

    if (!refreshToken) {
      console.warn('No refresh token is present.');
    }

    const url = tokenUrl;
    const body = `grant_type=refresh_token&`
      + `refresh_token=${refreshToken}`;

    return fetch(url, {
      method: 'POST',
      body,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })
    .then(res => res.status === 400 ? Promise.reject(res.json()) : res.json())
    .then(({ access_token, expires_in, refresh_token }) => {
      const accessToken: AccessToken = {
        value: access_token,
        expiry: (new Date(Date.now() + parseInt(expires_in))).toString()
      };
      this.state.accessToken = accessToken;
     
      if (refresh_token) {
        const refreshToken: RefreshToken = {
          value: refresh_token
        };
        this.state.refreshToken = refreshToken;
      }

      localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(this.state));
      return accessToken;
    })
    .catch(jsonPromise => Promise.reject(jsonPromise))
    .catch(data => {
      const error = data.error || 'There was a network error.';
      switch (error) {
        case 'invalid_grant':
          onInvalidGrant(() => this
            .fetchAuthorizationGrant()
            .catch(error => console.error(error))
          );
        default:
          break;
      }
      return Promise.reject(error);
    });
  }

  private recoverState(): this {
    this.state = JSON.parse(localStorage.getItem(LOCALSTORAGE_STATE) || '{}');
    return this;
  }

  private setState(state: State): this {
    this.state = state;
    localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(state));
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
}
