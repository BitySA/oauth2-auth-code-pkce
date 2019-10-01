export interface Configuration {
  authorizationUrl: URL;
  clientId: string;
  endpoints: URL[];
  redirectUrl: URL;
  scopes: string[];
  tokenUrl: URL;
}

export interface State {
  authorizationGrantCode?: string;
  codeChallenge?: string;
  codeVerifier?: string;
  token?: Token;
}

export type URL = string;

export interface Token {
  value: string;
  expiry: Date;
};

export interface PKCECodes {
  codeChallenge: string;
  codeVerifier: string;
}

export const LOCALSTORAGE_ID = `oauth2authcodepkce`;
export const LOCALSTORAGE_CONFIG = `${LOCALSTORAGE_ID}-config`;
export const LOCALSTORAGE_ORIGIN = `${LOCALSTORAGE_ID}-origin`;
export const LOCALSTORAGE_STATE = `${LOCALSTORAGE_ID}-state`;

/**
 * Character set to generate code verifier.
 */
const PKCE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

/**
 * OAuth2 that ONLY supports authorization code flow, with PKCE.
 */
export class OAuth2AuthCodePKCE {
  private config?: Configuration;
  private state: State = {};

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

  static isComingBackFromAuthServer(): Promise<OAuth2AuthCodePKCE> {
    // Check for errors if any were returned.
    const error = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'error_hint');

    if (error) {
      return Promise.reject(error);
    }

    // If there is no code, then it isn't seen as a redirect coming from the
    // auth server.
    const code = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'code');

    if (!code) {
      return Promise.reject();
    }

    const config = JSON.parse(localStorage.getItem(LOCALSTORAGE_CONFIG) || '{}');
    const state = JSON.parse(localStorage.getItem(LOCALSTORAGE_STATE) || '{}');

    state.authorizationGrantCode = code;
    localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(state));

    return Promise.resolve((new OAuth2AuthCodePKCE())
      .setConfig(config)
      .setState(state));
  }

  static generatePKCECodes(): PromiseLike<PKCECodes> {
    const encoder = new TextEncoder();
    const output = new Uint32Array(128);
    crypto.getRandomValues(output);
    const codeVerifier = Array
      .from(output)
      .map((num: number) => PKCE_CHARSET[num % PKCE_CHARSET.length])
      .join('')
    return crypto
      .subtle
      .digest('SHA-256', (new TextEncoder()).encode(codeVerifier))
      .then((hash: ArrayBuffer) => Array
        .from(new Uint8Array(hash))
        .map((s: number) => s.toString())
        .join(''))
      .then(btoa)
      .then((codeChallenge: string) => ({ codeChallenge, codeVerifier }));
  }
  
  public fetchAccessToken(codeOverride: string | undefined): Promise<Token> {
    if (!this.state || !this.config) {
      console.error('state:', this.state, 'config:', this.config);
      throw new Error('state or config is not set.');
    }
  
    const { authorizationGrantCode = codeOverride } = this.state;
    const { redirectUrl, clientId } = this.config;

    if (!authorizationGrantCode) {
      console.warn('No authorization grant code is being passed.');
    }

    const url = this.config.tokenUrl
      + `?grant_type=authorization_code&`
      + `code=${encodeURIComponent(authorizationGrantCode || '')}&`
      + `redirect_uri=${encodeURIComponent(redirectUrl)}&`
      + `client_id=${encodeURIComponent(clientId)}`;

    return fetch(url, { method: 'POST' })
      .then(response => response.json())
      .then(({ access_token, expires_in }) => ({
        value: access_token,
        expiry: new Date(Date.now() + parseInt(expires_in))
      }));
  }

  public async fetchAuthorizationGrant(): Promise<void> {
    if (!this.config || !this.state) {
      console.error('state:', this.state, 'config:', this.config);
      throw new Error('state or config is not set.');
    }

    const { clientId, redirectUrl, scopes } = this.config;
    const { codeChallenge, codeVerifier } = await OAuth2AuthCodePKCE.generatePKCECodes();

    this.state.codeChallenge = codeChallenge;
    this.state.codeVerifier = codeVerifier;
    localStorage.setItem(LOCALSTORAGE_STATE, JSON.stringify(this.state));

    const url = this.config.authorizationUrl
      + `?response_type=code&`
      + `client_id=${encodeURIComponent(clientId)}&`
      + `redirect_uri=${encodeURIComponent(redirectUrl)}&`
      + `scope=${encodeURIComponent(scopes.join(' '))}&`
      + `code_challenge=${encodeURIComponent(codeChallenge)}&`
      + `code_challenge_method=S256`;

    location.replace(url);
  }

  public getAccessToken(): never {
    throw new Error('not implemented');
  }

  public refreshAccessToken(): never {
    throw new Error('not implemented');
  }
}

OAuth2AuthCodePKCE
  .isComingBackFromAuthServer()
  .then(() => alert('welcome back! redirect detected and worked.'))
  .catch((potentialError) => {
    if (potentialError) {
      alert(decodeURI(potentialError.replace(/\+/g, ' ')));
      return;
    }

    (new OAuth2AuthCodePKCE())
      .setConfig({
        authorizationUrl: 'https://localhost:8000/oauth2/auth',
        tokenUrl: 'https://localhost:8000/oauth2/token',
        clientId: 'fa0d35f5-b636-4de6-94c0-25f4299e774b',
        endpoints: ['http://localhost:4445'],
        scopes: ['offline'],
        redirectUrl: 'http://localhost:8080'
      })
      .fetchAuthorizationGrant();
  });
