import { OAuth2AuthCodePKCE, Token } from './index';

OAuth2AuthCodePKCE
  .isComingBackFromAuthServer()
  .then((oauth: OAuth2AuthCodePKCE) => oauth.getAccessToken())
  .then((token: Token | undefined) => console.log(token))
  .catch((potentialError: string) => {
    if (potentialError) {
      alert(potentialError);
      return;
    }

    (new OAuth2AuthCodePKCE())
      .setConfig({
        authorizationUrl: 'https://localhost:8000/oauth2/auth',
        tokenUrl: 'https://localhost:8000/oauth2/token',
        clientId: 'f1e4ee59-d775-4314-b8bc-25e80c0b1ede',
        endpoints: ['http://localhost:4445'],
        scopes: ['offline'],
        redirectUrl: 'http://localhost:8080'
      })
      .fetchAuthorizationGrant();
  });
