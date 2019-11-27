const path = require('path');

module.exports = {
  mode: 'none',
  entry: './index.ts',
  module: {
    rules: [
      {
        test: /\.ts?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: [ '.tsx', '.ts', '.js' ],
  },
  output: {
    libraryTarget: 'commonjs2',
    library: 'OAuth2AuthCodePKCE',
    filename: 'oauth2-auth-code-pkce.js',
    path: path.resolve(__dirname, './'),
  },
};
