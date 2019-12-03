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
    libraryTarget: 'umd',
    library: 'OAuth2AuthCodePKCE',
    filename: 'index.umd.js',
    path: path.resolve(__dirname, './'),
  },
};
