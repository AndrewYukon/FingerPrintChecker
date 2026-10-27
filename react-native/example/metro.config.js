const path = require('path');
const {getDefaultConfig, mergeConfig} = require('@react-native/metro-config');

const libRoot = path.resolve(__dirname, '..');
const escape = p => p.replace(/[/\\]/g, '[/\\\\]');

/**
 * The library lives one directory up (installed with `file:..`). Watch it, and make sure the
 * app's own react / react-native are the only copies Metro sees.
 *
 * @type {import('metro-config').MetroConfig}
 */
const config = {
  watchFolders: [libRoot],
  resolver: {
    blockList: [
      new RegExp(`${escape(path.join(libRoot, 'node_modules'))}[/\\\\](react|react-native)[/\\\\].*`),
    ],
    extraNodeModules: {
      react: path.join(__dirname, 'node_modules/react'),
      'react-native': path.join(__dirname, 'node_modules/react-native'),
    },
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
