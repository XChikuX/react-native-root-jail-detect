// Jest test environment for @psync/anti-jailbreak.
// Re-exports the top-level jest-environment-node (v30) instead of the stale
// jest-environment-node (v29) bundled inside react-native's node_modules.
// Without this override, Jest 30 fails with:
//   TypeError: this._moduleMocker.clearMocksOnScope is not a function
// because jest-mock v30 added clearMocksOnScope but jest-environment-node v29
// doesn't expose it on its moduleMocker.
const { TestEnvironment } = require('jest-environment-node');
module.exports = TestEnvironment;
