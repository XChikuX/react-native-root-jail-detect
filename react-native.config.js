const path = require('path');

module.exports = {
  dependency: {
    platforms: {
      ios: {},
      android: {
        sourceDir: path.join(__dirname, 'android'),
        cmakeListsPath: path.join(__dirname, 'android', 'CMakeLists.txt'),
        packageImportPath: 'import com.rootjaildetect.RootJailDetectPackage;',
        packageInstance: 'new RootJailDetectPackage()',
      },
    },
  },
};
