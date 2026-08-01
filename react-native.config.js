module.exports = {
  dependency: {
    platforms: {
      ios: {},
      android: {
        packageImportPath: 'import com.rootjaildetect.RootJailDetectPackage;',
        packageInstance: 'new RootJailDetectPackage()',
      },
    },
  },
};
