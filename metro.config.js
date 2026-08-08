// Wraps Expo's default Metro config with Sentry's, so source maps get generated
// and (for EAS builds) uploaded automatically. See:
// https://docs.sentry.io/platforms/react-native/manual-setup/expo/
const { getSentryExpoConfig } = require('@sentry/react-native/metro');

const config = getSentryExpoConfig(__dirname);

module.exports = config;
