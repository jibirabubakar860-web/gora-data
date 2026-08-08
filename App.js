import React, { useState, useEffect, useCallback, useRef, createContext, useContext } from 'react';
import {
  StyleSheet, Text, View, ScrollView, TouchableOpacity, SafeAreaView,
  Alert, TextInput, Modal, ActivityIndicator, RefreshControl, Share, Platform, FlatList, Linking,
  KeyboardAvoidingView, BackHandler, Image,
} from 'react-native';
import * as Clipboard from 'expo-clipboard';
import { Ionicons } from '@expo/vector-icons';
import { captureRef } from 'react-native-view-shot';
import * as Sharing from 'expo-sharing';
import * as Print from 'expo-print';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Notifications from 'expo-notifications';
import Constants from 'expo-constants';
import * as LocalAuthentication from 'expo-local-authentication';
import * as SecureStore from 'expo-secure-store';
import * as Sentry from '@sentry/react-native';

// ─── Crash reporting ────────────────────────────────────────────────────────
// Must run before anything else in the app so it can catch errors from the
// very start of the app lifecycle. The DSN below is a public identifier
// (safe to have in client code, unlike an API secret) — it just tells the
// Sentry SDK where to send error reports. Find it anytime at sentry.io under
// your project's Settings > Client Keys (DSN).
Sentry.init({
  dsn: 'https://cd3ac26041ebd39b22d1ae4fec37445f@o4511866382647296.ingest.de.sentry.io/4511866401652816',
  sendDefaultPii: true,
  tracesSampleRate: 0.2,
});

// Foreground behavior: show an alert/banner + play sound even while the app is open.
Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
  }),
});

// Wraps a screen's ScrollView so the focused TextInput is never hidden behind the keyboard.
// Without this, a long list above a text field (e.g. Betting's biller list) pushes the field
// down far enough that opening the keyboard covers it completely — you'd be typing blind.
// iOS needs `padding` behavior with a header-height offset; Android handles this natively via
// `windowSoftInputMode` in most cases, but `height` behavior is a safe no-op fallback either way.
function KeyboardSafeScroll({ style, contentContainerStyle, children, headerOffset = 0 }) {
  return (
    <KeyboardAvoidingView
      style={{ flex: 1 }}
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      keyboardVerticalOffset={Platform.OS === 'ios' ? headerOffset : 0}
    >
      <ScrollView
        style={style}
        contentContainerStyle={contentContainerStyle}
        keyboardShouldPersistTaps="handled"
      >
        {children}
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

// ASSUMED backend route — not yet confirmed against your API:
//   POST /api/v1/notifications/register-token  body: { pushToken, platform }
// Registers this device's Expo push token so the backend can send pushes to it
// (e.g. via expo-server-sdk on a wallet credit, purchase success, or admin broadcast).
// If your backend doesn't have this route yet, that's the next thing to add there —
// once it does, it just needs to call Expo's push API with the stored token.
async function registerForPushNotificationsAsync(token) {
  try {
    const { status: existingStatus } = await Notifications.getPermissionsAsync();
    let finalStatus = existingStatus;
    if (existingStatus !== 'granted') {
      const { status } = await Notifications.requestPermissionsAsync();
      finalStatus = status;
    }
    if (finalStatus !== 'granted') return null;

    const projectId = Constants.expoConfig?.extra?.eas?.projectId || Constants.easConfig?.projectId;
    const pushTokenData = await Notifications.getExpoPushTokenAsync(projectId ? { projectId } : undefined);
    const pushToken = pushTokenData.data;

    if (Platform.OS === 'android') {
      await Notifications.setNotificationChannelAsync('default', {
        name: 'default',
        importance: Notifications.AndroidImportance.DEFAULT,
      });
    }

    if (pushToken && token) {
      await api('/api/v1/notifications/register-token', {
        method: 'POST',
        token,
        body: { pushToken, platform: Platform.OS },
      }).catch(() => {}); // non-critical — don't block app usage if this route isn't live yet
    }
    return pushToken;
  } catch (e) {
    return null;
  }
}

// ─── Biometric login (Face ID / fingerprint) ───────────────────────────────
// Stored as a per-user-device preference in AsyncStorage. This gates the app
// with an OS-level biometric prompt right after a saved session is restored,
// on top of (not instead of) the existing access/refresh token auth — losing
// your phone unlocked no longer means your wallet is exposed.
const BIOMETRIC_ENABLED_KEY = 'biometricLoginEnabled';

async function getBiometricSupport() {
  if (Platform.OS === 'web') return { available: false, label: 'Biometric login' };
  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  const isEnrolled = await LocalAuthentication.isEnrolledAsync();
  const types = await LocalAuthentication.supportedAuthenticationTypesAsync();
  const hasFace = types.includes(LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION);
  const label = hasFace ? 'Face ID' : 'Fingerprint';
  return { available: hasHardware && isEnrolled, label };
}

async function isBiometricLoginEnabled() {
  if (Platform.OS === 'web') return false;
  return (await AsyncStorage.getItem(BIOMETRIC_ENABLED_KEY)) === 'true';
}

async function setBiometricLoginEnabled(value) {
  if (Platform.OS === 'web') return;
  await AsyncStorage.setItem(BIOMETRIC_ENABLED_KEY, value ? 'true' : 'false');
}

async function promptBiometricUnlock(reason = 'Unlock Gora') {
  if (Platform.OS === 'web') return false;
  const result = await LocalAuthentication.authenticateAsync({
    promptMessage: reason,
    cancelLabel: 'Cancel',
    disableDeviceFallback: false, // allow device passcode as a fallback if biometrics fail
  });
  return result.success;
}

// ─── Transaction PIN ────────────────────────────────────────────────────────
// A separate 4-digit PIN (distinct from the login password) required by the server
// before any route that moves money out of the wallet — purchases and withdrawals.
// Biometrics don't replace the PIN on the server; they're a *local* shortcut for
// entering it: once a user opts in, the PIN is saved in the OS-encrypted keychain
// (expo-secure-store, unlocked only by Face ID/fingerprint) so they don't have to
// type 4 digits before every purchase. If biometrics isn't set up, they just type it.
const TX_BIOMETRIC_ENABLED_KEY = 'txBiometricEnabled';
const TX_PIN_SECURE_STORE_KEY = 'transactionPinSecure';

async function isTxBiometricEnabled() {
  return (await AsyncStorage.getItem(TX_BIOMETRIC_ENABLED_KEY)) === 'true';
}

async function enableTxBiometric(pin) {
  await SecureStore.setItemAsync(TX_PIN_SECURE_STORE_KEY, String(pin), {
    requireAuthentication: false, // the biometric prompt itself gates the read, see below
  });
  await AsyncStorage.setItem(TX_BIOMETRIC_ENABLED_KEY, 'true');
}

async function disableTxBiometric() {
  await AsyncStorage.setItem(TX_BIOMETRIC_ENABLED_KEY, 'false');
  try { await SecureStore.deleteItemAsync(TX_PIN_SECURE_STORE_KEY); } catch (e) {}
}

// Prompts Face ID/fingerprint, then reads the saved PIN out of the keychain on success.
// Returns null on cancel/failure — caller should fall back to manual PIN entry.
async function getPinViaBiometric() {
  const ok = await promptBiometricUnlock('Confirm to authorize this transaction');
  if (!ok) return null;
  try {
    return await SecureStore.getItemAsync(TX_PIN_SECURE_STORE_KEY);
  } catch (e) {
    return null;
  }
}

// Global singleton so any screen — deep inside a purchase flow — can request the
// transaction PIN without threading a prop through every component in between.
// The modal that fulfills this is mounted once, at the app root (see TransactionPinModalHost).
let _pinModalHandler = null;
function _setPinModalHandler(fn) { _pinModalHandler = fn; }
function requestTransactionPin() {
  return new Promise((resolve) => {
    if (!_pinModalHandler) return resolve(null);
    _pinModalHandler(resolve);
  });
}

const API_BASE = 'https://gora-data.onrender.com';

// ─── API helper ─────────────────────────────────────────────────────────────
// ─── API client with automatic session refresh ─────────────────────────────
// The backend issues a short-lived access token (15 min) plus a long-lived
// refresh token (30 days). Without this, every screen would start failing
// 15 minutes into a session and force the customer to log in again.
let currentAccessToken = null;
let currentRefreshToken = null;
let onTokenUpdated = null;   // called with the new access token after a successful refresh
let onAuthExpired = null;    // called when the refresh token itself is invalid/expired

function setApiTokens(accessToken, refreshToken) {
  currentAccessToken = accessToken || null;
  currentRefreshToken = refreshToken || null;
}
function setOnTokenUpdated(cb) { onTokenUpdated = cb; }
function setOnAuthExpired(cb) { onAuthExpired = cb; }

let refreshInFlight = null;
async function refreshAccessToken() {
  if (!currentRefreshToken) throw new Error('No refresh token available');
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      const res = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: currentRefreshToken }),
      });
      const json = await res.json();
      if (json.status !== 'success' || !json.data?.accessToken) throw new Error('Session expired');
      currentAccessToken = json.data.accessToken;
      await AsyncStorage.setItem('accessToken', currentAccessToken);
      if (onTokenUpdated) onTokenUpdated(currentAccessToken);
      return currentAccessToken;
    })().finally(() => { refreshInFlight = null; });
  }
  return refreshInFlight;
}

async function api(path, { method = 'GET', body, token, _retried } = {}) {
  // Prefer the freshest known token over whatever was passed in as a prop —
  // this way a background refresh is picked up immediately by every screen
  // without needing to thread updated tokens through props everywhere.
  const authToken = currentAccessToken || token;
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json();
  if (json.status !== 'success') {
    const isAuthError = res.status === 401 && !!authToken;
    if (isAuthError && !_retried) {
      try {
        const newToken = await refreshAccessToken();
        return api(path, { method, body, token: newToken, _retried: true });
      } catch (e) {
        if (onAuthExpired) onAuthExpired();
      }
    }
    const apiError = new Error(json.message || 'Something went wrong');
    apiError.code = json.code;
    apiError.attemptsLeft = json.attemptsLeft;
    apiError.refunded = json.refunded;
    throw apiError;
  }
  return json.data;
}

// ─── Theme ──────────────────────────────────────────────────────────────────
const lightColors = {
  bg: '#f5f3ff', card: '#fff', headerBg: '#5b21b6', text: '#1e1b4b', subtext: '#6b7280',
  inputBg: '#fff', inputBorder: '#e5e7eb', iconWrap: '#ede9fe', accent: '#6d28d9',
  overlay: 'rgba(255,255,255,0.15)', tabBg: '#fff', tabBorder: '#eee', inactiveTab: '#9ca3af',
};
const darkColors = {
  bg: '#0f0e1a', card: '#1b1930', headerBg: '#3b1876', text: '#f4f3ff', subtext: '#a5a3c2',
  inputBg: '#241f3d', inputBorder: '#352f57', iconWrap: '#2b2650', accent: '#a78bfa',
  overlay: 'rgba(255,255,255,0.08)', tabBg: '#1b1930', tabBorder: '#2b2650', inactiveTab: '#6b6890',
};

const ThemeContext = createContext();
const useTheme = () => useContext(ThemeContext);

function ThemeProvider({ children }) {
  const [dark, setDark] = useState(false);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    (async () => {
      const saved = await AsyncStorage.getItem('theme');
      if (saved === 'dark') setDark(true);
      setReady(true);
    })();
  }, []);

  const toggle = async () => {
    const next = !dark;
    setDark(next);
    await AsyncStorage.setItem('theme', next ? 'dark' : 'light');
  };

  if (!ready) return null;
  const colors = dark ? darkColors : lightColors;
  return <ThemeContext.Provider value={{ colors, dark, toggle }}>{children}</ThemeContext.Provider>;
}

const NETWORKS = ['MTN', 'Airtel', 'Glo', '9mobile'];
const NETWORK_COLORS = { MTN: '#ffcb05', Airtel: '#ff1a1a', Glo: '#3ea635', '9mobile': '#00a651' };

// Bigisub sends the plan quantity and unit as TWO separate fields:
// `size` (e.g. "20", "200", "1") and `plan_volume` (e.g. "MB", "GB").
// They must be joined together to get a readable label like "20MB" or "1GB".
// Falls back to `name`/`plan_name` only if `size` is missing entirely.
function formatPlanLabel(p) {
  if (p?.size) return `${p.size}${p.plan_volume || ''}`;
  return p?.name || p?.plan_name || '';
}

// ─── OTP Verify Screen ──────────────────────────────────────────────────────
function VerifyScreen({ phone, devOtp, onVerified, onBack }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [otp, setOtp] = useState(devOtp || '');
  const [loading, setLoading] = useState(false);

  const handleVerify = async () => {
    if (!otp) return Alert.alert('Missing OTP', 'Enter the code sent to your phone or email');
    setLoading(true);
    try {
      const data = await api('/api/v1/auth/verify', { method: 'POST', body: { phone, otp } });
      await AsyncStorage.setItem('accessToken', data.accessToken);
      await AsyncStorage.setItem('refreshToken', data.refreshToken);
      onVerified(data.user, data.accessToken, data.refreshToken);
    } catch (e) {
      Alert.alert('Verification failed', e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <KeyboardSafeScroll contentContainerStyle={{ flexGrow: 1 }}>
        <View style={s.loginWrap}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 20 }}>
            <Ionicons name="arrow-back" size={24} color={colors.text} />
          </TouchableOpacity>
          <Text style={s.loginTitle}>Verify Your Account</Text>
          <Text style={s.loginSubtitle}>Enter the OTP sent to {phone} and your email</Text>
          {devOtp ? <Text style={[s.loginSubtitle, { color: colors.accent }]}>Dev mode OTP: {devOtp}</Text> : null}

          <TextInput
            style={s.input}
            placeholder="6-digit OTP"
            placeholderTextColor={colors.subtext}
            keyboardType="number-pad"
            maxLength={6}
            value={otp}
            onChangeText={setOtp}
          />
          <TouchableOpacity style={s.loginBtn} onPress={handleVerify} disabled={loading}>
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Verify & Continue</Text>}
          </TouchableOpacity>
        </View>
      </KeyboardSafeScroll>
    </SafeAreaView>
  );
}

// ─── Signup Screen ──────────────────────────────────────────────────────────
function SignupScreen({ onRegistered, onSwitchToLogin, onOpenLegal }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [fullName, setFullName] = useState('');
  const [phone, setPhone] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [referralCode, setReferralCode] = useState('');
  const [otpChannel, setOtpChannel] = useState('both'); // 'sms' | 'email' | 'both'
  const [loading, setLoading] = useState(false);
  const [agreedToTerms, setAgreedToTerms] = useState(false);

  const isValidEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim());

  const handleSignup = async () => {
    if (!fullName || !phone || !email || !password) return Alert.alert('Missing info', 'Fill in all fields');
    if (!isValidEmail(email)) return Alert.alert('Invalid email', 'Enter a valid email address');
    if (password.length < 6) return Alert.alert('Weak password', 'Password must be at least 6 characters');
    if (!agreedToTerms) return Alert.alert('Terms required', 'Please agree to the Terms of Service and Privacy Policy to continue');
    setLoading(true);
    try {
      const data = await api('/api/v1/auth/register', {
        method: 'POST',
        body: { phone, email: email.trim().toLowerCase(), password, fullName, referralCode: referralCode || undefined, otpChannel },
      });
      onRegistered(phone, data?.otp);
    } catch (e) {
      Alert.alert('Signup failed', e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <KeyboardSafeScroll contentContainerStyle={{ flexGrow: 1 }}>
        <View style={s.loginWrap}>
          <View style={s.loginLogoWrap}>
            <Image source={require('./assets/icon.png')} style={{ width: 44, height: 44, borderRadius: 10 }} resizeMode="contain" />
          </View>
          <Text style={s.loginTitle}>Create Account</Text>
          <Text style={s.loginSubtitle}>Sign up to get started</Text>

          <TextInput style={s.input} placeholder="Full name" placeholderTextColor={colors.subtext} value={fullName} onChangeText={setFullName} />
          <TextInput style={s.input} placeholder="Phone number" placeholderTextColor={colors.subtext} keyboardType="phone-pad" value={phone} onChangeText={setPhone} />
          <TextInput style={s.input} placeholder="Email address" placeholderTextColor={colors.subtext} keyboardType="email-address" autoCapitalize="none" autoCorrect={false} value={email} onChangeText={setEmail} />
          <TextInput style={s.input} placeholder="Password" placeholderTextColor={colors.subtext} secureTextEntry value={password} onChangeText={setPassword} />
          <TextInput style={s.input} placeholder="Referral code (optional)" placeholderTextColor={colors.subtext} autoCapitalize="characters" value={referralCode} onChangeText={setReferralCode} />

          <Text style={{ color: colors.subtext, fontSize: 12.5, fontWeight: '600', marginBottom: 8 }}>Send my verification code via</Text>
          <View style={{ flexDirection: 'row', marginBottom: 18 }}>
            {[{ key: 'both', label: 'Both' }, { key: 'sms', label: 'SMS' }, { key: 'email', label: 'Email' }].map((opt) => (
              <TouchableOpacity
                key={opt.key}
                onPress={() => setOtpChannel(opt.key)}
                style={{
                  flex: 1, paddingVertical: 10, borderRadius: 10, marginRight: opt.key !== 'email' ? 8 : 0,
                  alignItems: 'center', borderWidth: 2,
                  borderColor: otpChannel === opt.key ? colors.accent : colors.inputBorder,
                  backgroundColor: otpChannel === opt.key ? colors.accent : 'transparent',
                }}
              >
                <Text style={{ color: otpChannel === opt.key ? '#fff' : colors.text, fontWeight: '700', fontSize: 13 }}>{opt.label}</Text>
              </TouchableOpacity>
            ))}
          </View>

          <TouchableOpacity
            onPress={() => setAgreedToTerms((v) => !v)}
            style={{ flexDirection: 'row', alignItems: 'flex-start', marginBottom: 18, marginTop: 2 }}
          >
            <View style={{
              width: 20, height: 20, borderRadius: 5, borderWidth: 2, marginRight: 10, marginTop: 1,
              borderColor: agreedToTerms ? colors.accent : colors.inputBorder,
              backgroundColor: agreedToTerms ? colors.accent : 'transparent',
              justifyContent: 'center', alignItems: 'center',
            }}>
              {agreedToTerms && <Ionicons name="checkmark" size={14} color="#fff" />}
            </View>
            <Text style={{ flex: 1, color: colors.subtext, fontSize: 12.5, lineHeight: 18 }}>
              I agree to the{' '}
              <Text style={{ color: colors.accent, fontWeight: '600' }} onPress={() => onOpenLegal('terms')}>Terms of Service</Text>
              {' '}and{' '}
              <Text style={{ color: colors.accent, fontWeight: '600' }} onPress={() => onOpenLegal('privacy')}>Privacy Policy</Text>
            </Text>
          </TouchableOpacity>

          <TouchableOpacity style={s.loginBtn} onPress={handleSignup} disabled={loading}>
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Sign Up</Text>}
          </TouchableOpacity>

          <TouchableOpacity onPress={onSwitchToLogin} style={{ marginTop: 18, alignItems: 'center' }}>
            <Text style={{ color: colors.subtext }}>
              Already have an account? <Text style={{ color: colors.accent, fontWeight: '600' }}>Login</Text>
            </Text>
          </TouchableOpacity>
        </View>
      </KeyboardSafeScroll>
    </SafeAreaView>
  );
}

// ─── Login Screen ───────────────────────────────────────────────────────────
function LoginScreen({ onLoggedIn, onSwitchToSignup, onForgotPassword }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    if (!identifier || !password) return Alert.alert('Missing info', 'Enter your phone number or email and password');
    setLoading(true);
    try {
      const data = await api('/api/v1/auth/login', { method: 'POST', body: { identifier: identifier.trim(), password } });
      await AsyncStorage.setItem('accessToken', data.accessToken);
      await AsyncStorage.setItem('refreshToken', data.refreshToken);
      onLoggedIn(data.user, data.accessToken, data.refreshToken);
    } catch (e) {
      Alert.alert('Login failed', e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <KeyboardSafeScroll contentContainerStyle={{ flexGrow: 1 }}>
        <View style={s.loginWrap}>
          <View style={s.loginLogoWrap}>
            <Image source={require('./assets/icon.png')} style={{ width: 44, height: 44, borderRadius: 10 }} resizeMode="contain" />
          </View>
          <Text style={s.loginTitle}>Gora Data</Text>
          <Text style={s.loginSubtitle}>Login to continue</Text>

          <TextInput style={s.input} placeholder="Phone number or Email" placeholderTextColor={colors.subtext} autoCapitalize="none" value={identifier} onChangeText={setIdentifier} />
          <TextInput style={s.input} placeholder="Password" placeholderTextColor={colors.subtext} secureTextEntry value={password} onChangeText={setPassword} />

          <TouchableOpacity style={s.loginBtn} onPress={handleLogin} disabled={loading}>
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Login</Text>}
          </TouchableOpacity>

          <TouchableOpacity onPress={onForgotPassword} style={{ marginTop: 14, alignItems: 'center' }}>
            <Text style={{ color: colors.accent, fontWeight: '600' }}>Forgot Password?</Text>
          </TouchableOpacity>

          <TouchableOpacity onPress={onSwitchToSignup} style={{ marginTop: 18, alignItems: 'center' }}>
            <Text style={{ color: colors.subtext }}>
              Don't have an account? <Text style={{ color: colors.accent, fontWeight: '600' }}>Sign Up</Text>
            </Text>
          </TouchableOpacity>
        </View>
      </KeyboardSafeScroll>
    </SafeAreaView>
  );
}

// ─── Forgot Password Screen ─────────────────────────────────────────────────
// Two steps: (1) enter identifier, (2) explicitly choose where the code should
// go (SMS or Email) — mirrors ForgotPinScreen's pattern instead of guessing the
// channel from whether the identifier looks like an email or a phone number.
function ForgotPasswordScreen({ onBack, onCodeSent }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [step, setStep] = useState('identifier'); // 'identifier' | 'method'
  const [identifier, setIdentifier] = useState('');
  const [method, setMethod] = useState(null);
  const [loading, setLoading] = useState(false);

  const goToMethod = () => {
    if (!identifier.trim()) return Alert.alert('Missing info', 'Enter your email or phone number');
    setStep('method');
  };

  const requestCode = async (chosenMethod) => {
    setMethod(chosenMethod);
    setLoading(true);
    try {
      const data = await api('/api/v1/auth/forgot-password', { method: 'POST', body: { identifier: identifier.trim(), method: chosenMethod } });
      onCodeSent(identifier.trim(), data.userId, chosenMethod);
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <KeyboardSafeScroll contentContainerStyle={{ flexGrow: 1 }}>
        <View style={s.loginWrap}>
          <TouchableOpacity onPress={step === 'method' ? () => setStep('identifier') : onBack} style={{ position: 'absolute', top: 20, left: 20 }}>
            <Ionicons name="arrow-back" size={24} color={colors.text} />
          </TouchableOpacity>
          <Text style={s.loginTitle}>Forgot Password</Text>

          {step === 'identifier' && (
            <>
              <Text style={s.loginSubtitle}>Enter your email or phone number to continue</Text>
              <TextInput
                style={s.input}
                placeholder="Email or phone number"
                placeholderTextColor={colors.subtext}
                value={identifier}
                onChangeText={setIdentifier}
                autoCapitalize="none"
              />
              <TouchableOpacity style={s.loginBtn} onPress={goToMethod}>
                <Text style={s.loginBtnText}>Continue</Text>
              </TouchableOpacity>
            </>
          )}

          {step === 'method' && (
            <>
              <Text style={s.loginSubtitle}>Where should we send your reset code?</Text>
              <TouchableOpacity style={s.loginBtn} onPress={() => requestCode('sms')} disabled={loading}>
                {loading && method === 'sms' ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Send code via SMS</Text>}
              </TouchableOpacity>
              <TouchableOpacity style={[s.loginBtn, { marginTop: 12 }]} onPress={() => requestCode('email')} disabled={loading}>
                {loading && method === 'email' ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Send code via Email</Text>}
              </TouchableOpacity>
            </>
          )}
        </View>
      </KeyboardSafeScroll>
    </SafeAreaView>
  );
}

// ─── Verify Reset Code Screen ───────────────────────────────────────────────
function VerifyResetCodeScreen({ identifier, userId, method, onBack, onVerified }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [cooldown, setCooldown] = useState(60);

  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setInterval(() => setCooldown((c) => Math.max(0, c - 1)), 1000);
    return () => clearInterval(t);
  }, [cooldown]);

  const handleVerify = async () => {
    if (code.length !== 6) return Alert.alert('Invalid code', 'Enter the 6-digit code');
    setLoading(true);
    try {
      const data = await api('/api/v1/auth/verify-reset-code', { method: 'POST', body: { userId, code } });
      onVerified(data.resetToken);
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (cooldown > 0 || resending) return;
    setResending(true);
    try {
      await api('/api/v1/auth/forgot-password', { method: 'POST', body: { identifier, method } });
      setCooldown(60);
      Alert.alert('Code sent', `A new code was sent to ${identifier}`);
    } catch (e) {
      Alert.alert('Could not resend', e.message);
    } finally {
      setResending(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <KeyboardSafeScroll contentContainerStyle={{ flexGrow: 1 }}>
        <View style={s.loginWrap}>
          <TouchableOpacity onPress={onBack} style={{ position: 'absolute', top: 20, left: 20 }}>
            <Ionicons name="arrow-back" size={24} color={colors.text} />
          </TouchableOpacity>
          <Text style={s.loginTitle}>Enter Code</Text>
          <Text style={s.loginSubtitle}>We sent a 6-digit code to {identifier}</Text>
          <TextInput
            style={[s.input, { textAlign: 'center', fontSize: 20, letterSpacing: 8 }]}
            placeholder="123456"
            placeholderTextColor={colors.subtext}
            keyboardType="number-pad"
            maxLength={6}
            value={code}
            onChangeText={setCode}
          />
          <TouchableOpacity style={s.loginBtn} onPress={handleVerify} disabled={loading}>
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Verify</Text>}
          </TouchableOpacity>
          <TouchableOpacity onPress={handleResend} disabled={cooldown > 0 || resending} style={{ marginTop: 18, alignItems: 'center' }}>
            {resending ? (
              <ActivityIndicator color={colors.accent} size="small" />
            ) : (
              <Text style={{ color: cooldown > 0 ? colors.subtext : colors.accent, fontSize: 13.5, fontWeight: '600' }}>
                {cooldown > 0 ? `Resend code in ${cooldown}s` : 'Resend code'}
              </Text>
            )}
          </TouchableOpacity>
        </View>
      </KeyboardSafeScroll>
    </SafeAreaView>
  );
}

// ─── Reset Password Screen ──────────────────────────────────────────────────
function ResetPasswordScreen({ resetToken, onDone }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [loading, setLoading] = useState(false);

  const handleReset = async () => {
    if (password.length < 6) return Alert.alert('Weak password', 'Password must be at least 6 characters');
    if (password !== confirm) return Alert.alert('Mismatch', 'Passwords do not match');
    setLoading(true);
    try {
      await api('/api/v1/auth/reset-password', { method: 'POST', body: { resetToken, newPassword: password } });
      Alert.alert('Success', 'Password reset. Please log in.', [{ text: 'OK', onPress: onDone }]);
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <KeyboardSafeScroll contentContainerStyle={{ flexGrow: 1 }}>
        <View style={s.loginWrap}>
          <Text style={s.loginTitle}>New Password</Text>
          <Text style={s.loginSubtitle}>Choose a new password for your account</Text>
          <TextInput style={s.input} placeholder="New password" placeholderTextColor={colors.subtext} secureTextEntry value={password} onChangeText={setPassword} />
          <TextInput style={s.input} placeholder="Confirm password" placeholderTextColor={colors.subtext} secureTextEntry value={confirm} onChangeText={setConfirm} />
          <TouchableOpacity style={s.loginBtn} onPress={handleReset} disabled={loading}>
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Reset Password</Text>}
          </TouchableOpacity>
        </View>
      </KeyboardSafeScroll>
    </SafeAreaView>
  );
}

// ─── Change Phone Screen ─── NEW ────────────────────────────────────────────
// ─── Change/Set Transaction PIN Screen (from Settings) ──────────────────────
function ChangePasswordScreen({ token, onBack }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const submit = async () => {
    if (!oldPassword) return Alert.alert('Missing password', 'Enter your current password');
    if (newPassword.length < 8) return Alert.alert('Password too short', 'New password must be at least 8 characters');
    if (newPassword !== confirmPassword) return Alert.alert('Mismatch', "Passwords don't match");

    setSubmitting(true);
    try {
      await api('/api/v1/user/password/change', { method: 'POST', token, body: { oldPassword, newPassword } });
      Alert.alert('Updated', 'Your password has been changed', [{ text: 'OK', onPress: onBack }]);
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Change Password</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <ScrollView style={s.body} keyboardShouldPersistTaps="handled">
          <Text style={{ color: colors.subtext, marginBottom: 16 }}>
            Choose a new password. You'll use it the next time you log in.
          </Text>
          <TextInput
            style={s.input}
            placeholder="Current password"
            placeholderTextColor={colors.subtext}
            secureTextEntry
            autoCapitalize="none"
            value={oldPassword}
            onChangeText={setOldPassword}
          />
          <TextInput
            style={s.input}
            placeholder="New password (min 8 characters)"
            placeholderTextColor={colors.subtext}
            secureTextEntry
            autoCapitalize="none"
            value={newPassword}
            onChangeText={setNewPassword}
          />
          <TextInput
            style={s.input}
            placeholder="Confirm new password"
            placeholderTextColor={colors.subtext}
            secureTextEntry
            autoCapitalize="none"
            value={confirmPassword}
            onChangeText={setConfirmPassword}
          />
          <TouchableOpacity style={s.loginBtn} onPress={submit} disabled={submitting}>
            {submitting ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Update Password</Text>}
          </TouchableOpacity>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function ChangePinScreen({ token, user, onBack, onForgotPin }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [loading, setLoading] = useState(true);
  const [hasPin, setHasPin] = useState(false);
  const [oldPin, setOldPin] = useState('');
  const [newPin, setNewPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const status = await api('/api/v1/user/pin/status', { token });
        setHasPin(!!status?.hasPin);
      } catch (e) {
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const submit = async () => {
    if (!/^\d{4}$/.test(newPin)) return Alert.alert('Invalid PIN', 'New PIN must be exactly 4 digits');
    if (newPin !== confirmPin) return Alert.alert('Mismatch', "PINs don't match");
    if (hasPin && !/^\d{4}$/.test(oldPin)) return Alert.alert('Missing PIN', 'Enter your current PIN');

    setSubmitting(true);
    try {
      if (hasPin) {
        await api('/api/v1/user/pin/change', { method: 'POST', token, body: { oldPin, newPin } });
        Alert.alert('Updated', 'Your transaction PIN has been changed', [{ text: 'OK', onPress: onBack }]);
      } else {
        await api('/api/v1/user/pin/set', { method: 'POST', token, body: { pin: newPin } });
        Alert.alert('Set Up', 'Your transaction PIN is ready', [{ text: 'OK', onPress: onBack }]);
      }
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <SafeAreaView style={[s.safeArea, { justifyContent: 'center', alignItems: 'center' }]}>
        <ActivityIndicator color={colors.accent} />
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>{hasPin ? 'Change Transaction PIN' : 'Set Up Transaction PIN'}</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <ScrollView style={s.body} keyboardShouldPersistTaps="handled">
          <Text style={{ color: colors.subtext, marginBottom: 16 }}>
            {hasPin
              ? 'This PIN is required to confirm every purchase and withdrawal.'
              : "Choose a 4-digit PIN — you'll need it to confirm every purchase and withdrawal."}
          </Text>
          {hasPin && (
            <>
              <TextInput
                style={s.input}
                placeholder="Current PIN"
                placeholderTextColor={colors.subtext}
                keyboardType="number-pad"
                maxLength={4}
                secureTextEntry
                value={oldPin}
                onChangeText={(t) => setOldPin(t.replace(/\D/g, ''))}
              />
              <TouchableOpacity onPress={onForgotPin} style={{ marginBottom: 16 }}>
                <Text style={{ color: colors.accent, fontSize: 13, fontWeight: '600' }}>Forgot your PIN?</Text>
              </TouchableOpacity>
            </>
          )}
          <TextInput
            style={s.input}
            placeholder={hasPin ? 'New PIN' : '4-digit PIN'}
            placeholderTextColor={colors.subtext}
            keyboardType="number-pad"
            maxLength={4}
            secureTextEntry
            value={newPin}
            onChangeText={(t) => setNewPin(t.replace(/\D/g, ''))}
          />
          <TextInput
            style={s.input}
            placeholder="Confirm PIN"
            placeholderTextColor={colors.subtext}
            keyboardType="number-pad"
            maxLength={4}
            secureTextEntry
            value={confirmPin}
            onChangeText={(t) => setConfirmPin(t.replace(/\D/g, ''))}
          />
          <TouchableOpacity style={s.loginBtn} onPress={submit} disabled={submitting}>
            {submitting ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>{hasPin ? 'Update PIN' : 'Set PIN'}</Text>}
          </TouchableOpacity>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// 3-step self-service PIN recovery: choose SMS/email → enter OTP → set new PIN.
// Mirrors ChangePhoneScreen's request/verify pattern. Requires the user to already be
// logged in (this screen only reachable from inside ChangePinScreen, which is auth-gated).
function ForgotPinScreen({ token, user, onBack, onReset }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [step, setStep] = useState('method'); // 'method' | 'verify' | 'newPin'
  const [method, setMethod] = useState(null);
  const [code, setCode] = useState('');
  const [resetToken, setResetToken] = useState(null);
  const [newPin, setNewPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [loading, setLoading] = useState(false);

  const requestCode = async (chosenMethod) => {
    setMethod(chosenMethod);
    setLoading(true);
    try {
      await api('/api/v1/user/pin/forgot', { method: 'POST', token, body: { method: chosenMethod } });
      setStep('verify');
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  };

  const verifyCode = async () => {
    if (code.length !== 6) return Alert.alert('Invalid code', 'Enter the 6-digit code');
    setLoading(true);
    try {
      const data = await api('/api/v1/user/pin/verify-reset-code', { method: 'POST', token, body: { code } });
      setResetToken(data?.resetToken);
      setStep('newPin');
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  };

  const submitNewPin = async () => {
    if (!/^\d{4}$/.test(newPin)) return Alert.alert('Invalid PIN', 'New PIN must be exactly 4 digits');
    if (newPin !== confirmPin) return Alert.alert('Mismatch', "PINs don't match");
    setLoading(true);
    try {
      await api('/api/v1/user/pin/reset', { method: 'POST', token, body: { resetToken, newPin } });
      Alert.alert('PIN Reset', 'Your transaction PIN has been reset', [{ text: 'OK', onPress: onReset }]);
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Reset Transaction PIN</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <ScrollView style={s.body} keyboardShouldPersistTaps="handled">
          {step === 'method' && (
            <>
              <Text style={{ color: colors.subtext, marginBottom: 16 }}>
                We'll send a verification code to confirm it's really you before resetting your PIN.
              </Text>
              {user?.phone && (
                <TouchableOpacity style={s.loginBtn} onPress={() => requestCode('sms')} disabled={loading}>
                  {loading && method === 'sms' ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Send code via SMS</Text>}
                </TouchableOpacity>
              )}
              {user?.email && (
                <TouchableOpacity style={[s.loginBtn, { marginTop: 12 }]} onPress={() => requestCode('email')} disabled={loading}>
                  {loading && method === 'email' ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Send code via Email</Text>}
                </TouchableOpacity>
              )}
            </>
          )}

          {step === 'verify' && (
            <>
              <Text style={{ color: colors.subtext, marginBottom: 16 }}>
                Enter the 6-digit code sent to your {method === 'sms' ? 'phone' : 'email'}.
              </Text>
              <TextInput
                style={s.input}
                placeholder="6-digit code"
                placeholderTextColor={colors.subtext}
                keyboardType="number-pad"
                maxLength={6}
                value={code}
                onChangeText={(t) => setCode(t.replace(/\D/g, ''))}
              />
              <TouchableOpacity style={s.loginBtn} onPress={verifyCode} disabled={loading}>
                {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Verify Code</Text>}
              </TouchableOpacity>
            </>
          )}

          {step === 'newPin' && (
            <>
              <Text style={{ color: colors.subtext, marginBottom: 16 }}>Choose your new 4-digit transaction PIN.</Text>
              <TextInput
                style={s.input}
                placeholder="New PIN"
                placeholderTextColor={colors.subtext}
                keyboardType="number-pad"
                maxLength={4}
                secureTextEntry
                value={newPin}
                onChangeText={(t) => setNewPin(t.replace(/\D/g, ''))}
              />
              <TextInput
                style={s.input}
                placeholder="Confirm New PIN"
                placeholderTextColor={colors.subtext}
                keyboardType="number-pad"
                maxLength={4}
                secureTextEntry
                value={confirmPin}
                onChangeText={(t) => setConfirmPin(t.replace(/\D/g, ''))}
              />
              <TouchableOpacity style={s.loginBtn} onPress={submitNewPin} disabled={loading}>
                {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Reset PIN</Text>}
              </TouchableOpacity>
            </>
          )}
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function ChangePhoneScreen({ token, currentPhone, onBack, onChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [step, setStep] = useState('request'); // 'request' | 'verify'
  const [newPhone, setNewPhone] = useState('');
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);

  const requestChange = async () => {
    if (!newPhone || newPhone.length < 10) return Alert.alert('Invalid phone', 'Enter a valid new phone number');
    if (newPhone === currentPhone) return Alert.alert('Same number', 'This is already your current phone number');
    setLoading(true);
    try {
      await api('/api/v1/auth/change-phone/request', { method: 'POST', token, body: { newPhone } });
      setStep('verify');
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  };

  const verifyChange = async () => {
    if (code.length !== 6) return Alert.alert('Invalid code', 'Enter the 6-digit code');
    setLoading(true);
    try {
      const data = await api('/api/v1/auth/change-phone/verify', { method: 'POST', token, body: { code } });
      Alert.alert('Success', 'Phone number updated', [{ text: 'OK', onPress: () => onChanged(data?.phone || newPhone) }]);
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Change Phone Number</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <ScrollView style={s.body} keyboardShouldPersistTaps="handled">
          {step === 'request' ? (
            <>
              <Text style={{ color: colors.subtext, marginBottom: 16 }}>Current number: {currentPhone || '—'}</Text>
              <TextInput
                style={s.input}
                placeholder="New phone number"
                placeholderTextColor={colors.subtext}
                keyboardType="phone-pad"
                value={newPhone}
                onChangeText={setNewPhone}
              />
              <TouchableOpacity style={s.loginBtn} onPress={requestChange} disabled={loading}>
                {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Send Verification Code</Text>}
              </TouchableOpacity>
            </>
          ) : (
            <>
              <Text style={{ color: colors.subtext, marginBottom: 16 }}>Enter the code sent to {newPhone}</Text>
              <TextInput
                style={[s.input, { textAlign: 'center', fontSize: 20, letterSpacing: 8 }]}
                placeholder="123456"
                placeholderTextColor={colors.subtext}
                keyboardType="number-pad"
                maxLength={6}
                value={code}
                onChangeText={setCode}
              />
              <TouchableOpacity style={s.loginBtn} onPress={verifyChange} disabled={loading}>
                {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Verify & Update</Text>}
              </TouchableOpacity>
              <TouchableOpacity onPress={() => setStep('request')} style={{ marginTop: 16, alignItems: 'center' }}>
                <Text style={{ color: colors.accent, fontWeight: '600' }}>Use a different number</Text>
              </TouchableOpacity>
            </>
          )}
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Change Email Screen ─── NEW ────────────────────────────────────────────
function ChangeEmailScreen({ token, currentEmail, onBack, onChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [step, setStep] = useState('request'); // 'request' | 'verify'
  const [newEmail, setNewEmail] = useState('');
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);

  const requestChange = async () => {
    if (!newEmail || !newEmail.includes('@')) return Alert.alert('Invalid email', 'Enter a valid email address');
    if (newEmail === currentEmail) return Alert.alert('Same email', 'This is already your current email');
    setLoading(true);
    try {
      await api('/api/v1/auth/change-email/request', { method: 'POST', token, body: { newEmail } });
      setStep('verify');
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  };

  const verifyChange = async () => {
    if (code.length !== 6) return Alert.alert('Invalid code', 'Enter the 6-digit code');
    setLoading(true);
    try {
      const data = await api('/api/v1/auth/change-email/verify', { method: 'POST', token, body: { code } });
      Alert.alert('Success', 'Email address updated', [{ text: 'OK', onPress: () => onChanged(data?.email || newEmail) }]);
    } catch (e) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Change Email Address</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <ScrollView style={s.body} keyboardShouldPersistTaps="handled">
          {step === 'request' ? (
            <>
              <Text style={{ color: colors.subtext, marginBottom: 16 }}>Current email: {currentEmail || 'Not set'}</Text>
              <TextInput
                style={s.input}
                placeholder="New email address"
                placeholderTextColor={colors.subtext}
                keyboardType="email-address"
                autoCapitalize="none"
                value={newEmail}
                onChangeText={setNewEmail}
              />
              <TouchableOpacity style={s.loginBtn} onPress={requestChange} disabled={loading}>
                {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Send Verification Code</Text>}
              </TouchableOpacity>
            </>
          ) : (
            <>
              <Text style={{ color: colors.subtext, marginBottom: 16 }}>Enter the code sent to {newEmail}</Text>
              <TextInput
                style={[s.input, { textAlign: 'center', fontSize: 20, letterSpacing: 8 }]}
                placeholder="123456"
                placeholderTextColor={colors.subtext}
                keyboardType="number-pad"
                maxLength={6}
                value={code}
                onChangeText={setCode}
              />
              <TouchableOpacity style={s.loginBtn} onPress={verifyChange} disabled={loading}>
                {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Verify & Update</Text>}
              </TouchableOpacity>
              <TouchableOpacity onPress={() => setStep('request')} style={{ marginTop: 16, alignItems: 'center' }}>
                <Text style={{ color: colors.accent, fontWeight: '600' }}>Use a different email</Text>
              </TouchableOpacity>
            </>
          )}
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Account Settings Screen ─── NEW ────────────────────────────────────────
// ─── Support ─────────────────────────────────────────────────────────────────
const SUPPORT_WHATSAPP_RAW = '+2340712091041';
const SUPPORT_CALL_NUMBER = '+2347012091041';
const SUPPORT_EMAIL = 'jibirabubakar860@gmail.com';
const APP_NAME = 'Gora Data';
const LEGAL_LAST_UPDATED = 'July 24, 2026';

// ─── Terms of Service & Privacy Policy content ─────────────────────────────
// Plain-text content rendered by LegalDocScreen below. Kept as data (not JSX)
// so the same copy can be reused for the in-app screen, the signup consent
// checkbox link, and — if hosted later — a plain webpage for the Play Store
// listing's Privacy Policy URL field.
const TERMS_OF_SERVICE_TEXT = `Last updated: ${LEGAL_LAST_UPDATED}

1. Acceptance of Terms
By creating an account or using ${APP_NAME}, you agree to these Terms of Service. If you do not agree, please do not use the app.

2. What ${APP_NAME} Does
${APP_NAME} lets you fund an in-app wallet and use that balance to buy data, airtime, electricity tokens, cable subscriptions, exam pins, and similar digital services, and to withdraw your wallet balance to a linked bank account.

3. Eligibility & Identity Verification
You must be able to form a binding contract to use this app. Certain actions — including funding your wallet and withdrawing funds — require identity verification (BVN or NIN) as required by Nigerian financial regulations. We may suspend wallet-related features until verification is complete.

4. Your Account
You are responsible for keeping your password and device secure. Enabling a transaction PIN and biometric login is strongly recommended. You must notify us immediately if you suspect unauthorized access to your account.

5. Wallet Funds
Your wallet balance is not a bank deposit and does not earn interest. Funds are held to facilitate purchases and withdrawals within the app. We reserve the right to freeze a wallet where fraud, chargebacks, or suspicious activity is suspected, pending review.

6. Transactions
Purchases (data, airtime, electricity, cable, etc.) are typically final once submitted to the relevant network or provider. Withdrawals are sent to the bank account you provide — please double-check account details before confirming, as we cannot guarantee reversal of funds sent to an incorrect account you supplied.

7. Fees
Certain transactions (e.g. withdrawals) may carry a service fee, shown to you before you confirm the transaction.

8. Prohibited Use
You may not use ${APP_NAME} for money laundering, fraud, or any illegal purpose, or to circumvent the transaction limits or verification requirements of any network or payment provider we work with.

9. Suspension & Termination
We may suspend or close an account that violates these terms, is used fraudulently, or where required by law or our payment partners.

10. Limitation of Liability
${APP_NAME} is provided "as is." We are not liable for delays or failures caused by third-party networks, banks, or payment providers, though we will work in good faith to help resolve failed or stuck transactions.

11. Changes to These Terms
We may update these Terms from time to time. Continued use of the app after a change means you accept the updated Terms.

12. Contact
Questions about these Terms? Reach us at ${SUPPORT_EMAIL} or WhatsApp +${SUPPORT_WHATSAPP_RAW.replace('+', '')}.`;

const PRIVACY_POLICY_TEXT = `Last updated: ${LEGAL_LAST_UPDATED}

1. Information We Collect
- Account details: full name, phone number, email address, password (stored securely, never in plain text).
- Identity verification: BVN or NIN, collected only when required to enable wallet funding or withdrawal, as required by Nigerian financial regulations.
- Transaction data: records of purchases, funding, and withdrawals made through your account, including amounts, timestamps, and status.
- Bank details you provide for withdrawals (account number and bank name).
- Device information: push notification token, device type, and app version, used to deliver notifications and diagnose issues.

2. How We Use Your Information
- To create and secure your account, and verify your identity where required.
- To process purchases, wallet funding, and withdrawals.
- To send you transaction receipts, security alerts, and service notifications.
- To detect and prevent fraud, and to comply with applicable law.
- To provide customer support when you contact us.

3. How We Share Your Information
We share the minimum information necessary with:
- Payment and verification partners (e.g. Flutterwave) to process funding, withdrawals, and identity checks.
- Network/service providers (e.g. data, airtime, electricity providers) to fulfill the specific purchase you request.
We do not sell your personal information to advertisers or third parties.

4. Data Storage & Security
Your data is stored with reputable infrastructure providers using encryption in transit. Passwords are hashed, not stored in plain text. Access to identity verification data (BVN/NIN) is restricted to what's needed to operate the wallet service.

5. Your Rights
You can:
- Review and update your phone number and email address in the app.
- Request a copy of the personal data we hold about you.
- Request deletion of your account and associated personal data (see Account Deletion in Settings), subject to any records we are legally required to retain (e.g. transaction records for financial compliance).

6. Data Retention
We retain transaction and verification records for as long as required by applicable financial regulations, even after an account is deleted, where legally necessary.

7. Children
${APP_NAME} is not intended for use by anyone under 18, as it involves financial transactions requiring legal capacity to contract.

8. Changes to This Policy
We may update this Privacy Policy from time to time. Continued use of the app after a change means you accept the updated Policy.

9. Contact
Questions about your data or this Policy? Reach us at ${SUPPORT_EMAIL} or WhatsApp +${SUPPORT_WHATSAPP_RAW.replace('+', '')}.`;

// ─── Legal document viewer (Terms of Service / Privacy Policy) ────────────
function LegalDocScreen({ title, text, onBack }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>{title}</Text>
      </View>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }}>
        <Text style={{ color: colors.text, fontSize: 13.5, lineHeight: 21 }}>{text}</Text>
      </ScrollView>
    </SafeAreaView>
  );
}

// Normalizes into the digits-only format WhatsApp's deep link expects
// (country code with no leading zero on the subscriber number).
function toWhatsAppNumber(raw) {
  let digits = raw.replace(/[^\d]/g, '');
  if (digits.startsWith('2340')) digits = '234' + digits.slice(4);
  return digits;
}

function SupportScreen({ onBack }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);

  const openWhatsApp = () => {
    const number = toWhatsAppNumber(SUPPORT_WHATSAPP_RAW);
    Linking.openURL(`https://wa.me/${number}`).catch(() => Alert.alert('Could not open WhatsApp', `Message us directly at +${number}`));
  };
  const openCall = () => {
    Linking.openURL(`tel:${SUPPORT_CALL_NUMBER}`).catch(() => Alert.alert('Could not start call', SUPPORT_CALL_NUMBER));
  };
  const openEmail = () => {
    Linking.openURL(`mailto:${SUPPORT_EMAIL}?subject=${encodeURIComponent('Gora Data Support')}`).catch(() => Alert.alert('Could not open mail app', SUPPORT_EMAIL));
  };

  const options = [
    { key: 'whatsapp', icon: 'logo-whatsapp', label: 'Chat on WhatsApp', sub: `+${toWhatsAppNumber(SUPPORT_WHATSAPP_RAW)}`, onPress: openWhatsApp, color: '#25D366' },
    { key: 'call', icon: 'call-outline', label: 'Call Support', sub: SUPPORT_CALL_NUMBER, onPress: openCall, color: colors.accent },
    { key: 'email', icon: 'mail-outline', label: 'Email Support', sub: SUPPORT_EMAIL, onPress: openEmail, color: colors.accent },
  ];

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Help & Support</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={{ color: colors.subtext, marginBottom: 16 }}>
          Need help with a transaction, a wallet issue, or anything else? Reach us directly below.
        </Text>
        {options.map((o) => (
          <TouchableOpacity key={o.key} style={s.notifCard} onPress={o.onPress}>
            <View style={[s.notifIconWrap, { backgroundColor: colors.iconWrap }]}>
              <Ionicons name={o.icon} size={20} color={o.color} />
            </View>
            <View style={{ flex: 1 }}>
              <Text style={s.notifTitle}>{o.label}</Text>
              <Text style={s.notifTime}>{o.sub}</Text>
            </View>
            <Ionicons name="chevron-forward" size={18} color={colors.subtext} />
          </TouchableOpacity>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Delete Account Screen ─────────────────────────────────────────────────
function DeleteAccountScreen({ token, onBack, onDeleted, onLogout }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);

  const [loading, setLoading] = useState(true);
  const [balance, setBalance] = useState(0);
  const [status, setStatus] = useState('none');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [wallet, deletion] = await Promise.all([
        api('/api/v1/wallet', { token }),
        api('/api/v1/account/deletion-status', { token }),
      ]);
      setBalance(parseFloat(wallet?.balance || 0));
      setStatus(deletion?.deletion_status || 'none');
    } catch (e) {} finally { setLoading(false); }
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const submitRequest = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setBusy(true);
    try {
      await api('/api/v1/account/delete-request', { method: 'POST', token, body: { pin, reason } });
      Alert.alert('Request Submitted', 'Your account deletion request has been received. This is usually processed within 30 days.');
      setStatus('pending');
    } catch (e) {
      Alert.alert('Could not submit request', e.message);
    } finally {
      setBusy(false);
    }
  };

  const confirmDelete = () => {
    Alert.alert(
      'Delete Your Account?',
      'This will permanently remove your personal data (name, email, phone, BVN/NIN) once processed. Transaction records are kept as required by financial regulations. This cannot be undone.',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Continue', style: 'destructive', onPress: submitRequest },
      ]
    );
  };

  const cancelRequest = async () => {
    setBusy(true);
    try {
      await api('/api/v1/account/delete-request/cancel', { method: 'POST', token });
      setStatus('none');
    } catch (e) {
      Alert.alert('Could not cancel request', e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Delete Account</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        {loading ? (
          <ActivityIndicator color={colors.accent} style={{ marginTop: 30 }} />
        ) : status === 'pending' ? (
          <>
            <View style={[s.notifCard, { alignItems: 'flex-start' }]}>
              <Ionicons name="time-outline" size={22} color={colors.accent} style={{ marginBottom: 8 }} />
              <Text style={s.notifTitle}>Deletion request pending</Text>
              <Text style={[s.notifTime, { marginTop: 4 }]}>
                Your account is scheduled for deletion and is being reviewed. You can cancel this request any time before it's processed.
              </Text>
            </View>
            <TouchableOpacity
              style={[s.loginBtn, { marginTop: 20, opacity: busy ? 0.6 : 1 }]}
              onPress={cancelRequest}
              disabled={busy}
            >
              <Text style={s.loginBtnText}>{busy ? 'Cancelling…' : 'Cancel Deletion Request'}</Text>
            </TouchableOpacity>
          </>
        ) : (
          <>
            <Text style={{ color: colors.subtext, marginBottom: 16, lineHeight: 20 }}>
              Deleting your account will remove your personal data (name, email, phone, BVN/NIN) from Gora Data.
              Transaction records are kept where required by financial regulations. Your wallet balance must be ₦0 before you can request deletion.
            </Text>

            <View style={s.notifCard}>
              <View style={[s.notifIconWrap, { backgroundColor: colors.iconWrap }]}>
                <Ionicons name="wallet-outline" size={20} color={colors.accent} />
              </View>
              <View style={{ flex: 1 }}>
                <Text style={s.notifTitle}>Wallet Balance</Text>
                <Text style={s.notifTime}>₦{balance.toLocaleString()}</Text>
              </View>
            </View>

            {balance > 0 ? (
              <View style={[s.notifCard, { marginTop: 12 }]}>
                <Ionicons name="alert-circle-outline" size={20} color="#e74c3c" />
                <Text style={{ color: colors.text, marginLeft: 10, flex: 1 }}>
                  Please withdraw your wallet balance before requesting deletion.
                </Text>
              </View>
            ) : (
              <>
                <Text style={[s.notifTitle, { marginTop: 20, marginBottom: 8 }]}>Reason (optional)</Text>
                <TextInput
                  style={[s.input, { height: 90, textAlignVertical: 'top' }]}
                  placeholder="Let us know why you're leaving (optional)"
                  placeholderTextColor={colors.subtext}
                  value={reason}
                  onChangeText={setReason}
                  multiline
                />
                <TouchableOpacity
                  style={[s.loginBtn, { marginTop: 20, backgroundColor: '#e74c3c', opacity: busy ? 0.6 : 1 }]}
                  onPress={confirmDelete}
                  disabled={busy}
                >
                  <Text style={s.loginBtnText}>{busy ? 'Submitting…' : 'Request Account Deletion'}</Text>
                </TouchableOpacity>
              </>
            )}
          </>
        )}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}


function SettingsScreen({ user, onBack, onNavigate, onLogout }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);

  const [bioSupport, setBioSupport] = useState({ available: false, label: 'Biometric Login' });
  const [bioEnabled, setBioEnabled] = useState(false);
  const [bioBusy, setBioBusy] = useState(false);
  const [txBioEnabled, setTxBioEnabled] = useState(false);
  const [txBioBusy, setTxBioBusy] = useState(false);
  const [hasPin, setHasPin] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        setTxBioEnabled(await isTxBiometricEnabled());
        const status = await api('/api/v1/user/pin/status');
        setHasPin(!!status?.hasPin);
      } catch (e) {}
    })();
  }, []);

  const toggleTxBiometric = async () => {
    if (txBioBusy || !bioSupport.available) return;
    setTxBioBusy(true);
    try {
      if (txBioEnabled) {
        await disableTxBiometric();
        setTxBioEnabled(false);
      } else {
        if (!hasPin) {
          Alert.alert('Set up your PIN first', 'You need a transaction PIN before you can use biometrics for purchases.');
          return;
        }
        const pin = await requestTransactionPin();
        if (!pin) return;
        const confirmed = await promptBiometricUnlock(`Confirm ${bioSupport.label} to enable`);
        if (confirmed) {
          await enableTxBiometric(pin);
          setTxBioEnabled(true);
        } else {
          Alert.alert('Not enabled', `${bioSupport.label} could not be confirmed, so this was left off.`);
        }
      }
    } finally {
      setTxBioBusy(false);
    }
  };

  useEffect(() => {
    (async () => {
      try {
        const support = await getBiometricSupport();
        setBioSupport(support);
        setBioEnabled(support.available && (await isBiometricLoginEnabled()));
      } catch (e) {}
    })();
  }, []);

  const toggleBiometric = async () => {
    if (bioBusy) return;
    setBioBusy(true);
    try {
      if (bioEnabled) {
        await setBiometricLoginEnabled(false);
        setBioEnabled(false);
      } else {
        // Confirm the user can actually authenticate before turning this on —
        // otherwise they could lock themselves out on next launch.
        const confirmed = await promptBiometricUnlock(`Confirm ${bioSupport.label} to enable`);
        if (confirmed) {
          await setBiometricLoginEnabled(true);
          setBioEnabled(true);
        } else {
          Alert.alert('Not enabled', `${bioSupport.label} could not be confirmed, so this was left off.`);
        }
      }
    } finally {
      setBioBusy(false);
    }
  };

  const rows = [
    { key: 'changePhone', icon: 'call-outline', label: 'Change Phone Number', sub: user?.phone || '—' },
    { key: 'changeEmail', icon: 'mail-outline', label: 'Change Email Address', sub: user?.email || 'Not set' },
    { key: 'changePassword', icon: 'lock-closed-outline', label: 'Change Password', sub: 'Update your login password' },
    { key: 'transactionPin', icon: 'keypad-outline', label: hasPin ? 'Change Transaction PIN' : 'Set Up Transaction PIN', sub: hasPin ? 'Required for every purchase' : 'Not set up yet' },
    { key: 'support', icon: 'help-buoy-outline', label: 'Help & Support', sub: 'Chat, call, or email us' },
    { key: 'terms', icon: 'document-text-outline', label: 'Terms of Service', sub: `Last updated ${LEGAL_LAST_UPDATED}` },
    { key: 'privacy', icon: 'shield-outline', label: 'Privacy Policy', sub: `Last updated ${LEGAL_LAST_UPDATED}` },
    { key: 'deleteAccount', icon: 'trash-outline', label: 'Delete Account', sub: 'Permanently delete your account and data' },
  ];

  const confirmLogout = () => {
    Alert.alert('Log Out', 'Are you sure you want to log out?', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Log Out', style: 'destructive', onPress: onLogout },
    ]);
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Profile</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        {rows.map((r) => (
          <TouchableOpacity key={r.key} style={s.notifCard} onPress={() => onNavigate(r.key)}>
            <View style={[s.notifIconWrap, { backgroundColor: colors.iconWrap }]}>
              <Ionicons name={r.icon} size={20} color={colors.accent} />
            </View>
            <View style={{ flex: 1 }}>
              <Text style={s.notifTitle}>{r.label}</Text>
              <Text style={s.notifTime}>{r.sub}</Text>
            </View>
            <Ionicons name="chevron-forward" size={18} color={colors.subtext} />
          </TouchableOpacity>
        ))}

        {bioSupport.available && (
          <View style={s.notifCard}>
            <View style={[s.notifIconWrap, { backgroundColor: colors.iconWrap }]}>
              <Ionicons name={bioSupport.label === 'Face ID' ? 'scan-outline' : 'finger-print-outline'} size={20} color={colors.accent} />
            </View>
            <View style={{ flex: 1 }}>
              <Text style={s.notifTitle}>{bioSupport.label} Login</Text>
              <Text style={s.notifTime}>Unlock Gora on launch instead of typing your password</Text>
            </View>
            <TouchableOpacity
              onPress={toggleBiometric}
              disabled={bioBusy}
              style={{
                width: 46, height: 28, borderRadius: 14, padding: 3,
                backgroundColor: bioEnabled ? colors.accent : colors.inputBorder,
                justifyContent: 'center', opacity: bioBusy ? 0.6 : 1,
              }}
            >
              <View style={{
                width: 22, height: 22, borderRadius: 11, backgroundColor: '#fff',
                alignSelf: bioEnabled ? 'flex-end' : 'flex-start',
              }} />
            </TouchableOpacity>
          </View>
        )}

        {bioSupport.available && hasPin && (
          <View style={s.notifCard}>
            <View style={[s.notifIconWrap, { backgroundColor: colors.iconWrap }]}>
              <Ionicons name={bioSupport.label === 'Face ID' ? 'scan-outline' : 'finger-print-outline'} size={20} color={colors.accent} />
            </View>
            <View style={{ flex: 1 }}>
              <Text style={s.notifTitle}>{bioSupport.label} for Purchases</Text>
              <Text style={s.notifTime}>Use {bioSupport.label} instead of typing your transaction PIN</Text>
            </View>
            <TouchableOpacity
              onPress={toggleTxBiometric}
              disabled={txBioBusy}
              style={{
                width: 46, height: 28, borderRadius: 14, padding: 3,
                backgroundColor: txBioEnabled ? colors.accent : colors.inputBorder,
                justifyContent: 'center', opacity: txBioBusy ? 0.6 : 1,
              }}
            >
              <View style={{
                width: 22, height: 22, borderRadius: 11, backgroundColor: '#fff',
                alignSelf: txBioEnabled ? 'flex-end' : 'flex-start',
              }} />
            </TouchableOpacity>
          </View>
        )}

        <TouchableOpacity style={[s.notifCard, { marginTop: 10 }]} onPress={confirmLogout}>
          <View style={[s.notifIconWrap, { backgroundColor: '#fee2e2' }]}>
            <Ionicons name="log-out-outline" size={20} color="#dc2626" />
          </View>
          <View style={{ flex: 1 }}>
            <Text style={[s.notifTitle, { color: '#dc2626' }]}>Log Out</Text>
          </View>
        </TouchableOpacity>
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Transaction PIN Modal ───────────────────────────────────────────────────
// Mounted once at the app root (see TransactionPinModalHost, rendered from App()).
// Any screen calls the global requestTransactionPin() to pop this up and get back
// either a 4-digit PIN string (typed, or auto-filled via biometrics) or null if the
// user cancelled. It never talks to the purchase route itself — the caller attaches
// the returned pin to its own request body, and the server is the real judge of it.
function PinDots({ length, filled }) {
  const { colors } = useTheme();
  return (
    <View style={{ flexDirection: 'row', justifyContent: 'center', marginVertical: 18 }}>
      {Array.from({ length }).map((_, i) => (
        <View
          key={i}
          style={{
            width: 16, height: 16, borderRadius: 8, marginHorizontal: 8,
            borderWidth: 1.5, borderColor: colors.accent,
            backgroundColor: i < filled ? colors.accent : 'transparent',
          }}
        />
      ))}
    </View>
  );
}

function TransactionPinModal({ visible, onResolve }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [phase, setPhase] = useState('loading'); // loading | setup | enter | biometric
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [offerBiometric, setOfferBiometric] = useState(false);
  const [bioLabel, setBioLabel] = useState('Biometric');
  const enterInputRef = useRef(null);

  useEffect(() => {
    if (!visible) return;
    setPin(''); setConfirmPin(''); setError(''); setBusy(false); setOfferBiometric(false);
    setPhase('loading');
    (async () => {
      try {
        const status = await api('/api/v1/user/pin/status');
        if (!status?.hasPin) { setPhase('setup'); return; }

        const bioOn = await isTxBiometricEnabled();
        if (bioOn) {
          const { available, label } = await getBiometricSupport();
          if (available) {
            setBioLabel(label);
            setPhase('biometric');
            const bioPin = await getPinViaBiometric();
            if (bioPin) { onResolve(bioPin); return; }
          }
        }
        setPhase('enter');
      } catch (e) {
        setError(e.message || 'Could not check PIN status');
        setPhase('enter');
      }
    })();
  }, [visible]);

  const submitSetup = async () => {
    if (!/^\d{4}$/.test(pin)) return setError('PIN must be exactly 4 digits');
    if (pin !== confirmPin) return setError('PINs do not match');
    setBusy(true); setError('');
    try {
      await api('/api/v1/user/pin/set', { method: 'POST', body: { pin } });
      const { available, label } = await getBiometricSupport();
      if (available) {
        setBioLabel(label);
        setOfferBiometric(true);
        setBusy(false);
      } else {
        onResolve(pin);
      }
    } catch (e) {
      setError(e.message || 'Could not set PIN');
      setBusy(false);
    }
  };

  const finishAfterOffer = async (wantsBiometric) => {
    if (wantsBiometric) {
      const confirmed = await promptBiometricUnlock(`Confirm ${bioLabel} to enable`);
      if (confirmed) await enableTxBiometric(pin);
    }
    onResolve(pin);
  };

  const submitEnter = () => {
    if (!/^\d{4}$/.test(pin)) return setError('Enter your 4-digit PIN');
    onResolve(pin);
  };

  const retryBiometric = async () => {
    setPhase('biometric');
    const bioPin = await getPinViaBiometric();
    if (bioPin) { onResolve(bioPin); return; }
    setPhase('enter');
  };

  return (
    <Modal visible={visible} animationType="fade" transparent>
      <View style={s.modalOverlay}>
        <View style={s.modalCard}>
          <View style={s.modalHeader}>
            <Text style={s.modalTitle}>
              {phase === 'setup' ? 'Set Up Transaction PIN' : offerBiometric ? `Use ${bioLabel}?` : 'Enter Transaction PIN'}
            </Text>
            <TouchableOpacity onPress={() => onResolve(null)}>
              <Ionicons name="close" size={24} color={colors.text} />
            </TouchableOpacity>
          </View>

          {phase === 'loading' && (
            <View style={{ paddingVertical: 30, alignItems: 'center' }}>
              <ActivityIndicator color={colors.accent} />
            </View>
          )}

          {phase === 'biometric' && (
            <View style={{ paddingVertical: 30, alignItems: 'center' }}>
              <Ionicons name={bioLabel === 'Face ID' ? 'scan-outline' : 'finger-print-outline'} size={40} color={colors.accent} />
              <Text style={[s.modalHint, { marginTop: 12, textAlign: 'center' }]}>Waiting for {bioLabel}…</Text>
              <TouchableOpacity onPress={() => setPhase('enter')} style={{ marginTop: 14 }}>
                <Text style={{ color: colors.subtext, fontSize: 13, textDecorationLine: 'underline' }}>Type PIN instead</Text>
              </TouchableOpacity>
            </View>
          )}

          {phase === 'setup' && !offerBiometric && (
            <View>
              <Text style={s.modalHint}>Choose a 4-digit PIN. You'll need it to confirm every purchase or withdrawal.</Text>
              <TextInput
                style={s.input}
                placeholder="New 4-digit PIN"
                placeholderTextColor={colors.subtext}
                keyboardType="number-pad"
                maxLength={4}
                secureTextEntry
                value={pin}
                onChangeText={(t) => setPin(t.replace(/\D/g, ''))}
              />
              <TextInput
                style={s.input}
                placeholder="Confirm PIN"
                placeholderTextColor={colors.subtext}
                keyboardType="number-pad"
                maxLength={4}
                secureTextEntry
                value={confirmPin}
                onChangeText={(t) => setConfirmPin(t.replace(/\D/g, ''))}
              />
              {!!error && <Text style={{ color: '#dc2626', fontSize: 13, marginTop: 4 }}>{error}</Text>}
              <TouchableOpacity style={[s.loginBtn, { marginTop: 14 }]} onPress={submitSetup} disabled={busy}>
                {busy ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Set PIN</Text>}
              </TouchableOpacity>
            </View>
          )}

          {phase === 'setup' && offerBiometric && (
            <View>
              <Text style={s.modalHint}>Use {bioLabel} instead of typing your PIN next time?</Text>
              <TouchableOpacity style={[s.loginBtn, { marginTop: 14 }]} onPress={() => finishAfterOffer(true)}>
                <Text style={s.loginBtnText}>Enable {bioLabel}</Text>
              </TouchableOpacity>
              <TouchableOpacity style={{ marginTop: 12, alignItems: 'center' }} onPress={() => finishAfterOffer(false)}>
                <Text style={{ color: colors.subtext, fontSize: 13.5 }}>Not now</Text>
              </TouchableOpacity>
            </View>
          )}

          {phase === 'enter' && (
            <View>
              <Text style={s.modalHint}>Enter your 4-digit transaction PIN to continue.</Text>
              <TouchableOpacity activeOpacity={1} onPress={() => enterInputRef.current?.focus()}>
                <PinDots length={4} filled={pin.length} />
              </TouchableOpacity>
              <TextInput
                ref={enterInputRef}
                style={{ position: 'absolute', opacity: 0, height: 1, width: 1 }}
                autoFocus
                keyboardType="number-pad"
                maxLength={4}
                secureTextEntry
                value={pin}
                onChangeText={(t) => setPin(t.replace(/\D/g, ''))}
                onSubmitEditing={submitEnter}
              />
              {!!error && <Text style={{ color: '#dc2626', fontSize: 13, textAlign: 'center', marginBottom: 6 }}>{error}</Text>}
              <TouchableOpacity style={s.loginBtn} onPress={submitEnter}>
                <Text style={s.loginBtnText}>Confirm</Text>
              </TouchableOpacity>
              {bioLabel !== 'Biometric' && (
                <TouchableOpacity onPress={retryBiometric} style={{ marginTop: 12, alignItems: 'center' }}>
                  <Text style={{ color: colors.subtext, fontSize: 13, textDecorationLine: 'underline' }}>
                    Use {bioLabel} instead
                  </Text>
                </TouchableOpacity>
              )}
            </View>
          )}
        </View>
      </View>
    </Modal>
  );
}

function TransactionPinModalHost() {
  const [resolver, setResolver] = useState(null);

  useEffect(() => {
    _setPinModalHandler((resolveFn) => setResolver(() => resolveFn));
  }, []);

  const handleResolve = (pin) => {
    if (resolver) resolver(pin);
    setResolver(null);
  };

  return <TransactionPinModal visible={!!resolver} onResolve={handleResolve} />;
}

// ─── Fund Wallet Modal ──────────────────────────────────────────────────────
function FundWalletModal({ visible, onClose, token, user, onFunded, onUserRefresh }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [bvn, setBvn] = useState('');
  const [loading, setLoading] = useState(false);
  const [account, setAccount] = useState(null);

  // KYC step state
  const [kycMethod, setKycMethod] = useState('bvn'); // 'bvn' | 'nin'
  const [kycValue, setKycValue] = useState('');
  const [submittingKyc, setSubmittingKyc] = useState(false);

  // Funding method state
  const [method, setMethod] = useState('transfer'); // 'transfer' | 'card' | 'ussd'
  const [amount, setAmount] = useState('');
  const [banks, setBanks] = useState([]);
  const [bankSearch, setBankSearch] = useState('');
  const [showBankPicker, setShowBankPicker] = useState(false);
  const [selectedBank, setSelectedBank] = useState(null);
  const [ussdResult, setUssdResult] = useState(null);
  const [processing, setProcessing] = useState(false);

  useEffect(() => {
    if (visible) {
      setAccount(null);
      setBvn('');
      setAmount('');
      setUssdResult(null);
      setMethod('transfer');
      setSelectedBank(null);
      setBankSearch('');
      setShowBankPicker(false);
      loadExisting();
      loadBanks();
    }
  }, [visible]);

  const loadExisting = async () => {
    try {
      const data = await api('/api/v1/wallet/virtual-account', { token });
      if (data) setAccount(data);
    } catch (e) {}
  };

  const loadBanks = async () => {
    try {
      const data = await api('/api/v1/wallet/fund/ussd/banks', { token });
      setBanks(Array.isArray(data) ? data : []);
    } catch (e) {}
  };

  const submitKyc = async () => {
    if (kycValue.length !== 11) return Alert.alert('Invalid number', `Enter your 11-digit ${kycMethod.toUpperCase()}`);
    setSubmittingKyc(true);
    try {
      await api('/api/v1/kyc/submit', { method: 'POST', token, body: { [kycMethod]: kycValue } });
      Alert.alert('Verified', 'You can now fund and withdraw');
      await onUserRefresh?.();
      loadBanks();
    } catch (e) {
      Alert.alert('Could not verify', e.message);
    } finally {
      setSubmittingKyc(false);
    }
  };

  const createAccount = async () => {
    if (!bvn || bvn.length !== 11) return Alert.alert(`Invalid ${kycMethod.toUpperCase()}`, `Enter your 11-digit ${kycMethod.toUpperCase()}`);
    setLoading(true);
    try {
      const data = await api('/api/v1/wallet/virtual-account', { method: 'POST', body: { [kycMethod]: bvn }, token });
      setAccount(data);
      onFunded && onFunded();
    } catch (e) {
      Alert.alert('Could not create account', e.message);
    } finally {
      setLoading(false);
    }
  };

  const copyAccount = () => {
    Clipboard.setStringAsync(account.accountNumber);
    Alert.alert('Copied', 'Account number copied');
  };

  const fundWithCard = async () => {
    const amt = parseFloat(amount);
    if (!amt || amt < 100) return Alert.alert('Enter an amount', 'Minimum funding amount is ₦100');
    setProcessing(true);
    try {
      const data = await api('/api/v1/wallet/fund/card', { method: 'POST', token, body: { amount: amt } });
      await Linking.openURL(data.paymentLink);
      Alert.alert('Complete payment in your browser', 'Once done, come back here — your wallet updates automatically within a few seconds.');
    } catch (e) {
      if (e.code === 'KYC_REQUIRED') {
        setMethod('transfer');
        Alert.alert('Verify your identity first', 'Switch to the Transfer tab and enter your BVN or NIN — this only takes a moment, then you can fund by card.');
      } else {
        Alert.alert('Could not start payment', e.message);
      }
    } finally {
      setProcessing(false);
    }
  };

  const filteredBanks = bankSearch ? banks.filter((b) => b.name.toLowerCase().includes(bankSearch.toLowerCase())) : banks;

  const fundWithUssd = async () => {
    const amt = parseFloat(amount);
    if (!amt || amt < 100) return Alert.alert('Enter an amount', 'Minimum funding amount is ₦100');
    if (!selectedBank) return Alert.alert('Choose a bank', 'Select the bank you want to dial USSD from');
    setProcessing(true);
    try {
      const data = await api('/api/v1/wallet/fund/ussd', { method: 'POST', token, body: { amount: amt, bankCode: selectedBank.code } });
      setUssdResult(data);
    } catch (e) {
      if (e.code === 'KYC_REQUIRED') {
        setMethod('transfer');
        Alert.alert('Verify your identity first', 'Switch to the Transfer tab and enter your BVN or NIN — this only takes a moment, then you can fund by USSD.');
      } else {
        Alert.alert('Could not generate USSD code', e.message);
      }
    } finally {
      setProcessing(false);
    }
  };

  const copyUssd = () => {
    Clipboard.setStringAsync(ussdResult.ussdCode);
    Alert.alert('Copied', 'Dial this code on your phone');
  };

  return (
    <Modal visible={visible} animationType="slide" transparent>
      <View style={s.modalOverlay}>
        <View style={s.modalCard}>
          <View style={s.modalHeader}>
            <Text style={s.modalTitle}>Fund Wallet</Text>
            <TouchableOpacity onPress={onClose}>
              <Ionicons name="close" size={24} color={colors.text} />
            </TouchableOpacity>
          </View>

          <View>
              <View style={{ flexDirection: 'row', marginBottom: 16 }}>
                {[{ key: 'transfer', label: 'Transfer' }, { key: 'card', label: 'Card' }, { key: 'ussd', label: 'USSD' }].map((m) => (
                  <TouchableOpacity
                    key={m.key}
                    onPress={() => { setMethod(m.key); setUssdResult(null); }}
                    style={{ flex: 1, paddingVertical: 9, borderRadius: 10, marginHorizontal: 3, alignItems: 'center', backgroundColor: method === m.key ? colors.accent : colors.iconWrap }}
                  >
                    <Text style={{ color: method === m.key ? '#fff' : colors.text, fontWeight: '700', fontSize: 12.5 }}>{m.label}</Text>
                  </TouchableOpacity>
                ))}
              </View>

              {method === 'transfer' && (
                account ? (
                  <View>
                    <Text style={s.modalHint}>Transfer any amount to this account. Your wallet is credited automatically.</Text>
                    <View style={s.vaCard}>
                      <Text style={s.vaBank}>{account.bankName}</Text>
                      <View style={s.vaAccountRow}>
                        <Text style={s.vaAccountNumber}>{account.accountNumber}</Text>
                        <TouchableOpacity onPress={copyAccount}>
                          <Ionicons name="copy-outline" size={20} color={colors.accent} />
                        </TouchableOpacity>
                      </View>
                    </View>
                    <TouchableOpacity style={s.loginBtn} onPress={onClose}>
                      <Text style={s.loginBtnText}>Done</Text>
                    </TouchableOpacity>
                  </View>
                ) : (
                  <View>
                    <Text style={s.modalHint}>We need your BVN or NIN to create a permanent funding account for you (one-time setup).</Text>
                    <View style={{ flexDirection: 'row', marginBottom: 12 }}>
                      <TouchableOpacity
                        onPress={() => { setKycMethod('bvn'); setBvn(''); }}
                        style={{ flex: 1, paddingVertical: 10, borderRadius: 10, marginRight: 6, alignItems: 'center', backgroundColor: kycMethod === 'bvn' ? colors.accent : colors.iconWrap }}
                      >
                        <Text style={{ color: kycMethod === 'bvn' ? '#fff' : colors.text, fontWeight: '700', fontSize: 13 }}>Use BVN</Text>
                      </TouchableOpacity>
                      <TouchableOpacity
                        onPress={() => { setKycMethod('nin'); setBvn(''); }}
                        style={{ flex: 1, paddingVertical: 10, borderRadius: 10, marginLeft: 6, alignItems: 'center', backgroundColor: kycMethod === 'nin' ? colors.accent : colors.iconWrap }}
                      >
                        <Text style={{ color: kycMethod === 'nin' ? '#fff' : colors.text, fontWeight: '700', fontSize: 13 }}>Use NIN</Text>
                      </TouchableOpacity>
                    </View>
                    <TextInput style={s.input} placeholder={`11-digit ${kycMethod.toUpperCase()}`} placeholderTextColor={colors.subtext} keyboardType="number-pad" maxLength={11} value={bvn} onChangeText={setBvn} />
                    <TouchableOpacity style={s.loginBtn} onPress={createAccount} disabled={loading}>
                      {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Create Funding Account</Text>}
                    </TouchableOpacity>
                  </View>
                )
              )}

              {method === 'card' && (
                <View>
                  <Text style={s.modalHint}>Enter an amount — you'll be taken to a secure payment page to enter your card details.</Text>
                  <TextInput style={s.input} placeholder="Amount (₦)" placeholderTextColor={colors.subtext} keyboardType="number-pad" value={amount} onChangeText={setAmount} />
                  <TouchableOpacity style={s.loginBtn} onPress={fundWithCard} disabled={processing}>
                    {processing ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Pay with Card</Text>}
                  </TouchableOpacity>
                </View>
              )}

              {method === 'ussd' && (
                ussdResult ? (
                  <View>
                    <Text style={s.modalHint}>Dial this code on your phone to complete payment:</Text>
                    <View style={s.vaCard}>
                      <View style={s.vaAccountRow}>
                        <Text style={s.vaAccountNumber}>{ussdResult.ussdCode}</Text>
                        <TouchableOpacity onPress={copyUssd}>
                          <Ionicons name="copy-outline" size={20} color={colors.accent} />
                        </TouchableOpacity>
                      </View>
                    </View>
                    <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 8 }}>Your wallet updates automatically once payment is confirmed.</Text>
                    <TouchableOpacity style={s.loginBtn} onPress={onClose}>
                      <Text style={s.loginBtnText}>Done</Text>
                    </TouchableOpacity>
                  </View>
                ) : (
                  <View>
                    <Text style={s.modalHint}>Choose your bank and an amount:</Text>
                    <TouchableOpacity style={s.input} onPress={() => setShowBankPicker(!showBankPicker)}>
                      <Text style={{ color: selectedBank ? colors.text : colors.subtext }}>{selectedBank ? selectedBank.name : 'Select bank'}</Text>
                    </TouchableOpacity>

                    {showBankPicker && (
                      <View style={{ maxHeight: 220, marginBottom: 12 }}>
                        <TextInput
                          style={s.input}
                          placeholder="Search banks"
                          placeholderTextColor={colors.subtext}
                          value={bankSearch}
                          onChangeText={setBankSearch}
                        />
                        <ScrollView style={{ maxHeight: 160 }}>
                          {filteredBanks.map((b) => (
                            <TouchableOpacity
                              key={b.code}
                              style={{ paddingVertical: 10, paddingHorizontal: 6, borderBottomWidth: 1, borderBottomColor: colors.border }}
                              onPress={() => { setSelectedBank(b); setShowBankPicker(false); setBankSearch(''); }}
                            >
                              <Text style={{ color: colors.text }}>{b.name}</Text>
                            </TouchableOpacity>
                          ))}
                        </ScrollView>
                      </View>
                    )}

                    <TextInput style={s.input} placeholder="Amount (₦)" placeholderTextColor={colors.subtext} keyboardType="number-pad" value={amount} onChangeText={setAmount} />
                    <TouchableOpacity style={s.loginBtn} onPress={fundWithUssd} disabled={processing}>
                      {processing ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Generate USSD Code</Text>}
                    </TouchableOpacity>
                  </View>
                )
              )}
            </View>
          </View>
        </View>
      </Modal>
  );
}

// ─── Withdraw Wallet Modal ──────────────────────────────────────────────────
function TransferModal({ visible, onClose, token, user, wallet, onTransferred }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [identifier, setIdentifier] = useState('');
  const [recipient, setRecipient] = useState(null);
  const [lookupError, setLookupError] = useState('');
  const [looking, setLooking] = useState(false);
  const [amount, setAmount] = useState('');
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (visible) {
      setIdentifier('');
      setRecipient(null);
      setLookupError('');
      setAmount('');
      setNote('');
    }
  }, [visible]);

  // Resolve the recipient's name as soon as the sender stops typing a phone/email,
  // so they see who they're paying before they enter an amount or PIN.
  useEffect(() => {
    setRecipient(null);
    setLookupError('');
    if (identifier.trim().length < 5) return;
    const timer = setTimeout(async () => {
      setLooking(true);
      try {
        const data = await api(`/api/v1/wallet/transfer/lookup?identifier=${encodeURIComponent(identifier.trim())}`, { token });
        setRecipient(data);
      } catch (e) {
        setLookupError(e.message || 'User not found');
      } finally {
        setLooking(false);
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [identifier]);

  const amt = Number(amount) || 0;
  const balance = parseFloat(wallet?.balance || 0);

  const confirmTransfer = () => {
    if (!recipient) return Alert.alert('Enter recipient', 'Enter the phone number or email of the gora-data user you want to pay');
    if (!amt || amt < 100) return Alert.alert('Invalid amount', 'Minimum transfer is ₦100');
    if (amt > balance) return Alert.alert('Insufficient balance', `Your wallet balance is ₦${balance.toLocaleString()}`);

    Alert.alert(
      'Confirm Transfer',
      `Send ₦${amt.toLocaleString()} to:\n${recipient.fullName} (${recipient.phone})`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Send', onPress: doTransfer },
      ]
    );
  };

  const doTransfer = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setSubmitting(true);
    try {
      const data = await api('/api/v1/wallet/transfer', {
        method: 'POST',
        token,
        body: { identifier: identifier.trim(), amount: amt, note: note.trim() || undefined, pin },
      });
      Alert.alert('Transfer Sent', data?.message || `₦${amt.toLocaleString()} sent`);
      onTransferred?.();
      onClose();
    } catch (e) {
      Alert.alert('Transfer failed', e.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal visible={visible} animationType="slide" transparent>
      <View style={s.modalOverlay}>
        <View style={s.modalCard}>
          <View style={s.modalHeader}>
            <Text style={s.modalTitle}>Send to gora-data User</Text>
            <TouchableOpacity onPress={onClose}>
              <Ionicons name="close" size={24} color={colors.text} />
            </TouchableOpacity>
          </View>

          <Text style={s.modalHint}>
            Available balance: ₦{balance.toLocaleString(undefined, { minimumFractionDigits: 2 })}
          </Text>

          <TextInput
            style={s.input}
            placeholder="Recipient phone or email"
            placeholderTextColor={colors.subtext}
            value={identifier}
            onChangeText={setIdentifier}
            autoCapitalize="none"
            keyboardType="email-address"
          />

          {looking && <Text style={s.modalHint}>Looking up...</Text>}
          {!looking && lookupError ? <Text style={{ color: '#ef4444', fontSize: 12, marginTop: -6, marginBottom: 8 }}>{lookupError}</Text> : null}
          {!looking && recipient ? (
            <View style={{ backgroundColor: colors.card, borderRadius: 10, padding: 12, marginBottom: 10 }}>
              <Text style={{ color: colors.text, fontWeight: '700' }}>{recipient.fullName}</Text>
              <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 2 }}>{recipient.phone}</Text>
            </View>
          ) : null}

          <TextInput
            style={s.input}
            placeholder="Amount (₦)"
            placeholderTextColor={colors.subtext}
            value={amount}
            onChangeText={setAmount}
            keyboardType="numeric"
          />

          <TextInput
            style={s.input}
            placeholder="Note (optional)"
            placeholderTextColor={colors.subtext}
            value={note}
            onChangeText={setNote}
            maxLength={140}
          />

          <TouchableOpacity
            style={[s.fundBtn, { marginTop: 10, opacity: submitting ? 0.6 : 1 }]}
            onPress={confirmTransfer}
            disabled={submitting}
          >
            {submitting ? <ActivityIndicator color="#fff" /> : <Text style={s.fundBtnText}>Send Money</Text>}
          </TouchableOpacity>
        </View>
      </View>
    </Modal>
  );
}

function WithdrawModal({ visible, onClose, token, user, wallet, onWithdrawn }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [banks, setBanks] = useState([]);
  const [bankSearch, setBankSearch] = useState('');
  const [showBankPicker, setShowBankPicker] = useState(false);
  const [selectedBank, setSelectedBank] = useState(null);
  const [accountNumber, setAccountNumber] = useState('');
  const [accountName, setAccountName] = useState('');
  const [resolving, setResolving] = useState(false);
  const [amount, setAmount] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [settings, setSettings] = useState({ enabled: true, maxAmount: null });

  useEffect(() => {
    if (visible) {
      setBankSearch('');
      setShowBankPicker(false);
      setSelectedBank(null);
      setAccountNumber('');
      setAccountName('');
      setAmount('');
      loadBanks();
      loadSettings();
    }
  }, [visible]);

  const loadBanks = async () => {
    try {
      const data = await api('/api/v1/banks', { token });
      setBanks(Array.isArray(data) ? data : []);
    } catch (e) {}
  };

  const loadSettings = async () => {
    try {
      const data = await api('/api/v1/wallet/withdraw/settings', { token });
      setSettings(data || { enabled: true, maxAmount: null });
    } catch (e) {}
  };

  // Auto-resolve the account name once we have a full account number and a chosen bank —
  // lets the customer see whose account they're sending to before they confirm.
  useEffect(() => {
    setAccountName('');
    if (!selectedBank || accountNumber.length !== 10) return;
    const timer = setTimeout(async () => {
      setResolving(true);
      try {
        const data = await api(`/api/v1/wallet/resolve-account?accountNumber=${accountNumber}&bankCode=${selectedBank.code}`, { token });
        setAccountName(data?.accountName || '');
      } catch (e) {
        setAccountName('');
      } finally {
        setResolving(false);
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [accountNumber, selectedBank]);

  const filteredBanks = bankSearch ? banks.filter((b) => b.name.toLowerCase().includes(bankSearch.toLowerCase())) : banks;
  const amt = Number(amount) || 0;
  const balance = parseFloat(wallet?.balance || 0);

  const confirmWithdraw = () => {
    if (!settings.enabled) return Alert.alert('Withdrawals unavailable', 'Withdrawals are temporarily disabled — please try again later');
    if (!selectedBank) return Alert.alert('Select bank', 'Choose the bank you want to withdraw to');
    if (accountNumber.length !== 10) return Alert.alert('Invalid account number', 'Enter a 10-digit account number');
    if (!accountName) return Alert.alert('Account not verified', 'We could not verify this account — check the number and bank');
    if (!amt || amt < 100) return Alert.alert('Invalid amount', 'Minimum withdrawal is ₦100');
    if (settings.maxAmount !== null && amt > settings.maxAmount) return Alert.alert('Amount too high', `Maximum withdrawal is ₦${settings.maxAmount.toLocaleString()} per transaction`);
    if (amt > balance) return Alert.alert('Insufficient balance', `Your wallet balance is ₦${balance.toLocaleString()}`);

    Alert.alert(
      'Confirm Withdrawal',
      `Withdraw ₦${amt.toLocaleString()} to:\n${accountName} — ${selectedBank.name} (${accountNumber})`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Withdraw', onPress: doWithdraw },
      ]
    );
  };

  const doWithdraw = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setSubmitting(true);
    try {
      const data = await api('/api/v1/wallet/withdraw', {
        method: 'POST',
        token,
        body: { amount: amt, accountNumber, bankCode: selectedBank.code, accountName, pin },
      });
      Alert.alert('Withdrawal Submitted', data?.message || 'Your withdrawal is on its way');
      onWithdrawn?.();
      onClose();
    } catch (e) {
      if (e.code === 'KYC_REQUIRED') {
        Alert.alert('Verify your identity first', 'Open Fund Wallet → Transfer tab and enter your BVN or NIN. Once verified, you can withdraw.');
        onClose();
      } else {
        Alert.alert('Withdrawal failed', e.message);
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal visible={visible} animationType="slide" transparent>
      <View style={s.modalOverlay}>
        <View style={s.modalCard}>
          <View style={s.modalHeader}>
            <Text style={s.modalTitle}>Withdraw to Bank</Text>
            <TouchableOpacity onPress={onClose}>
              <Ionicons name="close" size={24} color={colors.text} />
            </TouchableOpacity>
          </View>

          {!settings.enabled ? (
            <Text style={s.modalHint}>Withdrawals are temporarily unavailable — please check back later.</Text>
          ) : (
            <View>
              <Text style={s.modalHint}>
                Available balance: ₦{balance.toLocaleString(undefined, { minimumFractionDigits: 2 })}
                {settings.maxAmount !== null ? ` · Max ₦${settings.maxAmount.toLocaleString()} per withdrawal` : ''}
              </Text>

              <TouchableOpacity style={s.input} onPress={() => setShowBankPicker(!showBankPicker)}>
                <Text style={{ color: selectedBank ? colors.text : colors.subtext }}>{selectedBank ? selectedBank.name : 'Select bank'}</Text>
              </TouchableOpacity>

              {showBankPicker && (
                <View style={{ maxHeight: 220, marginBottom: 12 }}>
                  <TextInput
                    style={s.input}
                    placeholder="Search banks"
                    placeholderTextColor={colors.subtext}
                    value={bankSearch}
                    onChangeText={setBankSearch}
                  />
                  <ScrollView style={{ maxHeight: 160 }}>
                    {filteredBanks.map((b) => (
                      <TouchableOpacity
                        key={b.code}
                        style={{ paddingVertical: 10, paddingHorizontal: 6, borderBottomWidth: 1, borderBottomColor: colors.border }}
                        onPress={() => { setSelectedBank(b); setShowBankPicker(false); setBankSearch(''); }}
                      >
                        <Text style={{ color: colors.text }}>{b.name}</Text>
                      </TouchableOpacity>
                    ))}
                  </ScrollView>
                </View>
              )}

              <TextInput
                style={s.input}
                placeholder="10-digit account number"
                placeholderTextColor={colors.subtext}
                keyboardType="number-pad"
                maxLength={10}
                value={accountNumber}
                onChangeText={setAccountNumber}
              />

              {resolving && <Text style={{ color: colors.subtext, fontSize: 12.5, marginBottom: 8 }}>Verifying account…</Text>}
              {!resolving && accountName ? (
                <Text style={{ color: colors.accent, fontSize: 13.5, fontWeight: '700', marginBottom: 8 }}>{accountName}</Text>
              ) : null}
              {!resolving && !accountName && accountNumber.length === 10 && selectedBank ? (
                <Text style={{ color: '#b91c1c', fontSize: 12.5, marginBottom: 8 }}>Could not verify this account</Text>
              ) : null}

              <TextInput
                style={s.input}
                placeholder="Amount (₦)"
                placeholderTextColor={colors.subtext}
                keyboardType="number-pad"
                value={amount}
                onChangeText={setAmount}
              />

              <TouchableOpacity style={s.loginBtn} onPress={confirmWithdraw} disabled={submitting}>
                {submitting ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Withdraw</Text>}
              </TouchableOpacity>
            </View>
          )}
        </View>
      </View>
    </Modal>
  );
}

// ─── Data Purchase Screen ───────────────────────────────────────────────────
function DataScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [network, setNetwork] = useState(null);
  const [plans, setPlans] = useState([]);
  const [loadingPlans, setLoadingPlans] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [phone, setPhone] = useState('');
  const [buying, setBuying] = useState(false);
  const [receipt, setReceipt] = useState(null);

  const chooseNetwork = async (net) => {
    setNetwork(net);
    setSelectedPlan(null);
    setLoadingPlans(true);
    try {
      const data = await api(`/api/v1/vtu/data/plans?network=${net}`, { token });
      setPlans(Array.isArray(data) ? data : []);
    } catch (e) {
      Alert.alert('Could not load plans', e.message);
      setPlans([]);
    } finally {
      setLoadingPlans(false);
    }
  };

  const confirmPurchase = () => {
    if (!selectedPlan) return;
    if (!phone || phone.length < 10) return Alert.alert('Invalid phone', 'Enter a valid phone number');
    Alert.alert(
      'Confirm Purchase',
      `${network} ${formatPlanLabel(selectedPlan)} for ${phone}\n\nPrice: ₦${selectedPlan.sellingPrice?.toLocaleString()}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Buy Now', onPress: doPurchase },
      ]
    );
  };

  const doPurchase = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setBuying(true);
    try {
      const data = await api('/api/v1/vtu/data', {
        method: 'POST',
        token,
        body: {
          phone,
          network,
          planCode: selectedPlan.id || selectedPlan.plan_id || selectedPlan.code,
          amount: selectedPlan.sellingPrice,
          pin,
        },
      });
      setReceipt({ ...data, network, plan: selectedPlan, phone });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Purchase failed', e.message);
    } finally {
      setBuying(false);
    }
  };

  if (receipt) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Purchase Successful</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Network: {receipt.network}</Text>
            <Text style={s.receiptRow}>Plan: {formatPlanLabel(receipt.plan)}</Text>
            <Text style={s.receiptRow}>Phone: {receipt.phone}</Text>
            <Text style={s.receiptRow}>Amount: ₦{receipt.plan?.sellingPrice?.toLocaleString()}</Text>
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            <ShareReceiptButton
              colors={colors}
              title="Data Purchase Receipt"
              rows={[
                `Network: ${receipt.network}`,
                `Plan: ${formatPlanLabel(receipt.plan)}`,
                `Phone: ${receipt.phone}`,
                `Amount: ₦${receipt.plan?.sellingPrice?.toLocaleString()}`,
                `Reference: ${receipt.transaction?.reference}`,
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Buy Data</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Network</Text>
        <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
          {NETWORKS.map((n) => (
            <TouchableOpacity
              key={n}
              onPress={() => chooseNetwork(n)}
              style={[
                s.networkPill,
                { borderColor: NETWORK_COLORS[n], backgroundColor: network === n ? NETWORK_COLORS[n] : 'transparent' },
              ]}
            >
              <Text style={{ color: network === n ? '#fff' : colors.text, fontWeight: '600' }}>{n}</Text>
            </TouchableOpacity>
          ))}
        </View>

        {network && (
          <>
            <TextInput
              style={s.input}
              placeholder="Phone number to receive data"
              placeholderTextColor={colors.subtext}
              keyboardType="phone-pad"
              value={phone}
              onChangeText={setPhone}
            />
            {!!user?.phone && phone !== user.phone && (
              <TouchableOpacity onPress={() => setPhone(user.phone)} style={{ alignSelf: 'flex-start', marginTop: -8, marginBottom: 14 }}>
                <Text style={{ color: colors.accent, fontSize: 13, fontWeight: '600' }}>Use my number ({user.phone})</Text>
              </TouchableOpacity>
            )}
          </>
        )}

        {loadingPlans && <ActivityIndicator color={colors.accent} style={{ marginTop: 20 }} />}

        {!loadingPlans && network && plans.length > 0 && (
          <>
            <Text style={[s.sectionTitle, { marginTop: 10 }]}>Select Plan</Text>
            {plans.map((p, i) => (
              <TouchableOpacity
                key={i}
                style={[s.planCard, selectedPlan === p && { borderColor: colors.accent, borderWidth: 2 }]}
                onPress={() => setSelectedPlan(p)}
              >
                <View>
                  <Text style={s.planName}>{formatPlanLabel(p)}</Text>
                  <Text style={s.planValidity}>{p.validity || p.duration || ''}</Text>
                </View>
                <Text style={s.planPrice}>₦{p.sellingPrice?.toLocaleString()}</Text>
              </TouchableOpacity>
            ))}
          </>
        )}

        {!loadingPlans && network && plans.length === 0 && (
          <Text style={{ color: colors.subtext, marginTop: 10 }}>No plans found for {network}.</Text>
        )}

        {selectedPlan && (
          <TouchableOpacity style={[s.loginBtn, { marginTop: 24 }]} onPress={confirmPurchase} disabled={buying}>
            {buying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Buy for ₦{selectedPlan.sellingPrice?.toLocaleString()}</Text>}
          </TouchableOpacity>
        )}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Airtime Purchase Screen ────────────────────────────────────────────────
const QUICK_AMOUNTS = [100, 200, 500, 1000, 2000, 5000];

function AirtimeScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [network, setNetwork] = useState(null);
  const [phone, setPhone] = useState('');
  const [amount, setAmount] = useState('');
  const [quote, setQuote] = useState(null);
  const [quoting, setQuoting] = useState(false);
  const [buying, setBuying] = useState(false);
  const [receipt, setReceipt] = useState(null);

  // Fetches the EXACT price the customer will be charged (amount + your margin) for whatever
  // they've typed, straight from the backend — so this never drifts from what actually gets debited.
  useEffect(() => {
    const amt = Number(amount);
    if (!amt || amt < 50) { setQuote(null); return; }
    setQuoting(true);
    const t = setTimeout(async () => {
      try {
        const q = await api(`/api/v1/pricing/quote?service=airtime&amount=${amt}`, { token });
        setQuote(q);
      } catch (e) {
        setQuote(null);
      } finally {
        setQuoting(false);
      }
    }, 400);
    return () => clearTimeout(t);
  }, [amount, token]);

  const confirmPurchase = () => {
    if (!network) return Alert.alert('Select network', 'Choose a network first');
    if (!phone || phone.length < 10) return Alert.alert('Invalid phone', 'Enter a valid phone number');
    const amt = Number(amount);
    if (!amt || amt < 50) return Alert.alert('Invalid amount', 'Minimum airtime is ₦50');
    if (!quote) return Alert.alert('Please wait', 'Still calculating your price — try again in a moment');
    Alert.alert(
      'Confirm Purchase',
      `${network} airtime of ₦${amt.toLocaleString()} for ${phone}\n\nYou'll be charged: ₦${quote.sellingPrice.toLocaleString()}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Buy Now', onPress: doPurchase },
      ]
    );
  };

  const doPurchase = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setBuying(true);
    try {
      const data = await api('/api/v1/vtu/airtime', {
        method: 'POST',
        token,
        body: { phone, network, amount: Number(amount), pin },
      });
      // Use the actual charged amount from the transaction record — the single source of truth —
      // rather than the client-typed face value, which would understate what was really debited.
      setReceipt({ ...data, network, phone, amount: data.transaction?.amount ?? quote?.sellingPrice ?? Number(amount) });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Purchase failed', e.message);
    } finally {
      setBuying(false);
    }
  };

  if (receipt) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Purchase Successful</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Network: {receipt.network}</Text>
            <Text style={s.receiptRow}>Phone: {receipt.phone}</Text>
            <Text style={s.receiptRow}>Amount Charged: ₦{receipt.amount?.toLocaleString()}</Text>
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            <ShareReceiptButton
              colors={colors}
              title="Airtime Purchase Receipt"
              rows={[
                `Network: ${receipt.network}`,
                `Phone: ${receipt.phone}`,
                `Amount Charged: ₦${receipt.amount?.toLocaleString()}`,
                `Reference: ${receipt.transaction?.reference}`,
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Buy Airtime</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Network</Text>
        <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
          {NETWORKS.map((n) => (
            <TouchableOpacity
              key={n}
              onPress={() => setNetwork(n)}
              style={[
                s.networkPill,
                { borderColor: NETWORK_COLORS[n], backgroundColor: network === n ? NETWORK_COLORS[n] : 'transparent' },
              ]}
            >
              <Text style={{ color: network === n ? '#fff' : colors.text, fontWeight: '600' }}>{n}</Text>
            </TouchableOpacity>
          ))}
        </View>

        <TextInput
          style={s.input}
          placeholder="Phone number to recharge"
          placeholderTextColor={colors.subtext}
          keyboardType="phone-pad"
          value={phone}
          onChangeText={setPhone}
        />
        {!!user?.phone && phone !== user.phone && (
          <TouchableOpacity onPress={() => setPhone(user.phone)} style={{ alignSelf: 'flex-start', marginTop: -8, marginBottom: 14 }}>
            <Text style={{ color: colors.accent, fontSize: 13, fontWeight: '600' }}>Use my number ({user.phone})</Text>
          </TouchableOpacity>
        )}

        <TextInput
          style={s.input}
          placeholder="Amount (min ₦50)"
          placeholderTextColor={colors.subtext}
          keyboardType="number-pad"
          value={amount}
          onChangeText={setAmount}
        />

        <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 10 }}>
          {QUICK_AMOUNTS.map((a) => (
            <TouchableOpacity
              key={a}
              onPress={() => setAmount(String(a))}
              style={[
                s.networkPill,
                { borderColor: colors.accent, backgroundColor: Number(amount) === a ? colors.accent : 'transparent' },
              ]}
            >
              <Text style={{ color: Number(amount) === a ? '#fff' : colors.text, fontWeight: '600' }}>₦{a.toLocaleString()}</Text>
            </TouchableOpacity>
          ))}
        </View>

        {quoting && <ActivityIndicator color={colors.accent} style={{ marginBottom: 14 }} />}
        {quote && !quoting && (
          <View style={[s.vaCard, { marginBottom: 14 }]}>
            <Text style={s.vaBank}>You'll be charged</Text>
            <Text style={s.vaAccountNumber}>₦{quote.sellingPrice.toLocaleString()}</Text>
          </View>
        )}

        <TouchableOpacity style={[s.loginBtn, { marginTop: 6 }]} onPress={confirmPurchase} disabled={buying}>
          {buying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Buy Airtime</Text>}
        </TouchableOpacity>
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Electricity Payment Screen ─────────────────────────────────────────────
const METER_TYPES = ['prepaid', 'postpaid'];

function discoValue(d) {
  if (typeof d === 'string') return d;
  return d.code ?? d.company ?? d.id ?? d.name ?? d.slug ?? '';
}
function discoLabel(d) {
  if (typeof d === 'string') return d;
  return d.name ?? d.company ?? d.disco_name ?? d.title ?? d.code ?? JSON.stringify(d);
}

function ElectricityScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [discos, setDiscos] = useState([]);
  const [loadingDiscos, setLoadingDiscos] = useState(true);
  const [disco, setDisco] = useState(null);
  const [meterType, setMeterType] = useState('prepaid');
  const [meterNumber, setMeterNumber] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState(null);
  const [phone, setPhone] = useState('');
  const [amount, setAmount] = useState('');
  const [quote, setQuote] = useState(null);
  const [quoting, setQuoting] = useState(false);
  const [buying, setBuying] = useState(false);
  const [receipt, setReceipt] = useState(null);

  // Fetches the EXACT price the customer will be charged (units amount + your margin), straight
  // from the backend, so it always matches what actually gets debited from their wallet.
  useEffect(() => {
    const amt = Number(amount);
    if (!amt || amt < 1000) { setQuote(null); return; }
    setQuoting(true);
    const t = setTimeout(async () => {
      try {
        const q = await api(`/api/v1/pricing/quote?service=electric&amount=${amt}`, { token });
        setQuote(q);
      } catch (e) {
        setQuote(null);
      } finally {
        setQuoting(false);
      }
    }, 400);
    return () => clearTimeout(t);
  }, [amount, token]);

  useEffect(() => {
    (async () => {
      try {
        const data = await api('/api/v1/vtu/electric/providers', { token });
        const list = Array.isArray(data) ? data : data?.providers || [];
        setDiscos(list);
      } catch (e) {
        Alert.alert('Could not load providers', e.message);
      } finally {
        setLoadingDiscos(false);
      }
    })();
  }, []);

  const resetVerification = () => setVerified(null);

  const doVerify = async () => {
    if (!disco) return Alert.alert('Select disco', 'Choose your electricity provider first');
    if (!meterNumber) return Alert.alert('Missing meter number', 'Enter the meter number');
    setVerifying(true);
    try {
      const data = await api('/api/v1/vtu/electric/verify', {
        method: 'POST',
        token,
        body: { disco, meterNumber, meterType },
      });
      setVerified(data);
    } catch (e) {
      setVerified(null);
      Alert.alert('Verification failed', e.message);
    } finally {
      setVerifying(false);
    }
  };

  const confirmPurchase = () => {
    if (!phone || phone.length < 10) return Alert.alert('Invalid phone', 'Enter a valid phone number');
    const amt = Number(amount);
    if (!amt || amt < 1000) return Alert.alert('Invalid amount', 'Minimum electricity payment is ₦1,000');
    if (!quote) return Alert.alert('Please wait', 'Still calculating your price — try again in a moment');
    Alert.alert(
      'Confirm Purchase',
      `${discoLabel({ name: disco })} ${meterType} for ${verified?.name || meterNumber}\n\nUnits amount: ₦${amt.toLocaleString()}\nYou'll be charged: ₦${quote.sellingPrice.toLocaleString()}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Pay Now', onPress: doPurchase },
      ]
    );
  };

  const doPurchase = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setBuying(true);
    try {
      const data = await api('/api/v1/vtu/electric', {
        method: 'POST',
        token,
        body: { disco, meterNumber, meterType, amount: Number(amount), phone, pin },
      });
      // Use the actual charged amount from the transaction record, not the client-typed units value.
      setReceipt({ ...data, disco, meterNumber, meterType, phone, amount: data.transaction?.amount ?? quote?.sellingPrice ?? Number(amount) });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Purchase failed', e.message);
    } finally {
      setBuying(false);
    }
  };

  if (receipt) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Payment Successful</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Disco: {receipt.disco}</Text>
            <Text style={s.receiptRow}>Meter: {receipt.meterNumber} ({receipt.meterType})</Text>
            <Text style={s.receiptRow}>Amount Charged: ₦{receipt.amount?.toLocaleString()}</Text>
            {receipt.token ? <Text style={s.receiptRow}>Token: {receipt.token}</Text> : null}
            {receipt.units ? <Text style={s.receiptRow}>Units: {receipt.units}</Text> : null}
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            <ShareReceiptButton
              colors={colors}
              title="Electricity Payment Receipt"
              rows={[
                `Disco: ${receipt.disco}`,
                `Meter: ${receipt.meterNumber} (${receipt.meterType})`,
                `Amount Charged: ₦${receipt.amount?.toLocaleString()}`,
                receipt.token ? `Token: ${receipt.token}` : null,
                receipt.units ? `Units: ${receipt.units}` : null,
                `Reference: ${receipt.transaction?.reference}`,
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Pay Electricity</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Provider</Text>
        {loadingDiscos ? (
          <ActivityIndicator color={colors.accent} style={{ marginBottom: 20 }} />
        ) : (
          <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
            {discos.map((d, i) => {
              const val = discoValue(d);
              return (
                <TouchableOpacity
                  key={i}
                  onPress={() => { setDisco(val); resetVerification(); }}
                  style={[
                    s.networkPill,
                    { borderColor: colors.accent, backgroundColor: disco === val ? colors.accent : 'transparent' },
                  ]}
                >
                  <Text style={{ color: disco === val ? '#fff' : colors.text, fontWeight: '600' }}>{discoLabel(d)}</Text>
                </TouchableOpacity>
              );
            })}
          </View>
        )}

        {!loadingDiscos && discos.length === 0 && (
          <Text style={{ color: colors.subtext, marginTop: -12, marginBottom: 20 }}>
            Could not load electricity providers right now. Pull back and try again, or contact support if this keeps happening.
          </Text>
        )}

        <Text style={s.sectionTitle}>Meter Type</Text>
        <View style={{ flexDirection: 'row', marginBottom: 20 }}>
          {METER_TYPES.map((t) => (
            <TouchableOpacity
              key={t}
              onPress={() => { setMeterType(t); resetVerification(); }}
              style={[
                s.networkPill,
                { borderColor: colors.accent, backgroundColor: meterType === t ? colors.accent : 'transparent' },
              ]}
            >
              <Text style={{ color: meterType === t ? '#fff' : colors.text, fontWeight: '600', textTransform: 'capitalize' }}>{t}</Text>
            </TouchableOpacity>
          ))}
        </View>

        <TextInput
          style={s.input}
          placeholder="Meter number"
          placeholderTextColor={colors.subtext}
          keyboardType="number-pad"
          value={meterNumber}
          onChangeText={(v) => { setMeterNumber(v); resetVerification(); }}
        />

        <TouchableOpacity style={s.loginBtn} onPress={doVerify} disabled={verifying}>
          {verifying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Verify Meter</Text>}
        </TouchableOpacity>

        {verified && (
          <View style={[s.vaCard, { marginTop: 18 }]}>
            <Text style={s.vaBank}>Customer Name</Text>
            <Text style={s.vaAccountNumber}>{verified.name}</Text>
            {verified.address ? <Text style={{ color: colors.subtext, marginTop: 6 }}>{verified.address}</Text> : null}
          </View>
        )}

        {verified && (
          <>
            <TextInput
              style={[s.input, { marginTop: 18 }]}
              placeholder="Phone number"
              placeholderTextColor={colors.subtext}
              keyboardType="phone-pad"
              value={phone}
              onChangeText={setPhone}
            />
            {!!user?.phone && phone !== user.phone && (
              <TouchableOpacity onPress={() => setPhone(user.phone)} style={{ alignSelf: 'flex-start', marginTop: -8, marginBottom: 14 }}>
                <Text style={{ color: colors.accent, fontSize: 13, fontWeight: '600' }}>Use my number ({user.phone})</Text>
              </TouchableOpacity>
            )}
            <TextInput
              style={s.input}
              placeholder="Amount (min ₦1,000)"
              placeholderTextColor={colors.subtext}
              keyboardType="number-pad"
              value={amount}
              onChangeText={setAmount}
            />
            {quoting && <ActivityIndicator color={colors.accent} style={{ marginBottom: 14 }} />}
            {quote && !quoting && (
              <View style={[s.vaCard, { marginBottom: 14 }]}>
                <Text style={s.vaBank}>You'll be charged</Text>
                <Text style={s.vaAccountNumber}>₦{quote.sellingPrice.toLocaleString()}</Text>
              </View>
            )}
            <TouchableOpacity style={s.loginBtn} onPress={confirmPurchase} disabled={buying}>
              {buying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Pay Now</Text>}
            </TouchableOpacity>
          </>
        )}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Cable TV Screen ─────────────────────────────────────────────────────────
const CABLE_PROVIDERS = [
  { value: 'dstv', label: 'DSTV' },
  { value: 'gotv', label: 'GOtv' },
  { value: 'startimes', label: 'Startimes' },
  { value: 'showmax', label: 'Showmax' },
];

function ISPScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [ispProvider, setIspProvider] = useState('smile');
  const [accountId, setAccountId] = useState('');
  const [spectranetNumber, setSpectranetNumber] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState(null);
  const [plans, setPlans] = useState([]);
  const [loadingPlans, setLoadingPlans] = useState(true);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [buying, setBuying] = useState(false);
  const [receipt, setReceipt] = useState(null);

  const loadPlans = useCallback(async (chosenProvider) => {
    setLoadingPlans(true);
    setSelectedPlan(null);
    try {
      const data = await api(`/api/v1/isp/plans?ispProvider=${chosenProvider}`, { token });
      setPlans(Array.isArray(data) ? data : []);
    } catch (e) {
      Alert.alert('Could not load plans', e.message);
      setPlans([]);
    } finally {
      setLoadingPlans(false);
    }
  }, [token]);

  useEffect(() => { loadPlans(ispProvider); }, [ispProvider, loadPlans]);

  const chooseIspProvider = (p) => {
    setIspProvider(p);
    setVerified(null);
    setAccountId('');
    setSpectranetNumber('');
  };

  const doVerify = async () => {
    if (!accountId) return Alert.alert('Missing account', 'Enter your Smile account/mobile number');
    setVerifying(true);
    try {
      const data = await api('/api/v1/isp/verify', { method: 'POST', token, body: { accountId } });
      setVerified(data);
    } catch (e) {
      setVerified(null);
      Alert.alert('Verification failed', e.message);
    } finally {
      setVerifying(false);
    }
  };

  const canPurchase = ispProvider === 'smile' ? !!verified : !!spectranetNumber;

  const confirmPurchase = () => {
    if (!selectedPlan) return Alert.alert('Select plan', 'Choose a data plan first');
    const who = ispProvider === 'smile' ? (verified?.name || accountId) : spectranetNumber;
    Alert.alert(
      'Confirm Purchase',
      `${formatPlanLabel(selectedPlan)} for ${who}\n\nAmount: ₦${selectedPlan.sellingPrice?.toLocaleString()}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Pay Now', onPress: doPurchase },
      ]
    );
  };

  const doPurchase = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setBuying(true);
    try {
      const body = ispProvider === 'smile'
        ? { ispProvider, planCode: selectedPlan.id || selectedPlan.code, accountId, email: user?.email, phone: user?.phone, pin }
        : { ispProvider, planCode: selectedPlan.id || selectedPlan.code, spectranetNumber, quantity: 1, phone: user?.phone, pin };
      const data = await api('/api/v1/isp', { method: 'POST', token, body });
      setReceipt({ ...data, ispProvider, accountId, spectranetNumber, plan: selectedPlan });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Purchase failed', e.message);
    } finally {
      setBuying(false);
    }
  };

  if (receipt) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Purchase Successful</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Provider: {receipt.ispProvider === 'smile' ? 'Smile' : 'Spectranet'}</Text>
            <Text style={s.receiptRow}>Account: {receipt.ispProvider === 'smile' ? receipt.accountId : receipt.spectranetNumber}</Text>
            <Text style={s.receiptRow}>Plan: {formatPlanLabel(receipt.plan)}</Text>
            <Text style={s.receiptRow}>Amount: ₦{receipt.plan?.sellingPrice?.toLocaleString()}</Text>
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            <ShareReceiptButton
              colors={colors}
              title="ISP Purchase Receipt"
              rows={[
                `Provider: ${receipt.ispProvider === 'smile' ? 'Smile' : 'Spectranet'}`,
                `Account: ${receipt.ispProvider === 'smile' ? receipt.accountId : receipt.spectranetNumber}`,
                `Plan: ${formatPlanLabel(receipt.plan)}`,
                `Amount: ₦${receipt.plan?.sellingPrice?.toLocaleString()}`,
                `Reference: ${receipt.transaction?.reference}`,
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>ISP Data</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Provider</Text>
        <View style={{ flexDirection: 'row', marginBottom: 20 }}>
          {[{ label: 'Smile', value: 'smile' }, { label: 'Spectranet', value: 'spectranet' }].map((p) => (
            <TouchableOpacity
              key={p.value}
              onPress={() => chooseIspProvider(p.value)}
              style={[
                s.networkPill,
                { borderColor: colors.accent, backgroundColor: ispProvider === p.value ? colors.accent : 'transparent' },
              ]}
            >
              <Text style={{ color: ispProvider === p.value ? '#fff' : colors.text, fontWeight: '600' }}>{p.label}</Text>
            </TouchableOpacity>
          ))}
        </View>

        {ispProvider === 'smile' ? (
          <>
            <TextInput
              style={s.input}
              placeholder="Smile account / mobile number"
              placeholderTextColor={colors.subtext}
              keyboardType="number-pad"
              value={accountId}
              onChangeText={(v) => { setAccountId(v); setVerified(null); }}
            />
            <TouchableOpacity style={s.loginBtn} onPress={doVerify} disabled={verifying}>
              {verifying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Verify Account</Text>}
            </TouchableOpacity>
            {verified && (
              <View style={[s.vaCard, { marginTop: 18 }]}>
                <Text style={s.vaBank}>Account Name</Text>
                <Text style={s.vaAccountNumber}>{verified.name}</Text>
              </View>
            )}
          </>
        ) : (
          <TextInput
            style={s.input}
            placeholder="Spectranet number"
            placeholderTextColor={colors.subtext}
            value={spectranetNumber}
            onChangeText={setSpectranetNumber}
          />
        )}

        {loadingPlans && <ActivityIndicator color={colors.accent} style={{ marginTop: 20 }} />}

        {!loadingPlans && canPurchase && (
          <>
            <Text style={[s.sectionTitle, { marginTop: 18 }]}>Select Plan</Text>
            {plans.length === 0 ? (
              <Text style={{ color: colors.subtext, marginTop: 10 }}>No plans available right now.</Text>
            ) : (
              plans.map((p, i) => (
                <TouchableOpacity
                  key={i}
                  style={[s.planCard, selectedPlan === p && { borderColor: colors.accent, borderWidth: 2 }]}
                  onPress={() => setSelectedPlan(p)}
                >
                  <Text style={s.planName}>{formatPlanLabel(p)}</Text>
                  <Text style={s.planPrice}>₦{p.sellingPrice?.toLocaleString()}</Text>
                </TouchableOpacity>
              ))
            )}
          </>
        )}

        {canPurchase && selectedPlan && (
          <TouchableOpacity style={[s.loginBtn, { marginTop: 18 }]} onPress={confirmPurchase} disabled={buying}>
            {buying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Pay Now</Text>}
          </TouchableOpacity>
        )}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function SocialBoostScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [platforms, setPlatforms] = useState([]);
  const [loadingPlatforms, setLoadingPlatforms] = useState(true);
  const [platform, setPlatform] = useState(null);
  const [selectedPlatformIndex, setSelectedPlatformIndex] = useState(null);
  const [countries, setCountries] = useState([]);
  const [loadingCountries, setLoadingCountries] = useState(true);
  const [country, setCountry] = useState(null);
  const [services, setServices] = useState([]);
  const [loadingServices, setLoadingServices] = useState(false);
  const [selectedService, setSelectedService] = useState(null);
  const [link, setLink] = useState('');
  const [quantity, setQuantity] = useState('');
  const [ordering, setOrdering] = useState(false);
  const [receipt, setReceipt] = useState(null);
  const [checkingStatus, setCheckingStatus] = useState(false);
  const [orderStatus, setOrderStatus] = useState(null);

  useEffect(() => {
    (async () => {
      setLoadingPlatforms(true);
      try {
        const data = await api('/api/v1/social/platforms', { token });
        setPlatforms(Array.isArray(data) ? data : []);
      } catch (e) {
        Alert.alert('Could not load platforms', e.message);
        setPlatforms([]);
      } finally {
        setLoadingPlatforms(false);
      }
    })();
    (async () => {
      setLoadingCountries(true);
      try {
        const data = await api('/api/v1/social/countries', { token });
        setCountries(Array.isArray(data) ? data : []);
      } catch (e) {
        // Non-fatal — not every platform/service needs a country filter.
        setCountries([]);
      } finally {
        setLoadingCountries(false);
      }
    })();
  }, [token]);

  const fetchServicesFor = async (platformId, countryVal) => {
    setSelectedService(null);
    setServices([]);
    setLoadingServices(true);
    try {
      let url = `/api/v1/social/services?platform=${encodeURIComponent(platformId)}`;
      if (countryVal) url += `&country=${encodeURIComponent(countryVal)}`;
      const data = await api(url, { token });
      setServices(Array.isArray(data) ? data : []);
    } catch (e) {
      Alert.alert('Could not load services', e.message);
      setServices([]);
    } finally {
      setLoadingServices(false);
    }
  };

  const choosePlatform = async (p, index) => {
    setPlatform(p);
    setSelectedPlatformIndex(index);
    const platformId = p.name || p.value || p.platform_name || p.platform || p.display_name;
    await fetchServicesFor(platformId, country);
  };

  const chooseCountry = async (c) => {
    const countryVal = c ? (c.name || c.value || c.country_name || c.code) : null;
    setCountry(countryVal);
    if (platform) {
      const platformId = platform.name || platform.value || platform.platform_name || platform.platform || platform.display_name;
      await fetchServicesFor(platformId, countryVal);
    }
  };

  const checkOrderStatus = async () => {
    if (!receipt?.providerRef) return Alert.alert('No order ID', 'This order has no provider reference to check.');
    setCheckingStatus(true);
    try {
      const data = await api(`/api/v1/social/order/status?orderId=${encodeURIComponent(receipt.providerRef)}`, { token });
      setOrderStatus(data);
    } catch (e) {
      Alert.alert('Could not check status', e.message);
    } finally {
      setCheckingStatus(false);
    }
  };

  const confirmOrder = () => {
    if (!selectedService) return Alert.alert('Select service', 'Choose a service first');
    if (!quantity || Number(quantity) < 1) return Alert.alert('Missing quantity', 'Enter how many you want');
    const total = (selectedService.sellingPrice || 0) * Number(quantity);
    Alert.alert(
      'Confirm Order',
      `${platform?.display_name || platform?.name} — ${selectedService.name || selectedService.category}\nQuantity: ${quantity}\n\nAmount: ₦${total.toLocaleString()}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Place Order', onPress: doOrder },
      ]
    );
  };

  const doOrder = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setOrdering(true);
    try {
      const data = await api('/api/v1/social/order', {
        method: 'POST',
        token,
        body: {
          platform: platform?.name || platform?.value,
          serviceId: selectedService.id,
          quantity: Number(quantity),
          link: link || undefined,
          country: country || undefined,
          pin,
        },
      });
      setReceipt({ ...data, platform, service: selectedService, quantity, link });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Order failed', e.message);
    } finally {
      setOrdering(false);
    }
  };

  if (receipt) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Order Placed</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Platform: {receipt.platform?.display_name || receipt.platform?.name}</Text>
            <Text style={s.receiptRow}>Service: {receipt.service?.name || receipt.service?.category}</Text>
            <Text style={s.receiptRow}>Quantity: {receipt.quantity}</Text>
            {!!receipt.link && <Text style={s.receiptRow}>Link: {receipt.link}</Text>}
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            {!!receipt.providerRef && (
              <>
                <TouchableOpacity
                  onPress={checkOrderStatus}
                  disabled={checkingStatus}
                  style={{ marginTop: 14, backgroundColor: colors.iconWrap, borderRadius: 10, paddingVertical: 12, alignItems: 'center', flexDirection: 'row', justifyContent: 'center' }}
                >
                  {checkingStatus ? <ActivityIndicator color={colors.accent} /> : (
                    <>
                      <Ionicons name="refresh-outline" size={16} color={colors.accent} style={{ marginRight: 6 }} />
                      <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 13 }}>Check Order Status</Text>
                    </>
                  )}
                </TouchableOpacity>
                {!!orderStatus && (
                  <View style={{ marginTop: 12, padding: 12, backgroundColor: colors.card, borderRadius: 10 }}>
                    {Object.entries(orderStatus).map(([k, v]) => (
                      <Text key={k} style={{ color: colors.subtext, fontSize: 12, marginBottom: 2 }}>
                        {k}: {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                      </Text>
                    ))}
                  </View>
                )}
              </>
            )}
            <ShareReceiptButton
              colors={colors}
              title="Social Media Order Receipt"
              rows={[
                `Platform: ${receipt.platform?.display_name || receipt.platform?.name}`,
                `Service: ${receipt.service?.name || receipt.service?.category}`,
                `Quantity: ${receipt.quantity}`,
                receipt.link ? `Link: ${receipt.link}` : null,
                `Reference: ${receipt.transaction?.reference}`,
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Social Boost</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Platform</Text>
        {loadingPlatforms ? (
          <ActivityIndicator color={colors.accent} style={{ marginTop: 10 }} />
        ) : (
          <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
            {platforms.map((p, i) => {
              const label = p.display_name || p.name || p.platform_name || p.title || p.platform || p.value;
              const isSelected = selectedPlatformIndex === i;
              return (
                <TouchableOpacity
                  key={i}
                  onPress={() => choosePlatform(p, i)}
                  style={[
                    s.networkPill,
                    { borderColor: colors.accent, backgroundColor: isSelected ? colors.accent : 'transparent' },
                  ]}
                >
                  <Text style={{ color: isSelected ? '#fff' : colors.text, fontWeight: '600' }}>
                    {label || `[keys: ${Object.keys(p).join(', ')}]`}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        )}

        {!loadingCountries && countries.length > 0 && (
          <>
            <Text style={s.sectionTitle}>Country (optional)</Text>
            <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
              <TouchableOpacity
                onPress={() => chooseCountry(null)}
                style={[s.networkPill, { borderColor: colors.accent, backgroundColor: !country ? colors.accent : 'transparent' }]}
              >
                <Text style={{ color: !country ? '#fff' : colors.text, fontWeight: '600' }}>Any</Text>
              </TouchableOpacity>
              {countries.map((c, i) => {
                const val = c.name || c.value || c.country_name || c.code;
                const isSelected = country === val;
                return (
                  <TouchableOpacity
                    key={i}
                    onPress={() => chooseCountry(c)}
                    style={[s.networkPill, { borderColor: colors.accent, backgroundColor: isSelected ? colors.accent : 'transparent' }]}
                  >
                    <Text style={{ color: isSelected ? '#fff' : colors.text, fontWeight: '600' }}>{val}</Text>
                  </TouchableOpacity>
                );
              })}
            </View>
          </>
        )}

        {loadingServices && <ActivityIndicator color={colors.accent} style={{ marginTop: 10 }} />}

        {platform && !loadingServices && services.length > 0 && (
          <>
            <Text style={[s.sectionTitle, { marginTop: 10 }]}>Select Service</Text>
            {services.map((sv, i) => (
              <TouchableOpacity
                key={i}
                style={[s.planCard, selectedService === sv && { borderColor: colors.accent, borderWidth: 2 }]}
                onPress={() => setSelectedService(sv)}
              >
                <View style={{ flex: 1, marginRight: 10 }}>
                  <Text style={s.planName}>{sv.name || sv.category}</Text>
                </View>
                <Text style={[s.planPrice, { flexShrink: 0 }]}>₦{sv.sellingPrice?.toLocaleString()}/unit</Text>
              </TouchableOpacity>
            ))}
          </>
        )}

        {platform && !loadingServices && services.length === 0 && (
          <Text style={{ color: colors.subtext, marginTop: 10 }}>No services found for this platform.</Text>
        )}

        {selectedService && (
          <>
            <TextInput
              style={[s.input, { marginTop: 18 }]}
              placeholder="Link (profile, post, or video URL)"
              placeholderTextColor={colors.subtext}
              autoCapitalize="none"
              value={link}
              onChangeText={setLink}
            />
            <TextInput
              style={s.input}
              placeholder="Quantity"
              placeholderTextColor={colors.subtext}
              keyboardType="number-pad"
              value={quantity}
              onChangeText={setQuantity}
            />
            <TouchableOpacity style={s.loginBtn} onPress={confirmOrder} disabled={ordering}>
              {ordering ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Place Order</Text>}
            </TouchableOpacity>
          </>
        )}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

const SMS_TEMPLATES = [
  { label: 'Promo', text: 'Special offer! Get 50% off on all data plans today. Limited time only!' },
  { label: 'Reminder', text: 'Reminder: your subscription is due for renewal. Top up now to stay active.' },
  { label: 'Alert', text: 'Alert: your account had a recent activity. Contact support if this wasn\'t you.' },
];

function BulkSmsScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [pricing, setPricing] = useState(null);
  const [loadingPricing, setLoadingPricing] = useState(true);
  const [senderId, setSenderId] = useState('');
  const [message, setMessage] = useState('');
  const [recipientsText, setRecipientsText] = useState('');
  const [showTemplates, setShowTemplates] = useState(false);
  const [sending, setSending] = useState(false);
  const [receipt, setReceipt] = useState(null);
  const [checkingStatus, setCheckingStatus] = useState(false);
  const [jobStatus, setJobStatus] = useState(null);
  const [showHistory, setShowHistory] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [jobHistory, setJobHistory] = useState(null);

  const loadJobHistory = async () => {
    setShowHistory(true);
    setLoadingHistory(true);
    try {
      const data = await api('/api/v1/sms/jobs', { token });
      // Field names for each job aren't documented anywhere in server.js — this passes
      // through whatever Bigisub returns as-is rather than guessing a shape, same
      // defensive-fallback approach used for recipient rows in checkJobStatus below.
      const list = Array.isArray(data) ? data : (Array.isArray(data?.jobs) ? data.jobs : []);
      setJobHistory(list);
    } catch (e) {
      Alert.alert('Could not load SMS history', e.message);
      setJobHistory([]);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    (async () => {
      setLoadingPricing(true);
      try {
        const data = await api('/api/v1/sms/pricing', { token });
        setPricing(data);
      } catch (e) {
        Alert.alert('Could not load SMS pricing', e.message);
      } finally {
        setLoadingPricing(false);
      }
    })();
  }, [token]);

  const recipients = recipientsText
    .split(/[\s,]+/)
    .map((r) => r.trim())
    .filter(Boolean);

  // Same rule Bigisub bills by: any non-ASCII character makes it a unicode SMS (70 chars/page)
  // instead of normal (160 chars/page).
  const isUnicode = /[^\x00-\x7F]/.test(message);
  const charsPerPage = pricing ? (isUnicode ? pricing.unicode_chars_per_page : pricing.normal_chars_per_page) : 160;
  const pages = message.length > 0 ? Math.max(1, Math.ceil(message.length / charsPerPage)) : 0;
  const costPerPage = pricing ? (pricing.sellingCostPerPage ?? pricing.cost_per_page) : 0;
  const estimatedCost = pages * recipients.length * costPerPage;

  const pasteNumbers = async () => {
    try {
      const text = await Clipboard.getStringAsync();
      if (text) setRecipientsText((prev) => (prev ? `${prev}, ${text}` : text));
    } catch (e) {
      Alert.alert('Could not paste', 'Unable to read clipboard.');
    }
  };

  const clearDraft = () => {
    setSenderId('');
    setMessage('');
    setRecipientsText('');
  };

  const confirmSend = () => {
    if (!senderId) return Alert.alert('Sender ID required', 'Enter a Sender ID (max 11 characters).');
    if (senderId.length > 11) return Alert.alert('Sender ID too long', 'Sender ID must be 11 characters or fewer.');
    if (!message) return Alert.alert('Message required', 'Enter a message to send.');
    if (recipients.length === 0) return Alert.alert('Recipients required', 'Add at least one recipient number.');
    if (recipients.length > 500) return Alert.alert('Too many recipients', 'Maximum 500 recipients per send.');
    Alert.alert(
      'Confirm Send',
      `Sender ID: ${senderId}\nRecipients: ${recipients.length}\nPages: ${pages}\n\nEstimated cost: ₦${estimatedCost.toLocaleString()}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Send', onPress: doSend },
      ]
    );
  };

  const doSend = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setSending(true);
    try {
      const data = await api('/api/v1/sms/send', {
        method: 'POST',
        token,
        body: { senderId, message, recipients, pin },
      });
      setReceipt({ ...data, senderId, recipientCount: recipients.length, pages });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Send failed', e.message);
    } finally {
      setSending(false);
    }
  };

  const checkJobStatus = async () => {
    if (!receipt?.jobId) return Alert.alert('No job ID', 'This send has no job ID to check.');
    setCheckingStatus(true);
    try {
      const data = await api(`/api/v1/sms/job/${encodeURIComponent(receipt.jobId)}/status`, { token });
      console.log('[sms job status RAW]', JSON.stringify(data));
      setJobStatus(data);
    } catch (e) {
      Alert.alert('Could not check status', e.message);
    } finally {
      setCheckingStatus(false);
    }
  };

  if (receipt) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>SMS Job Created</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Sender ID: {receipt.senderId}</Text>
            <Text style={s.receiptRow}>Recipients: {receipt.recipientCount}</Text>
            <Text style={s.receiptRow}>Pages: {receipt.pagesPerSms || receipt.pages}</Text>
            <Text style={s.receiptRow}>Status: {receipt.status || 'processing'}</Text>
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            {!!receipt.jobId && (
              <>
                <TouchableOpacity
                  onPress={checkJobStatus}
                  disabled={checkingStatus}
                  style={{ marginTop: 14, backgroundColor: colors.iconWrap, borderRadius: 10, paddingVertical: 12, alignItems: 'center', flexDirection: 'row', justifyContent: 'center' }}
                >
                  {checkingStatus ? <ActivityIndicator color={colors.accent} /> : (
                    <>
                      <Ionicons name="refresh-outline" size={16} color={colors.accent} style={{ marginRight: 6 }} />
                      <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 13 }}>Check Delivery Status</Text>
                    </>
                  )}
                </TouchableOpacity>
                {!!jobStatus && (
                  <View style={{ marginTop: 12, padding: 12, backgroundColor: colors.card, borderRadius: 10 }}>
                    <Text style={{ color: colors.subtext, fontSize: 12, marginBottom: 6 }}>
                      Pending: {jobStatus.pending_count ?? '—'} · Total: ₦{jobStatus.total_amount ?? '—'}
                    </Text>
                    {(jobStatus.recipients || []).map((r, i) => {
                      const number = r.phone_number || r.phone || r.msisdn || r.recipient || r.number || `Recipient ${i + 1}`;
                      return (
                        <Text key={i} style={{ color: colors.subtext, fontSize: 12, marginBottom: 2 }}>
                          {number}: {r.status}{r.error_message ? ` (${r.error_message})` : ''}
                        </Text>
                      );
                    })}
                  </View>
                )}
              </>
            )}
            <ShareReceiptButton
              colors={colors}
              title="SMS Job Receipt"
              rows={[
                `Sender ID: ${receipt.senderId}`,
                `Recipients: ${receipt.recipientCount}`,
                `Pages: ${receipt.pagesPerSms || receipt.pages}`,
                `Status: ${receipt.status || 'processing'}`,
                `Reference: ${receipt.transaction?.reference}`,
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Bulk SMS</Text>
        <Text style={{ color: '#fff', opacity: 0.85, marginTop: 2 }}>
          {loadingPricing ? 'Loading pricing…' : `₦${costPerPage}/page`}
        </Text>
        <TouchableOpacity onPress={loadJobHistory} style={{ marginTop: 10, alignSelf: 'flex-start' }}>
          <Text style={{ color: '#fff', fontWeight: '700', fontSize: 13, textDecorationLine: 'underline' }}>View Past SMS Jobs</Text>
        </TouchableOpacity>
      </View>

      {showHistory && (
        <Modal visible transparent animationType="slide" onRequestClose={() => setShowHistory(false)}>
          <View style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.5)', justifyContent: 'flex-end' }}>
            <View style={{ backgroundColor: colors.bg, borderTopLeftRadius: 20, borderTopRightRadius: 20, maxHeight: '80%', padding: 20 }}>
              <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <Text style={s.sectionTitle}>Past SMS Jobs</Text>
                <TouchableOpacity onPress={() => setShowHistory(false)}>
                  <Ionicons name="close" size={24} color={colors.text} />
                </TouchableOpacity>
              </View>
              {loadingHistory ? (
                <ActivityIndicator color={colors.accent} style={{ marginVertical: 20 }} />
              ) : !jobHistory || jobHistory.length === 0 ? (
                <Text style={{ color: colors.subtext, textAlign: 'center', marginVertical: 20 }}>No SMS jobs found.</Text>
              ) : (
                <ScrollView>
                  {jobHistory.map((job, i) => (
                    <View key={i} style={{ paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: colors.border }}>
                      <Text style={{ color: colors.text, fontWeight: '700', fontSize: 14 }}>{job.job_id}</Text>
                      <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 2 }} numberOfLines={1}>
                        {job.message}
                      </Text>
                      <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 4 }}>
                        Status: {job.status} · Sent: {job.sent_count}/{job.total_recipients}
                        {job.failed_count > 0 ? ` · Failed: ${job.failed_count}` : ''}
                      </Text>
                      <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 2 }}>
                        ₦{job.total_amount} · {new Date(job.date_created).toLocaleString()}
                      </Text>
                    </View>
                  ))}
                </ScrollView>
              )}
            </View>
          </View>
        </Modal>
      )}

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">

        <Text style={s.sectionTitle}>Sender ID</Text>
        <TextInput
          style={s.input}
          placeholder="e.g. BIGISUB"
          placeholderTextColor={colors.subtext}
          value={senderId}
          onChangeText={(t) => setSenderId(t.slice(0, 11))}
          maxLength={11}
          autoCapitalize="characters"
        />
        <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 4, marginBottom: 16, textAlign: 'right' }}>
          {senderId.length}/11
        </Text>

        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <Text style={s.sectionTitle}>Message</Text>
          <TouchableOpacity
            onPress={() => setShowTemplates((v) => !v)}
            style={{ flexDirection: 'row', alignItems: 'center', backgroundColor: colors.iconWrap, paddingHorizontal: 12, paddingVertical: 6, borderRadius: 20 }}
          >
            <Ionicons name="flash-outline" size={14} color={colors.accent} style={{ marginRight: 4 }} />
            <Text style={{ color: colors.accent, fontWeight: '600', fontSize: 12.5 }}>Templates</Text>
          </TouchableOpacity>
        </View>
        {showTemplates && (
          <View style={{ marginBottom: 10 }}>
            {SMS_TEMPLATES.map((t, i) => (
              <TouchableOpacity
                key={i}
                onPress={() => { setMessage(t.text); setShowTemplates(false); }}
                style={{ padding: 10, backgroundColor: colors.card, borderRadius: 8, marginBottom: 6 }}
              >
                <Text style={{ color: colors.text, fontWeight: '600', fontSize: 12.5 }}>{t.label}</Text>
                <Text style={{ color: colors.subtext, fontSize: 11.5 }} numberOfLines={2}>{t.text}</Text>
              </TouchableOpacity>
            ))}
          </View>
        )}
        <TextInput
          style={[s.input, { height: 110, textAlignVertical: 'top' }]}
          placeholder="Type your message"
          placeholderTextColor={colors.subtext}
          value={message}
          onChangeText={setMessage}
          multiline
        />
        <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: 4, marginBottom: 16 }}>
          {message.length} chars · {pages} page{pages === 1 ? '' : 's'} · {isUnicode ? 'Unicode' : 'Plain'}
        </Text>

        <Text style={s.sectionTitle}>Recipients</Text>
        <TouchableOpacity
          onPress={pasteNumbers}
          style={{ flexDirection: 'row', alignItems: 'center', alignSelf: 'flex-start', backgroundColor: colors.iconWrap, paddingHorizontal: 12, paddingVertical: 8, borderRadius: 10, marginTop: 6, marginBottom: 10 }}
        >
          <Ionicons name="copy-outline" size={14} color={colors.accent} style={{ marginRight: 6 }} />
          <Text style={{ color: colors.accent, fontWeight: '600', fontSize: 12.5 }}>Paste Numbers</Text>
        </TouchableOpacity>
        <TextInput
          style={[s.input, { height: 100, textAlignVertical: 'top' }]}
          placeholder="08012345678, 08098765432, ..."
          placeholderTextColor={colors.subtext}
          value={recipientsText}
          onChangeText={setRecipientsText}
          multiline
        />
        <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: 4, marginBottom: 4 }}>
          Separate numbers with commas, spaces, or new lines
        </Text>
        <Text style={{ color: colors.subtext, fontSize: 11.5, marginBottom: 16 }}>
          {recipients.length} recipient{recipients.length === 1 ? '' : 's'}
        </Text>

        <View style={[s.receiptCard, { marginBottom: 16 }]}>
          <Text style={{ color: colors.text, fontWeight: '700', fontSize: 14, marginBottom: 4 }}>
            Estimated cost: ₦{estimatedCost.toLocaleString()}
          </Text>
          <Text style={{ color: colors.subtext, fontSize: 12 }}>
            {pages} page{pages === 1 ? '' : 's'} × {recipients.length} recipient{recipients.length === 1 ? '' : 's'} × ₦{costPerPage}/page
          </Text>
        </View>

        <TouchableOpacity style={s.loginBtn} onPress={confirmSend} disabled={sending}>
          {sending ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Send</Text>}
        </TouchableOpacity>

        <TouchableOpacity onPress={clearDraft} style={{ marginTop: 16, alignSelf: 'center' }}>
          <Text style={{ color: colors.subtext, fontSize: 12.5 }}>Clear draft</Text>
        </TouchableOpacity>
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function CableScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [provider, setProvider] = useState(null);
  const [plans, setPlans] = useState([]);
  const [loadingPlans, setLoadingPlans] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [smartCardNumber, setSmartCardNumber] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState(null);
  const [phone, setPhone] = useState('');
  const [buying, setBuying] = useState(false);
  const [receipt, setReceipt] = useState(null);

  const resetVerification = () => setVerified(null);

  const chooseProvider = async (p) => {
    setProvider(p.value);
    setSelectedPlan(null);
    resetVerification();
    setLoadingPlans(true);
    try {
      const data = await api('/api/v1/vtu/cable/plans', { token });
      const all = Array.isArray(data) ? data : [];
      const filtered = all.filter((pl) => !pl.cableTV || String(pl.cableTV).toLowerCase() === p.value);
      setPlans(filtered.length ? filtered : all);
    } catch (e) {
      Alert.alert('Could not load packages', e.message);
      setPlans([]);
    } finally {
      setLoadingPlans(false);
    }
  };

  const doVerify = async () => {
    if (!provider) return Alert.alert('Select provider', 'Choose your cable TV provider first');
    if (!smartCardNumber) return Alert.alert('Missing smartcard number', 'Enter the smartcard/IUC number');
    setVerifying(true);
    try {
      const data = await api('/api/v1/vtu/cable/verify', {
        method: 'POST',
        token,
        body: { provider, smartCardNumber },
      });
      setVerified(data);
    } catch (e) {
      setVerified(null);
      Alert.alert('Verification failed', e.message);
    } finally {
      setVerifying(false);
    }
  };

  const confirmPurchase = () => {
    if (!selectedPlan) return Alert.alert('Select package', 'Choose a subscription package first');
    if (!phone || phone.length < 10) return Alert.alert('Invalid phone', 'Enter a valid phone number');
    const providerLabel = CABLE_PROVIDERS.find((p) => p.value === provider)?.label || provider;
    Alert.alert(
      'Confirm Purchase',
      `${providerLabel} ${formatPlanLabel(selectedPlan)} for ${verified?.name || smartCardNumber}\n\nAmount: ₦${selectedPlan.sellingPrice?.toLocaleString()}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Pay Now', onPress: doPurchase },
      ]
    );
  };

  const doPurchase = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setBuying(true);
    try {
      const data = await api('/api/v1/vtu/cable', {
        method: 'POST',
        token,
        body: {
          provider,
          smartCardNumber,
          planCode: selectedPlan.id || selectedPlan.code,
          phone,
          pin,
        },
      });
      setReceipt({ ...data, provider, smartCardNumber, phone, plan: selectedPlan });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Purchase failed', e.message);
    } finally {
      setBuying(false);
    }
  };

  if (receipt) {
    const providerLabel = CABLE_PROVIDERS.find((p) => p.value === receipt.provider)?.label || receipt.provider;
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Subscription Successful</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Provider: {providerLabel}</Text>
            <Text style={s.receiptRow}>Package: {formatPlanLabel(receipt.plan)}</Text>
            <Text style={s.receiptRow}>Smartcard: {receipt.smartCardNumber}</Text>
            <Text style={s.receiptRow}>Amount: ₦{receipt.plan?.sellingPrice?.toLocaleString()}</Text>
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            <ShareReceiptButton
              colors={colors}
              title="Cable TV Subscription Receipt"
              rows={[
                `Provider: ${providerLabel}`,
                `Package: ${formatPlanLabel(receipt.plan)}`,
                `Smartcard: ${receipt.smartCardNumber}`,
                `Amount: ₦${receipt.plan?.sellingPrice?.toLocaleString()}`,
                `Reference: ${receipt.transaction?.reference}`,
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Pay Cable TV</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Provider</Text>
        <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
          {CABLE_PROVIDERS.map((p) => (
            <TouchableOpacity
              key={p.value}
              onPress={() => chooseProvider(p)}
              style={[
                s.networkPill,
                { borderColor: colors.accent, backgroundColor: provider === p.value ? colors.accent : 'transparent' },
              ]}
            >
              <Text style={{ color: provider === p.value ? '#fff' : colors.text, fontWeight: '600' }}>{p.label}</Text>
            </TouchableOpacity>
          ))}
        </View>

        {provider && (
          <TextInput
            style={s.input}
            placeholder="Smartcard / IUC number"
            placeholderTextColor={colors.subtext}
            keyboardType="number-pad"
            value={smartCardNumber}
            onChangeText={(v) => { setSmartCardNumber(v); resetVerification(); }}
          />
        )}

        {provider && (
          <TouchableOpacity style={s.loginBtn} onPress={doVerify} disabled={verifying}>
            {verifying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Verify Smartcard</Text>}
          </TouchableOpacity>
        )}

        {verified && (
          <View style={[s.vaCard, { marginTop: 18 }]}>
            <Text style={s.vaBank}>Customer Name</Text>
            <Text style={s.vaAccountNumber}>{verified.name}</Text>
            {verified.currentPlan ? <Text style={{ color: colors.subtext, marginTop: 6 }}>Current plan: {verified.currentPlan}</Text> : null}
          </View>
        )}

        {loadingPlans && <ActivityIndicator color={colors.accent} style={{ marginTop: 20 }} />}

        {verified && !loadingPlans && plans.length > 0 && (
          <>
            <Text style={[s.sectionTitle, { marginTop: 18 }]}>Select Package</Text>
            {plans.map((p, i) => (
              <TouchableOpacity
                key={i}
                style={[s.planCard, selectedPlan === p && { borderColor: colors.accent, borderWidth: 2 }]}
                onPress={() => setSelectedPlan(p)}
              >
                <View>
                  <Text style={s.planName}>{formatPlanLabel(p)}</Text>
                </View>
                <Text style={s.planPrice}>₦{p.sellingPrice?.toLocaleString()}</Text>
              </TouchableOpacity>
            ))}
          </>
        )}

        {verified && !loadingPlans && plans.length === 0 && (
          <Text style={{ color: colors.subtext, marginTop: 10 }}>No packages found for this provider.</Text>
        )}

        {verified && selectedPlan && (
          <>
            <TextInput
              style={[s.input, { marginTop: 18 }]}
              placeholder="Phone number"
              placeholderTextColor={colors.subtext}
              keyboardType="phone-pad"
              value={phone}
              onChangeText={setPhone}
            />
            {!!user?.phone && phone !== user.phone && (
              <TouchableOpacity onPress={() => setPhone(user.phone)} style={{ alignSelf: 'flex-start', marginTop: -8, marginBottom: 14 }}>
                <Text style={{ color: colors.accent, fontSize: 13, fontWeight: '600' }}>Use my number ({user.phone})</Text>
              </TouchableOpacity>
            )}
            <TouchableOpacity style={s.loginBtn} onPress={confirmPurchase} disabled={buying}>
              {buying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Pay Now</Text>}
            </TouchableOpacity>
          </>
        )}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Exam Pins Screen ────────────────────────────────────────────────────────
function ExamScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [prices, setPrices] = useState([]);
  const [loadingPrices, setLoadingPrices] = useState(true);
  const [examType, setExamType] = useState(null);
  const [quantity, setQuantity] = useState('1');
  const [phone, setPhone] = useState('');
  const [buying, setBuying] = useState(false);
  const [receipt, setReceipt] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await api('/api/v1/vtu/exam/prices', { token });
        setPrices(Array.isArray(data) ? data : []);
      } catch (e) {
        Alert.alert('Could not load exam prices', e.message);
      } finally {
        setLoadingPrices(false);
      }
    })();
  }, []);

  const selectedInfo = prices.find((p) => p.code === examType);
  const qty = Number(quantity) || 1;
  const total = selectedInfo ? Number(selectedInfo.amount) * qty : 0;

  const confirmPurchase = () => {
    if (!examType) return Alert.alert('Select exam', 'Choose an exam type first');
    if (!phone || phone.length < 10) return Alert.alert('Invalid phone', 'Enter a valid phone number');
    if (qty < 1) return Alert.alert('Invalid quantity', 'Quantity must be at least 1');
    Alert.alert(
      'Confirm Purchase',
      `${selectedInfo?.name || examType.toUpperCase()} pin x${qty}\n\nTotal: ₦${total.toLocaleString()}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Buy Now', onPress: doPurchase },
      ]
    );
  };

  const doPurchase = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setBuying(true);
    try {
      const data = await api('/api/v1/vtu/exam', {
        method: 'POST',
        token,
        body: { examType, quantity: qty, phone, pin },
      });
      setReceipt({ ...data, examType: selectedInfo?.name || examType, quantity: qty, total });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Purchase failed', e.message);
    } finally {
      setBuying(false);
    }
  };

  if (receipt) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Purchase Successful</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Exam: {receipt.examType?.toUpperCase()}</Text>
            <Text style={s.receiptRow}>Quantity: {receipt.quantity}</Text>
            <Text style={s.receiptRow}>Amount: ₦{receipt.total?.toLocaleString()}</Text>
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            {Array.isArray(receipt.pins) && receipt.pins.length > 0 && (
              <>
                <Text style={[s.receiptRow, { fontWeight: 'bold', marginTop: 6 }]}>Pins:</Text>
                {receipt.pins.map((pin, i) => (
                  <Text key={i} style={s.receiptRow}>
                    {pin.serial ? `${pin.serial}: ` : ''}{pin.pin || pin}
                  </Text>
                ))}
              </>
            )}
            <ShareReceiptButton
              colors={colors}
              title="Exam Pin Purchase Receipt"
              rows={[
                `Exam: ${receipt.examType?.toUpperCase()}`,
                `Quantity: ${receipt.quantity}`,
                `Amount: ₦${receipt.total?.toLocaleString()}`,
                `Reference: ${receipt.transaction?.reference}`,
                ...(Array.isArray(receipt.pins) ? receipt.pins.map((pin) => `${pin.serial ? pin.serial + ': ' : ''}${pin.pin || pin}`) : []),
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Buy Exam Pin</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Exam</Text>
        {loadingPrices ? (
          <ActivityIndicator color={colors.accent} style={{ marginBottom: 20 }} />
        ) : (
          <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
            {prices.map((p, i) => (
              <TouchableOpacity
                key={i}
                onPress={() => setExamType(p.code)}
                style={[
                  s.networkPill,
                  { borderColor: colors.accent, backgroundColor: examType === p.code ? colors.accent : 'transparent' },
                ]}
              >
                <Text style={{ color: examType === p.code ? '#fff' : colors.text, fontWeight: '600' }}>
                  {p.name || (p.code || 'Exam').toUpperCase()} - ₦{Number(p.amount).toLocaleString()}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        )}

        <TextInput
          style={s.input}
          placeholder="Quantity"
          placeholderTextColor={colors.subtext}
          keyboardType="number-pad"
          value={quantity}
          onChangeText={setQuantity}
        />

        <TextInput
          style={s.input}
          placeholder="Phone number"
          placeholderTextColor={colors.subtext}
          keyboardType="phone-pad"
          value={phone}
          onChangeText={setPhone}
        />
        {!!user?.phone && phone !== user.phone && (
          <TouchableOpacity onPress={() => setPhone(user.phone)} style={{ alignSelf: 'flex-start', marginTop: -8, marginBottom: 14 }}>
            <Text style={{ color: colors.accent, fontSize: 13, fontWeight: '600' }}>Use my number ({user.phone})</Text>
          </TouchableOpacity>
        )}

        {selectedInfo && (
          <Text style={{ color: colors.subtext, marginBottom: 14 }}>
            Total: ₦{total.toLocaleString()} ({qty} x ₦{Number(selectedInfo.amount).toLocaleString()})
          </Text>
        )}

        <TouchableOpacity style={s.loginBtn} onPress={confirmPurchase} disabled={buying}>
          {buying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Buy Now</Text>}
        </TouchableOpacity>
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── JAMB e-PIN Screen ───────────────────────────────────────────────────────
// Note: KlubConnect's JAMB API has no quantity param — each purchase buys exactly 1 pin.
function JambScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [packages, setPackages] = useState([]);
  const [loadingPackages, setLoadingPackages] = useState(true);
  const [examType, setExamType] = useState(null);
  const [phone, setPhone] = useState('');
  const [profileId, setProfileId] = useState('');
  const [verified, setVerified] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [buying, setBuying] = useState(false);
  const [receipt, setReceipt] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await api('/api/v1/vtu/jamb/packages', { token });
        setPackages(Array.isArray(data) ? data : []);
      } catch (e) {
        Alert.alert('Could not load JAMB packages', e.message);
      } finally {
        setLoadingPackages(false);
      }
    })();
  }, []);

  const selectedInfo = packages.find((p) => p.code === examType);
  const total = selectedInfo?.sellingPrice ? Number(selectedInfo.sellingPrice) : 0;

  // Profile ID is optional (only needed for Direct Entry / reprinting), so verification is
  // only required when one is entered — same "verify before you pay" pattern as Cable/Electric,
  // just conditional on whether there's anything to verify.
  const resetVerification = () => setVerified(null);

  const doVerify = async () => {
    if (!profileId) return;
    setVerifying(true);
    try {
      const data = await api('/api/v1/vtu/jamb/verify', {
        method: 'POST',
        token,
        body: { profileId },
      });
      setVerified(data);
    } catch (e) {
      setVerified(null);
      Alert.alert('Verification failed', e.message);
    } finally {
      setVerifying(false);
    }
  };

  const confirmPurchase = () => {
    if (!examType) return Alert.alert('Select package', 'Choose a JAMB package first');
    if (!selectedInfo?.sellingPrice) return Alert.alert('Price unavailable', 'This package has no live price right now, try again shortly');
    if (!phone || phone.length < 10) return Alert.alert('Invalid phone', 'Enter a valid phone number');
    if (profileId && !verified) return Alert.alert('Verify Profile ID', 'Tap "Verify Profile ID" first so we can confirm it before you pay');
    Alert.alert(
      'Confirm Purchase',
      `${selectedInfo?.name || examType}${verified?.name ? `\nProfile: ${verified.name}` : ''}\n\nTotal: ₦${total.toLocaleString()}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Buy Now', onPress: doPurchase },
      ]
    );
  };

  const doPurchase = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setBuying(true);
    try {
      const data = await api('/api/v1/vtu/jamb', {
        method: 'POST',
        token,
        body: { examType, phone, profileId: profileId || undefined, pin },
      });
      setReceipt({ ...data, examType: selectedInfo?.name || examType, total });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Purchase failed', e.message);
    } finally {
      setBuying(false);
    }
  };

  if (receipt) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Purchase Successful</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Package: {receipt.examType}</Text>
            <Text style={s.receiptRow}>Amount: ₦{receipt.total?.toLocaleString()}</Text>
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            {!!receipt.serial && <Text style={s.receiptRow}>Serial No: {receipt.serial}</Text>}
            {!!receipt.pin && <Text style={[s.receiptRow, { fontWeight: 'bold' }]}>PIN: {receipt.pin}</Text>}
            <ShareReceiptButton
              colors={colors}
              title="JAMB e-PIN Purchase Receipt"
              rows={[
                `Package: ${receipt.examType}`,
                `Amount: ₦${receipt.total?.toLocaleString()}`,
                `Reference: ${receipt.transaction?.reference}`,
                receipt.serial ? `Serial No: ${receipt.serial}` : null,
                receipt.pin ? `PIN: ${receipt.pin}` : null,
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Buy JAMB e-PIN</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Package</Text>
        {loadingPackages ? (
          <ActivityIndicator color={colors.accent} style={{ marginBottom: 20 }} />
        ) : (
          <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
            {packages.map((p, i) => (
              <TouchableOpacity
                key={i}
                onPress={() => setExamType(p.code)}
                style={[
                  s.networkPill,
                  { borderColor: colors.accent, backgroundColor: examType === p.code ? colors.accent : 'transparent' },
                ]}
              >
                <Text style={{ color: examType === p.code ? '#fff' : colors.text, fontWeight: '600' }}>
                  {p.name}{p.sellingPrice ? ` - ₦${Number(p.sellingPrice).toLocaleString()}` : ' (price unavailable)'}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        )}

        <TextInput
          style={s.input}
          placeholder="Phone number"
          placeholderTextColor={colors.subtext}
          keyboardType="phone-pad"
          value={phone}
          onChangeText={setPhone}
        />
        {!!user?.phone && phone !== user.phone && (
          <TouchableOpacity onPress={() => setPhone(user.phone)} style={{ alignSelf: 'flex-start', marginTop: -8, marginBottom: 14 }}>
            <Text style={{ color: colors.accent, fontSize: 13, fontWeight: '600' }}>Use my number ({user.phone})</Text>
          </TouchableOpacity>
        )}

        <TextInput
          style={s.input}
          placeholder="JAMB Profile ID (only needed for Direct Entry / reprinting)"
          placeholderTextColor={colors.subtext}
          value={profileId}
          onChangeText={(v) => { setProfileId(v); resetVerification(); }}
        />

        {!!profileId && !verified && (
          <TouchableOpacity style={[s.loginBtn, { marginBottom: 14 }]} onPress={doVerify} disabled={verifying}>
            {verifying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Verify Profile ID</Text>}
          </TouchableOpacity>
        )}

        {verified && (
          <View style={[s.vaCard, { marginBottom: 14 }]}>
            <Text style={s.vaBank}>Profile Name</Text>
            <Text style={s.vaAccountNumber}>{verified.name}</Text>
          </View>
        )}

        {selectedInfo?.sellingPrice && (
          <Text style={{ color: colors.subtext, marginBottom: 14 }}>Total: ₦{total.toLocaleString()}</Text>
        )}

        <TouchableOpacity style={s.loginBtn} onPress={confirmPurchase} disabled={buying}>
          {buying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Buy Now</Text>}
        </TouchableOpacity>
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Recharge Pin Screen ─────────────────────────────────────────────────────
const RECHARGE_DENOMINATIONS = [100, 200, 500, 1000];

function RechargePinScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [network, setNetwork] = useState(null);
  const [denomination, setDenomination] = useState('');
  const [quantity, setQuantity] = useState('1');
  const [nameOnCard, setNameOnCard] = useState('');
  const [quote, setQuote] = useState(null);
  const [quoting, setQuoting] = useState(false);
  const [buying, setBuying] = useState(false);
  const [receipt, setReceipt] = useState(null);

  const qty = Number(quantity) || 1;
  const denom = Number(denomination) || 0;

  // Fetches the exact price for denom × quantity, straight from the backend, so it matches
  // what actually gets debited. (For KlubConnect this is exact; for Bigisub it's a close
  // preview since Bigisub prices off its own plan catalog — the receipt after purchase always
  // shows the real charged amount either way.)
  useEffect(() => {
    const totalCost = denom * qty;
    if (!totalCost || totalCost <= 0) { setQuote(null); return; }
    setQuoting(true);
    const t = setTimeout(async () => {
      try {
        const q = await api(`/api/v1/pricing/quote?service=recharge_pin&amount=${totalCost}`, { token });
        setQuote(q);
      } catch (e) {
        setQuote(null);
      } finally {
        setQuoting(false);
      }
    }, 400);
    return () => clearTimeout(t);
  }, [denom, qty, token]);

  const confirmPurchase = () => {
    if (!network) return Alert.alert('Select network', 'Choose a network first');
    if (!denom) return Alert.alert('Missing denomination', 'Enter or select a card denomination');
    if (qty < 1) return Alert.alert('Invalid quantity', 'Quantity must be at least 1');
    Alert.alert(
      'Confirm Purchase',
      `${network} ₦${denom.toLocaleString()} recharge pin x${qty}${quote ? `\n\nYou'll be charged: ₦${quote.sellingPrice.toLocaleString()}` : ''}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Print Now', onPress: doPurchase },
      ]
    );
  };

  const doPurchase = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setBuying(true);
    try {
      const data = await api('/api/v1/vtu/recharge-pin', {
        method: 'POST',
        token,
        body: { network, denomination: denom, quantity: qty, nameOnCard: nameOnCard || undefined, pin },
      });
      // Use the actual charged amount from the transaction record, not the client-side estimate.
      setReceipt({ ...data, network, denomination: denom, quantity: qty, amountCharged: data.transaction?.amount ?? quote?.sellingPrice });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Purchase failed', e.message);
    } finally {
      setBuying(false);
    }
  };

  if (receipt) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Pins Generated</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Network: {receipt.network}</Text>
            <Text style={s.receiptRow}>Denomination: ₦{receipt.denomination?.toLocaleString()}</Text>
            <Text style={s.receiptRow}>Quantity: {receipt.quantity}</Text>
            {receipt.amountCharged ? <Text style={s.receiptRow}>Amount Charged: ₦{Number(receipt.amountCharged).toLocaleString()}</Text> : null}
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            {Array.isArray(receipt.pins) && receipt.pins.length > 0 && (
              <>
                <Text style={[s.receiptRow, { fontWeight: 'bold', marginTop: 6 }]}>Pins:</Text>
                {receipt.pins.map((pin, i) => (
                  <Text key={i} style={s.receiptRow}>
                    {pin.serial ? `${pin.serial}: ` : ''}{pin.pin || pin}
                  </Text>
                ))}
              </>
            )}
            <ShareReceiptButton
              colors={colors}
              title="Recharge Pin Receipt"
              rows={[
                `Network: ${receipt.network}`,
                `Denomination: ₦${receipt.denomination?.toLocaleString()}`,
                `Quantity: ${receipt.quantity}`,
                receipt.amountCharged ? `Amount Charged: ₦${Number(receipt.amountCharged).toLocaleString()}` : null,
                `Reference: ${receipt.transaction?.reference}`,
                ...(Array.isArray(receipt.pins) ? receipt.pins.map((pin) => `${pin.serial ? pin.serial + ': ' : ''}${pin.pin || pin}`) : []),
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Recharge Pin</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Network</Text>
        <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
          {NETWORKS.map((n) => (
            <TouchableOpacity
              key={n}
              onPress={() => setNetwork(n)}
              style={[
                s.networkPill,
                { borderColor: NETWORK_COLORS[n], backgroundColor: network === n ? NETWORK_COLORS[n] : 'transparent' },
              ]}
            >
              <Text style={{ color: network === n ? '#fff' : colors.text, fontWeight: '600' }}>{n}</Text>
            </TouchableOpacity>
          ))}
        </View>

        <Text style={s.sectionTitle}>Denomination</Text>
        <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 14 }}>
          {RECHARGE_DENOMINATIONS.map((d) => (
            <TouchableOpacity
              key={d}
              onPress={() => setDenomination(String(d))}
              style={[
                s.networkPill,
                { borderColor: colors.accent, backgroundColor: denom === d ? colors.accent : 'transparent' },
              ]}
            >
              <Text style={{ color: denom === d ? '#fff' : colors.text, fontWeight: '600' }}>₦{d.toLocaleString()}</Text>
            </TouchableOpacity>
          ))}
        </View>

        <TextInput
          style={s.input}
          placeholder="Or type custom denomination (₦)"
          placeholderTextColor={colors.subtext}
          keyboardType="number-pad"
          value={denomination}
          onChangeText={setDenomination}
        />

        <TextInput
          style={s.input}
          placeholder="Quantity"
          placeholderTextColor={colors.subtext}
          keyboardType="number-pad"
          value={quantity}
          onChangeText={setQuantity}
        />

        <TextInput
          style={s.input}
          placeholder="Name on card (optional)"
          placeholderTextColor={colors.subtext}
          value={nameOnCard}
          onChangeText={setNameOnCard}
        />

        <TouchableOpacity style={[s.loginBtn, { marginTop: 6 }]} onPress={confirmPurchase} disabled={buying}>
          {buying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Print Recharge Cards</Text>}
        </TouchableOpacity>
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Airtime-to-Cash Screen ─────────────────────────────────────────────────
const A2C_RATE = 0.85; // estimate only, backend is source of truth

function AirtimeToCashScreen({ token, user, onBack }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [network, setNetwork] = useState(null);
  const [airtimeAmount, setAirtimeAmount] = useState('');
  const [accountNumber, setAccountNumber] = useState('');
  const [bankName, setBankName] = useState('');
  const [accountName, setAccountName] = useState('');
  const [phone, setPhone] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [pending, setPending] = useState(null);
  const [receivingNumbers, setReceivingNumbers] = useState({});
  const [loadingNumbers, setLoadingNumbers] = useState(true);
  const [banks, setBanks] = useState([]);
  const [bankCode, setBankCode] = useState(null);
  const [showBankPicker, setShowBankPicker] = useState(false);
  const [bankSearch, setBankSearch] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const data = await api('/api/v1/banks', { token });
        setBanks(Array.isArray(data) ? data : []);
      } catch (e) {
        // free-text fallback below still lets the request go through
      }
    })();
  }, [token]);

  useEffect(() => {
    (async () => {
      try {
        const data = await api('/api/v1/vtu/airtime-to-cash/receiving-numbers', { token });
        setReceivingNumbers(data || {});
      } catch (e) {
        // fall through — the "send to" card just won't render, but the
        // request can still be submitted and support can follow up
      } finally {
        setLoadingNumbers(false);
      }
    })();
  }, [token]);

  const amt = Number(airtimeAmount) || 0;
  const estimatedCash = Math.round(amt * A2C_RATE);
  const receiveNumberForNetwork = network ? receivingNumbers[network] : null;

  const confirmSubmit = () => {
    if (!network) return Alert.alert('Select network', 'Choose the network the airtime is coming from');
    if (!receiveNumberForNetwork) return Alert.alert('Not available', `We don't have a receiving number for ${network} right now. Please try another network, or reach us on WhatsApp at +${toWhatsAppNumber(SUPPORT_WHATSAPP_RAW)}.`);
    if (!amt || amt < 100) return Alert.alert('Invalid amount', 'Minimum airtime-to-cash is ₦100');
    if (!accountNumber || !bankName || !accountName) return Alert.alert('Missing payout details', 'Fill in your account number, bank, and account name');
    if (banks.length > 0 && !bankCode) return Alert.alert('Select bank', 'Please pick your bank from the list so we can send your payout to the right bank');
    if (!phone || phone.length < 10) return Alert.alert('Invalid phone', 'Enter the phone number sending the airtime');
    Alert.alert(
      'Confirm Request',
      `Send ${network} airtime worth ₦${amt.toLocaleString()} to ${receiveNumberForNetwork}\n\nEstimated payout: ₦${estimatedCash.toLocaleString()}\nTo: ${accountName} — ${bankName} (${accountNumber})`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Submit Request', onPress: doSubmit },
      ]
    );
  };

  const doSubmit = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setSubmitting(true);
    try {
      const data = await api('/api/v1/vtu/airtime-to-cash', {
        method: 'POST',
        token,
        body: {
          network,
          airtimeAmount: amt,
          senderPhone: phone,
          payoutAccountNumber: accountNumber,
          payoutBankCode: bankCode,
          payoutAccountName: accountName,
          pin,
        },
      });
      setPending({ ...data, network, airtimeAmount: amt, accountNumber, bankName, accountName, receiveNumber: receiveNumberForNetwork });
    } catch (e) {
      Alert.alert('Request failed', e.message);
    } finally {
      setSubmitting(false);
    }
  };

  if (pending) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Request Submitted</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="time-outline" size={56} color="#d97706" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Network: {pending.network}</Text>
            <Text style={s.receiptRow}>Airtime Amount: ₦{pending.airtimeAmount?.toLocaleString()}</Text>
            <Text style={s.receiptRow}>Estimated Payout: ₦{(pending.cashAmount ?? Math.round(pending.airtimeAmount * A2C_RATE))?.toLocaleString()}</Text>
            <Text style={s.receiptRow}>Payout To: {pending.accountName} — {pending.bankName} ({pending.accountNumber})</Text>
            <Text style={s.receiptRow}>Reference: {pending.reference || pending.transaction?.reference}</Text>
          </View>
          {!!pending.receiveNumber && (
            <View style={[s.receiptCard, { marginTop: 14, borderWidth: 2, borderColor: NETWORK_COLORS[pending.network] || colors.accent }]}>
              <Text style={{ color: colors.subtext, marginBottom: 6 }}>Send your {pending.network} airtime now to:</Text>
              <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }}>
                <Text style={{ fontSize: 22, fontWeight: '700', color: colors.text }}>{pending.receiveNumber}</Text>
                <TouchableOpacity onPress={() => { Clipboard.setStringAsync(pending.receiveNumber); Alert.alert('Copied', 'Number copied'); }}>
                  <Ionicons name="copy-outline" size={20} color={colors.accent} />
                </TouchableOpacity>
              </View>
              <Text style={{ color: colors.subtext, marginTop: 10, fontSize: 13 }}>
                Once we confirm the airtime has arrived, your payout will be sent to the account above — status: Pending.
              </Text>
            </View>
          )}
          <ShareReceiptButton
            colors={colors}
            title="Airtime-to-Cash Request"
            rows={[
              `Network: ${pending.network}`,
              `Airtime Amount: ₦${pending.airtimeAmount?.toLocaleString()}`,
              `Estimated Payout: ₦${(pending.cashAmount ?? Math.round(pending.airtimeAmount * A2C_RATE))?.toLocaleString()}`,
              `Payout To: ${pending.accountName} — ${pending.bankName} (${pending.accountNumber})`,
              `Reference: ${pending.reference || pending.transaction?.reference}`,
            ]}
          />
          <TouchableOpacity style={[s.loginBtn, { marginTop: 14 }]} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Airtime to Cash</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Network</Text>
        <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
          {NETWORKS.map((n) => (
            <TouchableOpacity
              key={n}
              onPress={() => setNetwork(n)}
              style={[
                s.networkPill,
                { borderColor: NETWORK_COLORS[n], backgroundColor: network === n ? NETWORK_COLORS[n] : 'transparent' },
              ]}
            >
              <Text style={{ color: network === n ? '#fff' : colors.text, fontWeight: '600' }}>{n}</Text>
            </TouchableOpacity>
          ))}
        </View>

        {network && loadingNumbers && (
          <ActivityIndicator color={colors.accent} style={{ marginBottom: 16 }} />
        )}

        {network && !loadingNumbers && receiveNumberForNetwork && (
          <View style={[s.receiptCard, { marginBottom: 16, borderWidth: 2, borderColor: NETWORK_COLORS[network] }]}>
            <Text style={{ color: colors.subtext, marginBottom: 6 }}>Send your {network} airtime to:</Text>
            <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }}>
              <Text style={{ fontSize: 20, fontWeight: '700', color: colors.text }}>{receiveNumberForNetwork}</Text>
              <TouchableOpacity onPress={() => { Clipboard.setStringAsync(receiveNumberForNetwork); Alert.alert('Copied', 'Number copied'); }}>
                <Ionicons name="copy-outline" size={20} color={colors.accent} />
              </TouchableOpacity>
            </View>
          </View>
        )}

        {network && !loadingNumbers && !receiveNumberForNetwork && (
          <Text style={{ color: '#dc2626', marginBottom: 16 }}>
            {network} isn't available for airtime-to-cash right now. Please choose another network.
          </Text>
        )}

        <TextInput
          style={s.input}
          placeholder="Phone number sending the airtime"
          placeholderTextColor={colors.subtext}
          keyboardType="phone-pad"
          value={phone}
          onChangeText={setPhone}
        />
        {!!user?.phone && phone !== user.phone && (
          <TouchableOpacity onPress={() => setPhone(user.phone)} style={{ alignSelf: 'flex-start', marginTop: -8, marginBottom: 14 }}>
            <Text style={{ color: colors.accent, fontSize: 13, fontWeight: '600' }}>Use my number ({user.phone})</Text>
          </TouchableOpacity>
        )}

        <TextInput
          style={s.input}
          placeholder="Airtime amount (min ₦100)"
          placeholderTextColor={colors.subtext}
          keyboardType="number-pad"
          value={airtimeAmount}
          onChangeText={setAirtimeAmount}
        />

        {amt > 0 && (
          <Text style={{ color: colors.subtext, marginBottom: 14 }}>
            Estimated payout: ₦{estimatedCash.toLocaleString()} (final rate confirmed by support)
          </Text>
        )}

        <Text style={[s.sectionTitle, { marginTop: 6 }]}>Payout Account</Text>
        <TextInput
          style={s.input}
          placeholder="Account number"
          placeholderTextColor={colors.subtext}
          keyboardType="number-pad"
          value={accountNumber}
          onChangeText={setAccountNumber}
        />
        <TouchableOpacity
          style={[s.input, { justifyContent: 'center' }]}
          onPress={() => (banks.length > 0 ? setShowBankPicker(true) : null)}
        >
          <Text style={{ color: bankName ? colors.text : colors.subtext, fontSize: 15 }}>
            {bankName || (banks.length > 0 ? 'Select bank' : 'Bank name')}
          </Text>
        </TouchableOpacity>
        {banks.length === 0 && (
          <TextInput
            style={s.input}
            placeholder="Bank name (type manually)"
            placeholderTextColor={colors.subtext}
            value={bankName}
            onChangeText={setBankName}
          />
        )}
        <TextInput
          style={s.input}
          placeholder="Account name"
          placeholderTextColor={colors.subtext}
          value={accountName}
          onChangeText={setAccountName}
        />

        <TouchableOpacity style={[s.loginBtn, { marginTop: 6 }]} onPress={confirmSubmit} disabled={submitting}>
          {submitting ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Submit Request</Text>}
        </TouchableOpacity>
      </ScrollView>
      </KeyboardAvoidingView>

      <Modal visible={showBankPicker} transparent animationType="slide" onRequestClose={() => setShowBankPicker(false)}>
        <View style={{ flex: 1, backgroundColor: '#00000088', justifyContent: 'flex-end' }}>
          <View style={{ backgroundColor: colors.bg, borderTopLeftRadius: 18, borderTopRightRadius: 18, maxHeight: '75%', paddingTop: 16 }}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: 20 }}>
              <Text style={{ color: colors.text, fontSize: 16, fontWeight: 'bold' }}>Select Bank</Text>
              <TouchableOpacity onPress={() => setShowBankPicker(false)}>
                <Ionicons name="close" size={24} color={colors.subtext} />
              </TouchableOpacity>
            </View>
            <TextInput
              style={[s.input, { marginHorizontal: 20, marginTop: 12 }]}
              placeholder="Search bank"
              placeholderTextColor={colors.subtext}
              value={bankSearch}
              onChangeText={setBankSearch}
              autoFocus
            />
            <FlatList
              data={banks.filter((b) => (b.name || '').toLowerCase().includes(bankSearch.toLowerCase()))}
              keyExtractor={(b, i) => String(b.code || b.id || i)}
              renderItem={({ item }) => (
                <TouchableOpacity
                  style={{ paddingVertical: 14, paddingHorizontal: 20, borderBottomWidth: 1, borderBottomColor: colors.inputBorder }}
                  onPress={() => { setBankName(item.name); setBankCode(item.code); setShowBankPicker(false); setBankSearch(''); }}
                >
                  <Text style={{ color: colors.text, fontSize: 15 }}>{item.name}</Text>
                </TouchableOpacity>
              )}
              ListEmptyComponent={<Text style={{ color: colors.subtext, textAlign: 'center', marginTop: 20 }}>No banks match your search</Text>}
            />
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

// ─── Betting Screen ──────────────────────────────────────────────────────────
const FALLBACK_BETTING_PROVIDERS = [
  { code: 'nairabet', name: 'Nairabet' },
  { code: 'bangbet', name: 'BangBet' },
  { code: 'betway', name: 'BetWay' },
  { code: 'betland', name: 'BetLand' },
  { code: 'betking', name: 'BetKing' },
  { code: '1xbet', name: '1xBet' },
  { code: 'naijabet', name: 'NaijaBet' },
  { code: 'sportybet', name: 'Sporty Bet' },
  { code: 'merrybet', name: 'MerryBet' },
];

function BettingScreen({ token, user, onBack, onWalletChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [providers, setProviders] = useState([]);
  const [loadingProviders, setLoadingProviders] = useState(true);
  const [usingFallback, setUsingFallback] = useState(false);
  const [provider, setProvider] = useState(null);
  const [customerId, setCustomerId] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verified, setVerified] = useState(null);
  const [phone, setPhone] = useState('');
  const [amount, setAmount] = useState('');
  const [buying, setBuying] = useState(false);
  const [receipt, setReceipt] = useState(null);
  const [products, setProducts] = useState([]);
  const [loadingProducts, setLoadingProducts] = useState(false);
  const [checkingStatus, setCheckingStatus] = useState(false);
  const [statusResult, setStatusResult] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await api('/api/v1/betting/billers', { token });
        const list = Array.isArray(data) ? data : data?.providers || [];
        if (list.length > 0) {
          setProviders(list);
          setUsingFallback(false);
        } else {
          setProviders(FALLBACK_BETTING_PROVIDERS);
          setUsingFallback(true);
        }
      } catch (e) {
        setProviders(FALLBACK_BETTING_PROVIDERS);
        setUsingFallback(true);
      } finally {
        setLoadingProviders(false);
      }
    })();
  }, []);

  const resetVerification = () => setVerified(null);

  const choosePlatform = async (val) => {
    setProvider(val);
    resetVerification();
    setProducts([]);
    setLoadingProducts(true);
    try {
      const data = await api(`/api/v1/betting/products?billerCode=${encodeURIComponent(val)}`, { token });
      setProducts(Array.isArray(data) ? data : []);
    } catch (e) {
      setProducts([]);
    } finally {
      setLoadingProducts(false);
    }
  };

  const checkStatus = async () => {
    const txId = receipt?.providerTransactionId || receipt?.transaction?.reference;
    if (!txId) return Alert.alert('No transaction ID', 'Nothing to check yet.');
    setCheckingStatus(true);
    try {
      const data = await api(`/api/v1/betting/requery?transactionId=${encodeURIComponent(txId)}`, { token });
      setStatusResult(data);
    } catch (e) {
      Alert.alert('Could not check status', e.message);
    } finally {
      setCheckingStatus(false);
    }
  };

  const providerLabelFor = (val) => {
    const match = providers.find((p) => discoValue(p) === val);
    return match ? discoLabel(match) : val;
  };

  const doVerify = async () => {
    if (!provider) return Alert.alert('Select platform', 'Choose your betting platform first');
    if (!customerId) return Alert.alert('Missing customer ID', 'Enter your betting account customer ID');
    setVerifying(true);
    try {
      const data = await api('/api/v1/betting/validate', {
        method: 'POST',
        token,
        body: { billerCode: provider, customerId },
      });
      setVerified({ name: data?.customerName || 'Verified' });
    } catch (e) {
      setVerified(null);
      Alert.alert('Verification failed', e.message);
    } finally {
      setVerifying(false);
    }
  };

  const confirmPurchase = () => {
    if (!phone || phone.length < 10) return Alert.alert('Invalid phone', 'Enter a valid phone number');
    const amt = Number(amount);
    if (!amt || amt < 100) return Alert.alert('Invalid amount', 'Enter a valid top-up amount');
    Alert.alert(
      'Confirm Purchase',
      `${providerLabelFor(provider)} top-up for ${verified?.name || customerId}\n\nAmount: ₦${amt.toLocaleString()}`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Pay Now', onPress: doPurchase },
      ]
    );
  };

  const doPurchase = async () => {
    const pin = await requestTransactionPin();
    if (!pin) return;
    setBuying(true);
    try {
      const data = await api('/api/v1/betting/fund', {
        method: 'POST',
        token,
        body: { billerCode: provider, customerId, amount: Number(amount), phone, pin },
      });
      setReceipt({ ...data, provider, customerId, phone, amount: Number(amount) });
      onWalletChanged && onWalletChanged();
    } catch (e) {
      Alert.alert('Purchase failed', e.message);
    } finally {
      setBuying(false);
    }
  };

  if (receipt) {
    return (
      <SafeAreaView style={s.safeArea}>
        <View style={[s.header, { paddingBottom: 20 }]}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          <Text style={s.nameText}>Top-up Successful</Text>
        </View>
        <View style={s.body}>
          <View style={s.receiptCard}>
            <Ionicons name="checkmark-circle" size={56} color="#059669" style={{ alignSelf: 'center', marginBottom: 12 }} />
            <Text style={s.receiptRow}>Platform: {providerLabelFor(receipt.provider)}</Text>
            <Text style={s.receiptRow}>Customer ID: {receipt.customerId}</Text>
            <Text style={s.receiptRow}>Amount: ₦{receipt.amount?.toLocaleString()}</Text>
            <Text style={s.receiptRow}>Reference: {receipt.transaction?.reference}</Text>
            <TouchableOpacity
              onPress={checkStatus}
              disabled={checkingStatus}
              style={{ marginTop: 14, backgroundColor: colors.iconWrap, borderRadius: 10, paddingVertical: 12, alignItems: 'center', flexDirection: 'row', justifyContent: 'center' }}
            >
              {checkingStatus ? <ActivityIndicator color={colors.accent} /> : (
                <>
                  <Ionicons name="refresh-outline" size={16} color={colors.accent} style={{ marginRight: 6 }} />
                  <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 13 }}>Check Funding Status</Text>
                </>
              )}
            </TouchableOpacity>
            {!!statusResult && (
              <View style={{ marginTop: 12, padding: 12, backgroundColor: colors.card, borderRadius: 10 }}>
                {Object.entries(statusResult).map(([k, v]) => (
                  <Text key={k} style={{ color: colors.subtext, fontSize: 12, marginBottom: 2 }}>
                    {k}: {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                  </Text>
                ))}
              </View>
            )}
            <ShareReceiptButton
              colors={colors}
              title="Betting Top-up Receipt"
              rows={[
                `Platform: ${providerLabelFor(receipt.provider)}`,
                `Customer ID: ${receipt.customerId}`,
                `Amount: ₦${receipt.amount?.toLocaleString()}`,
                `Reference: ${receipt.transaction?.reference}`,
              ]}
            />
          </View>
          <TouchableOpacity style={s.loginBtn} onPress={onBack}>
            <Text style={s.loginBtnText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Betting Top-up</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={s.sectionTitle}>Select Platform</Text>
        {loadingProviders ? (
          <ActivityIndicator color={colors.accent} style={{ marginBottom: 20 }} />
        ) : (
          <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 20 }}>
            {providers.map((p, i) => {
              const val = discoValue(p);
              return (
                <TouchableOpacity
                  key={i}
                  onPress={() => choosePlatform(val)}
                  style={[
                    s.networkPill,
                    { borderColor: colors.accent, backgroundColor: provider === val ? colors.accent : 'transparent' },
                  ]}
                >
                  <Text style={{ color: provider === val ? '#fff' : colors.text, fontWeight: '600' }}>{discoLabel(p)}</Text>
                </TouchableOpacity>
              );
            })}
          </View>
        )}

        {loadingProducts && <ActivityIndicator color={colors.accent} style={{ marginBottom: 12 }} />}
        {!loadingProducts && products.length > 0 && (
          <>
            <Text style={[s.sectionTitle, { marginTop: -8 }]}>Quick Amounts</Text>
            <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 16 }}>
              {products.map((prod, i) => {
                const prodAmount = prod.amount ?? prod.price ?? prod.value;
                const label = prod.name || prod.label || `₦${prodAmount}`;
                return (
                  <TouchableOpacity
                    key={i}
                    onPress={() => setAmount(String(prodAmount))}
                    style={[s.networkPill, { borderColor: colors.accent, backgroundColor: String(amount) === String(prodAmount) ? colors.accent : 'transparent' }]}
                  >
                    <Text style={{ color: String(amount) === String(prodAmount) ? '#fff' : colors.text, fontWeight: '600' }}>{label}</Text>
                  </TouchableOpacity>
                );
              })}
            </View>
          </>
        )}

        {!loadingProviders && usingFallback && (
          <Text style={{ color: colors.subtext, fontSize: 12, marginTop: -10, marginBottom: 16 }}>
            Showing common platforms — couldn't reach the live list, but you can still proceed.
          </Text>
        )}

        <TextInput
          style={s.input}
          placeholder="Customer ID"
          placeholderTextColor={colors.subtext}
          keyboardType="default"
          value={customerId}
          onChangeText={(v) => { setCustomerId(v); resetVerification(); }}
        />

        <TouchableOpacity style={s.loginBtn} onPress={doVerify} disabled={verifying}>
          {verifying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Verify Customer ID</Text>}
        </TouchableOpacity>

        {verified && (
          <View style={[s.vaCard, { marginTop: 18 }]}>
            <Text style={s.vaBank}>Account Name</Text>
            <Text style={s.vaAccountNumber}>{verified.name}</Text>
          </View>
        )}

        {verified && (
          <>
            <TextInput
              style={[s.input, { marginTop: 18 }]}
              placeholder="Phone number"
              placeholderTextColor={colors.subtext}
              keyboardType="phone-pad"
              value={phone}
              onChangeText={setPhone}
            />
            {!!user?.phone && phone !== user.phone && (
              <TouchableOpacity onPress={() => setPhone(user.phone)} style={{ alignSelf: 'flex-start', marginTop: -8, marginBottom: 14 }}>
                <Text style={{ color: colors.accent, fontSize: 13, fontWeight: '600' }}>Use my number ({user.phone})</Text>
              </TouchableOpacity>
            )}
            <TextInput
              style={s.input}
              placeholder="Top-up amount"
              placeholderTextColor={colors.subtext}
              keyboardType="number-pad"
              value={amount}
              onChangeText={setAmount}
            />
            <TouchableOpacity style={s.loginBtn} onPress={confirmPurchase} disabled={buying}>
              {buying ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Pay Now</Text>}
            </TouchableOpacity>
          </>
        )}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Notifications Screen ───────────────────────────────────────────────────
function timeAgo(dateStr) {
  if (!dateStr) return '';
  const then = new Date(dateStr).getTime();
  if (Number.isNaN(then)) return '';
  const diffMs = Date.now() - then;
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(then).toLocaleDateString();
}

function notifIconFor(type) {
  switch (type) {
    case 'wallet_credit':
    case 'wallet_funded':
      return { name: 'wallet-outline', color: '#059669' };
    case 'wallet_debit':
    case 'purchase':
    case 'transaction':
      return { name: 'receipt-outline', color: '#6d28d9' };
    case 'airtime_to_cash':
      return { name: 'cash-outline', color: '#d97706' };
    case 'system':
    case 'alert':
      return { name: 'alert-circle-outline', color: '#b91c1c' };
    default:
      return { name: 'notifications-outline', color: '#6d28d9' };
  }
}

function NotificationsScreen({ token, onBack, onUnreadChanged }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await api('/api/v1/notifications', { token });
      const list = Array.isArray(data) ? data : data?.notifications || [];
      setItems(list);
    } catch (e) {
      Alert.alert('Could not load notifications', e.message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const onRefresh = async () => {
    setRefreshing(true);
    await load();
    setRefreshing(false);
  };

  const markRead = async (notif) => {
    const id = notif.id || notif._id;
    const isRead = notif.read ?? notif.isRead ?? notif.is_read;
    if (isRead || !id) return;
    setItems((prev) => prev.map((n) => ((n.id || n._id) === id ? { ...n, read: true, isRead: true, is_read: true } : n)));
    onUnreadChanged && onUnreadChanged();
    try {
      await api(`/api/v1/notifications/${id}/mark-read`, { method: 'POST', token, body: {} });
    } catch (e) {
      setItems((prev) => prev.map((n) => ((n.id || n._id) === id ? { ...n, read: false, isRead: false, is_read: false } : n)));
      onUnreadChanged && onUnreadChanged();
    }
  };

  const hasUnread = items.some((n) => !(n.read ?? n.isRead ?? n.is_read));

  const markAllRead = async () => {
    const prevItems = items;
    setItems((prev) => prev.map((n) => ({ ...n, read: true, isRead: true, is_read: true })));
    onUnreadChanged && onUnreadChanged();
    try {
      await api('/api/v1/notifications/mark-read', { method: 'POST', token, body: {} });
    } catch (e) {
      setItems(prevItems);
      onUnreadChanged && onUnreadChanged();
      Alert.alert('Could not mark all as read', e.message);
    }
  };

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
          <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
            <Ionicons name="arrow-back" size={24} color="#fff" />
          </TouchableOpacity>
          {hasUnread && (
            <TouchableOpacity onPress={markAllRead} style={{ marginBottom: 10 }}>
              <Text style={{ color: '#fff', fontSize: 13, fontWeight: '600' }}>Mark all read</Text>
            </TouchableOpacity>
          )}
        </View>
        <Text style={s.nameText}>Notifications</Text>
      </View>

      {loading ? (
        <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
          <ActivityIndicator color={colors.accent} size="large" />
        </View>
      ) : (
        <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <ScrollView
          style={s.body}
          contentContainerStyle={{ paddingBottom: 40 }}
          refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} colors={[colors.accent]} />}
        >
          {items.length === 0 ? (
            <View style={{ alignItems: 'center', marginTop: 60 }}>
              <Ionicons name="notifications-off-outline" size={48} color={colors.subtext} />
              <Text style={{ color: colors.subtext, marginTop: 12 }}>No notifications yet</Text>
            </View>
          ) : (
            items.map((n, i) => {
              const isRead = n.read ?? n.isRead ?? n.is_read;
              const icon = notifIconFor(n.type);
              return (
                <TouchableOpacity
                  key={n.id || n._id || i}
                  style={[s.notifCard, !isRead && { borderColor: colors.accent, borderWidth: 1.5 }]}
                  onPress={() => markRead(n)}
                >
                  <View style={[s.notifIconWrap, { backgroundColor: colors.iconWrap }]}>
                    <Ionicons name={icon.name} size={20} color={icon.color} />
                  </View>
                  <View style={{ flex: 1 }}>
                    <Text style={s.notifTitle}>{n.title || 'Notification'}</Text>
                    {!!n.message && <Text style={s.notifMessage}>{n.message || n.body}</Text>}
                    <Text style={s.notifTime}>{timeAgo(n.createdAt || n.created_at)}</Text>
                  </View>
                  {!isRead && <View style={s.notifDot} />}
                </TouchableOpacity>
              );
            })
          )}
        </ScrollView>
        </KeyboardAvoidingView>
      )}
    </SafeAreaView>
  );
}

// ─── Transaction History Screen ─────────────────────────────────────────────
const TXN_FILTERS = ['All', 'Credit', 'Debit'];

function txnIsCredit(t) {
  const type = (t.type || t.direction || '').toLowerCase();
  if (type) return type.includes('credit') || type.includes('fund') || type === 'in';
  return Number(t.amount) > 0;
}

function txnStatusColor(status) {
  const s = (status || '').toLowerCase();
  if (s.includes('success') || s.includes('complete') || s.includes('paid')) return '#059669';
  if (s.includes('pending')) return '#d97706';
  if (s.includes('fail') || s.includes('reject')) return '#b91c1c';
  return '#6b7280';
}

function txnStatusLabel(status) {
  const s = (status || 'success').toLowerCase();
  if (s === 'pending_review') return 'Under Review';
  if (s === 'success') return 'Successful';
  if (s === 'failed') return 'Failed';
  return s.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

// ─── Branded, image/PDF-shareable receipt (OPay-style) ─────────────────────
// Turns a title + array of "Label: value" strings into a proper visual receipt
// card (logo, big amount, status, date, detail rows) that can be captured as a
// PNG or rendered to a PDF and handed to the OS share sheet — instead of the
// old plain-text-only Share.share() message.

// Splits "Label: value" rows into {label, value} pairs. Rows that are falsy
// (conditionally included with `cond && '...'`) are dropped first.
function parseReceiptRows(rows) {
  return (rows || []).filter(Boolean).map((row) => {
    const idx = row.indexOf(':');
    if (idx === -1) return { label: row, value: '' };
    return { label: row.slice(0, idx).trim(), value: row.slice(idx + 1).trim() };
  });
}

// Pulls the Amount / Status / Date rows out to feature prominently at the top
// of the receipt (like OPay's big green figure), leaving the rest as detail rows.
function splitReceiptHero(parsedRows) {
  let amount = null;
  let status = null;
  let date = null;
  const rest = [];
  parsedRows.forEach((r) => {
    const label = r.label.toLowerCase();
    if (amount === null && label.includes('amount')) { amount = r.value; return; }
    if (status === null && label === 'status') { status = r.value; return; }
    if (date === null && label === 'date') { date = r.value; return; }
    rest.push(r);
  });
  return { amount, status: status || 'Successful', date: date || new Date().toLocaleString(), rest };
}

function buildReceiptHTML({ title, hero, rest }) {
  const rowsHtml = rest.map((r) => `
    <tr>
      <td style="padding:10px 0;color:#888;font-size:14px;">${r.label}</td>
      <td style="padding:10px 0;color:#1a1a1a;font-size:14px;font-weight:600;text-align:right;">${r.value}</td>
    </tr>`).join('');
  return `
  <html>
    <body style="margin:0;padding:24px;font-family:-apple-system,Helvetica,Arial,sans-serif;background:#f4f4f6;">
      <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:18px;padding:28px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;">
          <span style="font-size:20px;font-weight:800;color:#6d28d9;">${APP_NAME}</span>
          <span style="font-size:13px;color:#888;">${title || 'Transaction Receipt'}</span>
        </div>
        <div style="text-align:center;margin-bottom:20px;">
          ${hero.amount ? `<div style="font-size:32px;font-weight:800;color:#059669;">${hero.amount}</div>` : ''}
          <div style="font-size:16px;color:#222;margin-top:4px;">${hero.status}</div>
          <div style="font-size:12px;color:#999;margin-top:4px;">${hero.date}</div>
        </div>
        <table style="width:100%;border-collapse:collapse;border-top:1px solid #eee;margin-top:8px;">
          ${rowsHtml}
        </table>
        <div style="font-size:11px;color:#aaa;text-align:center;margin-top:20px;">
          Powered by ${APP_NAME}. Fast, reliable VTU top-ups you can trust.
        </div>
      </div>
    </body>
  </html>`;
}

// Full-screen modal showing the styled receipt, with "Share as PDF" and a
// plain-text fallback share — mirrors the OPay share-receipt UI, but skips
// react-native-view-shot (a third-party native module prone to version
// mismatches between Snack and the installed Expo Go client). expo-print and
// expo-sharing are official Expo SDK packages, so Snack always resolves a
// version that matches Expo Go, making this the reliable path.
function ReceiptShareModal({ visible, onClose, title, rows, colors }) {
  const viewRef = useRef(null);
  const [busy, setBusy] = useState(false);
  const parsed = parseReceiptRows(rows);
  const hero = splitReceiptHero(parsed);

  const shareAsImage = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const uri = await captureRef(viewRef, { format: 'png', quality: 1, result: 'tmpfile' });
      if (!uri) throw new Error('Could not generate the receipt image.');
      if (await Sharing.isAvailableAsync()) {
        await Sharing.shareAsync(uri, { mimeType: 'image/png', dialogTitle: title || 'Receipt', UTI: 'public.png' });
      } else {
        await Share.share({ url: uri });
      }
    } catch (e) {
      Alert.alert('Could not share image', e.message || String(e));
    } finally {
      setBusy(false);
    }
  };

  const shareAsPDF = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const html = buildReceiptHTML({ title, hero, rest: hero.rest });
      const { uri } = await Print.printToFileAsync({ html, base64: false });
      if (await Sharing.isAvailableAsync()) {
        await Sharing.shareAsync(uri, { mimeType: 'application/pdf', dialogTitle: title || 'Receipt' });
      } else {
        await Share.share({ url: uri });
      }
    } catch (e) {
      Alert.alert('Could not create PDF', e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal visible={visible} animationType="slide" transparent onRequestClose={onClose}>
      <View style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.45)', justifyContent: 'flex-end' }}>
        <View style={{ backgroundColor: colors.background, borderTopLeftRadius: 22, borderTopRightRadius: 22, maxHeight: '90%' }}>
          <View style={{ flexDirection: 'row', alignItems: 'center', padding: 16, borderBottomWidth: 1, borderBottomColor: colors.inputBorder }}>
            <TouchableOpacity onPress={onClose} hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}>
              <Ionicons name="chevron-back" size={22} color={colors.text} />
            </TouchableOpacity>
            <Text style={{ flex: 1, textAlign: 'center', fontSize: 17, fontWeight: '600', color: colors.text, marginRight: 22 }}>
              Share Receipt
            </Text>
          </View>

          <ScrollView contentContainerStyle={{ padding: 20, alignItems: 'center', backgroundColor: colors.body || colors.background }}>
            <View
              ref={viewRef}
              collapsable={false}
              style={{ backgroundColor: '#fff', borderRadius: 18, padding: 24, width: '100%' }}
            >
              <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <Text style={{ fontSize: 20, fontWeight: '800', color: '#6d28d9' }}>{APP_NAME}</Text>
                <Text style={{ fontSize: 13, color: '#888' }}>{title || 'Transaction Receipt'}</Text>
              </View>

              <View style={{ alignItems: 'center', marginBottom: 20 }}>
                {!!hero.amount && (
                  <Text style={{ fontSize: 32, fontWeight: '800', color: '#059669' }}>{hero.amount}</Text>
                )}
                <Text style={{ fontSize: 16, color: '#222', marginTop: 4 }}>{hero.status}</Text>
                <Text style={{ fontSize: 12, color: '#999', marginTop: 4 }}>{hero.date}</Text>
              </View>

              <View style={{ borderTopWidth: 1, borderTopColor: '#eee', paddingTop: 14 }}>
                {hero.rest.map((r, i) => (
                  <View key={i} style={{ flexDirection: 'row', justifyContent: 'space-between', marginBottom: 12 }}>
                    <Text style={{ color: '#888', fontSize: 14 }}>{r.label}</Text>
                    <Text style={{ color: '#1a1a1a', fontSize: 14, fontWeight: '600', maxWidth: '62%', textAlign: 'right' }}>
                      {r.value}
                    </Text>
                  </View>
                ))}
              </View>

              <Text style={{ fontSize: 11, color: '#aaa', marginTop: 18, textAlign: 'center' }}>
                Powered by {APP_NAME}. Fast, reliable VTU top-ups you can trust.
              </Text>
            </View>
          </ScrollView>

          <View style={{ flexDirection: 'row', borderTopWidth: 1, borderTopColor: colors.inputBorder, paddingVertical: 6 }}>
            <TouchableOpacity disabled={busy} onPress={shareAsImage} style={{ flex: 1, alignItems: 'center', paddingVertical: 14 }}>
              <Ionicons name="image-outline" size={20} color={colors.accent} />
              <Text style={{ color: colors.accent, fontWeight: '600', marginTop: 4, fontSize: 13.5 }}>Share as image</Text>
            </TouchableOpacity>
            <View style={{ width: 1, backgroundColor: colors.inputBorder }} />
            <TouchableOpacity disabled={busy} onPress={shareAsPDF} style={{ flex: 1, alignItems: 'center', paddingVertical: 14 }}>
              <Ionicons name="document-text-outline" size={20} color={colors.accent} />
              <Text style={{ color: colors.accent, fontWeight: '600', marginTop: 4, fontSize: 13.5 }}>Share as PDF</Text>
            </TouchableOpacity>
          </View>
          {busy && <ActivityIndicator style={{ marginBottom: 10 }} color={colors.accent} />}
        </View>
      </View>
    </Modal>
  );
}

// Small reusable "Share Receipt" button dropped into each receiptCard. Opens
// the styled ReceiptShareModal instead of firing a plain-text share directly.
function ShareReceiptButton({ title, rows, colors }) {
  const [visible, setVisible] = useState(false);
  return (
    <>
      <TouchableOpacity
        onPress={() => setVisible(true)}
        style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'center', marginTop: 14, padding: 10, borderRadius: 10, borderWidth: 1, borderColor: colors.inputBorder }}
      >
        <Ionicons name="share-outline" size={17} color={colors.accent} />
        <Text style={{ color: colors.accent, fontWeight: '600', marginLeft: 8 }}>Share Receipt</Text>
      </TouchableOpacity>
      <ReceiptShareModal visible={visible} onClose={() => setVisible(false)} title={title} rows={rows} colors={colors} />
    </>
  );
}

// Builds the same "Label: value" row shape from a wallet-transaction object
// (used by the Transactions history list, which doesn't have `rows` handy).
function txnToReceiptRows(t) {
  const isCredit = txnIsCredit(t);
  const amt = Math.abs(Number(t.amount) || 0);
  return [
    `Description: ${t.description || t.narration || (isCredit ? 'Wallet Credit' : 'Wallet Debit')}`,
    `Amount: ${isCredit ? '+' : '-'}₦${amt.toLocaleString()}`,
    `Status: ${txnStatusLabel(t.status)}`,
    `Reference: ${t.reference || t.id || t._id || '—'}`,
    `Date: ${new Date(t.createdAt || t.created_at || Date.now()).toLocaleString()}`,
  ];
}

function TransactionsScreen({ token, onBack }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [txns, setTxns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState('All');
  const [receiptTxn, setReceiptTxn] = useState(null);

  const load = useCallback(async () => {
    try {
      const data = await api('/api/v1/wallet/transactions', { token });
      const list = Array.isArray(data) ? data : data?.transactions || [];
      setTxns(list);
    } catch (e) {
      Alert.alert('Could not load transactions', e.message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const onRefresh = async () => {
    setRefreshing(true);
    await load();
    setRefreshing(false);
  };

  const filtered = txns.filter((t) => {
    if (filter === 'All') return true;
    const isCredit = txnIsCredit(t);
    return filter === 'Credit' ? isCredit : !isCredit;
  });

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Transaction History</Text>
      </View>

      <View style={{ flexDirection: 'row', paddingHorizontal: 20, marginTop: 16, marginBottom: 6 }}>
        {TXN_FILTERS.map((f) => (
          <TouchableOpacity
            key={f}
            onPress={() => setFilter(f)}
            style={[
              s.networkPill,
              { borderColor: colors.accent, backgroundColor: filter === f ? colors.accent : 'transparent' },
            ]}
          >
            <Text style={{ color: filter === f ? '#fff' : colors.text, fontWeight: '600' }}>{f}</Text>
          </TouchableOpacity>
        ))}
      </View>

      {loading ? (
        <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
          <ActivityIndicator color={colors.accent} size="large" />
        </View>
      ) : (
        <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <ScrollView
          style={s.body}
          contentContainerStyle={{ paddingBottom: 40 }}
          refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} colors={[colors.accent]} />}
        >
          {filtered.length === 0 ? (
            <View style={{ alignItems: 'center', marginTop: 60 }}>
              <Ionicons name="receipt-outline" size={48} color={colors.subtext} />
              <Text style={{ color: colors.subtext, marginTop: 12 }}>No transactions yet</Text>
            </View>
          ) : (
            filtered.map((t, i) => {
              const isCredit = txnIsCredit(t);
              const amt = Math.abs(Number(t.amount) || 0);
              return (
                <View key={t.id || t._id || t.reference || i} style={s.txnCard}>
                  <View style={[s.notifIconWrap, { backgroundColor: colors.iconWrap }]}>
                    <Ionicons name={isCredit ? 'arrow-down-circle' : 'arrow-up-circle'} size={22} color={isCredit ? '#059669' : colors.accent} />
                  </View>
                  <View style={{ flex: 1 }}>
                    <Text style={s.notifTitle}>{t.description || t.narration || (isCredit ? 'Wallet Credit' : 'Wallet Debit')}</Text>
                    <Text style={s.notifTime}>{timeAgo(t.createdAt || t.created_at)} · {t.reference || ''}</Text>
                  </View>
                  <View style={{ alignItems: 'flex-end' }}>
                    <Text style={{ fontWeight: 'bold', fontSize: 14.5, color: isCredit ? '#059669' : colors.text }}>
                      {isCredit ? '+' : '-'}₦{amt.toLocaleString()}
                    </Text>
                    <Text style={{ fontSize: 11, color: txnStatusColor(t.status), marginTop: 3, fontWeight: '600', }}>
                      {txnStatusLabel(t.status)}
                    </Text>
                  </View>
                  <TouchableOpacity
                    onPress={() => setReceiptTxn(t)}
                    style={{ marginLeft: 10, padding: 6 }}
                    hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
                  >
                    <Ionicons name="share-outline" size={19} color={colors.subtext} />
                  </TouchableOpacity>
                </View>
              );
            })
          )}
        </ScrollView>
        </KeyboardAvoidingView>
      )}
      <ReceiptShareModal
        visible={!!receiptTxn}
        onClose={() => setReceiptTxn(null)}
        title="Transaction Receipt"
        rows={receiptTxn ? txnToReceiptRows(receiptTxn) : []}
        colors={colors}
      />
    </SafeAreaView>
  );
}

// ─── Referral Screen ─────────────────────────────────────────────────────────
function ReferralScreen({ token, onBack }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    try {
      const d = await api('/api/v1/referrals', { token });
      setData(d);
    } catch (e) {
      Alert.alert('Could not load referral info', e.message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const onRefresh = async () => {
    setRefreshing(true);
    await load();
    setRefreshing(false);
  };

  const copyCode = () => {
    if (!data?.code) return;
    Clipboard.setStringAsync(data.code);
    Alert.alert('Copied', 'Referral code copied');
  };

  const shareCode = async () => {
    if (!data?.code) return;
    try {
      await Share.share({
        message: `Join Gora Data and get great deals on data, airtime & more! Use my referral code ${data.code} when you sign up.${data.link ? `\n${data.link}` : ''}`,
      });
    } catch (e) {}
  };

  if (loading) {
    return (
      <SafeAreaView style={[s.safeArea, { justifyContent: 'center', alignItems: 'center' }]}>
        <ActivityIndicator color={colors.accent} size="large" />
      </SafeAreaView>
    );
  }

  const referrals = data?.referrals || [];

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <TouchableOpacity onPress={onBack} style={{ marginBottom: 10 }}>
          <Ionicons name="arrow-back" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={s.nameText}>Refer & Earn</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView
        style={s.body}
        contentContainerStyle={{ paddingBottom: 40 }}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} colors={[colors.accent]} />}
      >
        <View style={s.vaCard}>
          <Text style={s.vaBank}>Your Referral Code</Text>
          <View style={s.vaAccountRow}>
            <Text style={s.vaAccountNumber}>{data?.code || '—'}</Text>
            <TouchableOpacity onPress={copyCode}>
              <Ionicons name="copy-outline" size={20} color={colors.accent} />
            </TouchableOpacity>
          </View>
        </View>

        <TouchableOpacity style={[s.loginBtn, { flexDirection: 'row', justifyContent: 'center' }]} onPress={shareCode}>
          <Ionicons name="share-social-outline" size={18} color="#fff" style={{ marginRight: 8 }} />
          <Text style={s.loginBtnText}>Share Your Code</Text>
        </TouchableOpacity>

        <View style={s.overviewRow}>
          <View style={[s.overviewCard, { width: '48%' }]}>
            <Text style={s.overviewLabel}>Total Earned</Text>
            <Text style={s.overviewValue}>₦{(data?.totalEarned || 0).toLocaleString()}</Text>
          </View>
          <View style={[s.overviewCard, { width: '48%' }]}>
            <Text style={s.overviewLabel}>Friends Referred</Text>
            <Text style={s.overviewValue}>{data?.referredCount || 0}</Text>
          </View>
        </View>

        <Text style={[s.sectionTitle, { marginTop: 24 }]}>Your Referrals</Text>
        {referrals.length === 0 ? (
          <Text style={{ color: colors.subtext }}>No one has signed up with your code yet. Share it to start earning!</Text>
        ) : (
          referrals.map((r, i) => (
            <View key={r.id || r._id || i} style={s.notifCard}>
              <View style={[s.notifIconWrap, { backgroundColor: colors.iconWrap }]}>
                <Ionicons name="person-outline" size={20} color={colors.accent} />
              </View>
              <View style={{ flex: 1 }}>
                <Text style={s.notifTitle}>{r.name || r.fullName || 'New User'}</Text>
                <Text style={s.notifTime}>Joined {timeAgo(r.joinedAt || r.createdAt)}</Text>
              </View>
              <Text style={{ color: '#059669', fontWeight: 'bold' }}>+₦{(r.bonusEarned || 0).toLocaleString()}</Text>
            </View>
          ))
        )}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Home Screen ────────────────────────────────────────────────────────────
function HomeScreen({ user, token, onOpenService, unreadCount, onUserRefresh }) {
  const { colors, dark, toggle } = useTheme();
  const s = makeStyles(colors);
  const [greeting, setGreeting] = useState('');
  const [isDay, setIsDay] = useState(true);
  const [wallet, setWallet] = useState(null);
  const [balanceHidden, setBalanceHidden] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [fundModalVisible, setFundModalVisible] = useState(false);
  const [withdrawModalVisible, setWithdrawModalVisible] = useState(false);
  const [transferModalVisible, setTransferModalVisible] = useState(false);
  const [recentTxns, setRecentTxns] = useState([]);
  const [txnsLoading, setTxnsLoading] = useState(true);
  const [virtualAccount, setVirtualAccount] = useState(null);
  const [announcement, setAnnouncement] = useState(null);
  const [announcementDismissed, setAnnouncementDismissed] = useState(false);

  const loadAnnouncement = useCallback(async () => {
    try {
      const data = await api('/api/v1/announcements/active', { token });
      setAnnouncement(data || null);
    } catch (e) {}
  }, [token]);

  useEffect(() => { loadAnnouncement(); }, [loadAnnouncement]);

  // Dismissing hides it for this specific announcement only — a new one (different id)
  // will show again even if the user dismissed a previous one.
  useEffect(() => {
    if (!announcement) return;
    AsyncStorage.getItem('dismissedAnnouncementId').then((v) => {
      setAnnouncementDismissed(v === announcement.id);
    });
  }, [announcement]);

  const dismissAnnouncement = () => {
    if (!announcement) return;
    setAnnouncementDismissed(true);
    AsyncStorage.setItem('dismissedAnnouncementId', announcement.id);
  };

  useEffect(() => {
    const hour = new Date().getHours();
    if (hour < 12) { setGreeting('Good Morning'); setIsDay(true); }
    else if (hour < 17) { setGreeting('Good Afternoon'); setIsDay(true); }
    else { setGreeting('Good Evening'); setIsDay(false); }
  }, []);

  const loadWallet = useCallback(async () => {
    try {
      const data = await api('/api/v1/wallet', { token });
      setWallet(data);
    } catch (e) {}
  }, [token]);

  const loadVirtualAccount = useCallback(async () => {
    try {
      const data = await api('/api/v1/wallet/virtual-account', { token });
      if (data) setVirtualAccount(data);
    } catch (e) {}
  }, [token]);

  useEffect(() => { loadVirtualAccount(); }, [loadVirtualAccount]);

  const copyAccountNumber = () => {
    Clipboard.setStringAsync(virtualAccount.accountNumber);
    Alert.alert('Copied', 'Account number copied');
  };

  const loadRecentTxns = useCallback(async () => {
    try {
      const data = await api('/api/v1/wallet/transactions', { token });
      const list = Array.isArray(data) ? data : data?.transactions || [];
      setRecentTxns(list.slice(0, 5));
    } catch (e) {
      // Non-critical for the home screen — the full history screen will surface the error.
    } finally {
      setTxnsLoading(false);
    }
  }, [token]);

  useEffect(() => { loadWallet(); }, [loadWallet]);
  useEffect(() => { loadRecentTxns(); }, [loadRecentTxns]);
  // Remember the user's choice across app opens — if they hid it, it should stay hidden
  // next time, not reset and flash the real number before they can react.
  useEffect(() => {
    AsyncStorage.getItem('balanceHidden').then((v) => { if (v === 'true') setBalanceHidden(true); });
  }, []);
  const toggleBalanceHidden = () => {
    setBalanceHidden((prev) => {
      const next = !prev;
      AsyncStorage.setItem('balanceHidden', next ? 'true' : 'false');
      return next;
    });
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await Promise.all([loadWallet(), loadRecentTxns(), loadAnnouncement()]);
    setRefreshing(false);
  };

  const services = [
    { name: 'Data', icon: 'wifi', key: 'data' },
    { name: 'Airtime', icon: 'call', key: 'airtime' },
    { name: 'Electricity', icon: 'flash', key: 'electric' },
    { name: 'Cable TV', icon: 'tv', key: 'cable' },
    { name: 'ISP', icon: 'globe', key: 'isp' },
    { name: 'Social Boost', icon: 'trending-up', key: 'social' },
    { name: 'Bulk SMS', icon: 'chatbox-ellipses', key: 'sms' },
    { name: 'Exam Pins', icon: 'school', key: 'exam' },
    { name: 'JAMB e-PIN', icon: 'library', key: 'jamb' },
    { name: 'Recharge Pin', icon: 'card', key: 'recharge' },
    { name: 'Airtime to Cash', icon: 'cash', key: 'a2c' },
    { name: 'Betting', icon: 'football', key: 'betting' },
    { name: 'Refer & Earn', icon: 'people', key: 'referral' },
  ];

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={s.header}>
        <View style={s.headerTop}>
          <View>
            <View style={s.greetingRow}>
              <Ionicons name={isDay ? 'sunny' : 'moon'} size={20} color="#fde68a" />
              <Text style={s.greetingText}>{greeting}</Text>
            </View>
            <Text style={s.nameText}>{user?.full_name || 'Welcome back'}</Text>
          </View>
          <View style={{ flexDirection: 'row' }}>
            <TouchableOpacity style={[s.notifBtn, { marginRight: 10 }]} onPress={toggle}>
              <Ionicons name={dark ? 'sunny-outline' : 'moon-outline'} size={20} color="#fff" />
            </TouchableOpacity>
            <TouchableOpacity style={[s.notifBtn, { marginRight: 10 }]} onPress={() => onOpenService('settings')}>
              <Ionicons name="person-outline" size={20} color="#fff" />
            </TouchableOpacity>
            <TouchableOpacity style={s.notifBtn} onPress={() => onOpenService('notifications')}>
              <Ionicons name="notifications-outline" size={22} color="#fff" />
              {unreadCount > 0 && (
                <View style={s.notifBadge}>
                  <Text style={s.notifBadgeText}>{unreadCount > 9 ? '9+' : unreadCount}</Text>
                </View>
              )}
            </TouchableOpacity>
          </View>
        </View>

        <View style={s.walletCard}>
          <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }}>
            <Text style={s.walletLabel}>Wallet Balance</Text>
            <TouchableOpacity onPress={toggleBalanceHidden} hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}>
              <Ionicons name={balanceHidden ? 'eye-off-outline' : 'eye-outline'} size={18} color="#e0e7ff" />
            </TouchableOpacity>
          </View>
          <Text style={s.walletAmount}>
            {balanceHidden
              ? '₦••••••'
              : `₦${wallet ? parseFloat(wallet.balance).toLocaleString(undefined, { minimumFractionDigits: 2 }) : '0.00'}`}
          </Text>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginTop: 14 }}>
            <TouchableOpacity style={s.fundBtn} onPress={() => setFundModalVisible(true)}>
              <Text style={s.fundBtnText}>+ Fund Wallet</Text>
            </TouchableOpacity>
            <TouchableOpacity style={[s.fundBtn, { marginLeft: 10, backgroundColor: 'rgba(255,255,255,0.14)' }]} onPress={() => setWithdrawModalVisible(true)}>
              <Text style={s.fundBtnText}>Withdraw</Text>
            </TouchableOpacity>
            <TouchableOpacity style={[s.fundBtn, { marginLeft: 10, backgroundColor: 'rgba(255,255,255,0.14)' }]} onPress={() => setTransferModalVisible(true)}>
              <Text style={s.fundBtnText}>Send</Text>
            </TouchableOpacity>
          </View>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginTop: 8 }}>
            <TouchableOpacity onPress={() => onOpenService('transactions')}>
              <Text style={{ color: '#e0e7ff', fontWeight: '600', fontSize: 13 }}>View History →</Text>
            </TouchableOpacity>
          </View>

          {virtualAccount && (
            <TouchableOpacity onPress={copyAccountNumber} style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: 'rgba(255,255,255,0.12)', borderRadius: 12, paddingVertical: 10, paddingHorizontal: 14, marginTop: 14 }}>
              <View>
                <Text style={{ color: '#e0e7ff', fontSize: 11 }}>{virtualAccount.bankName} — tap to copy</Text>
                <Text style={{ color: '#fff', fontSize: 15, fontWeight: '700', letterSpacing: 0.5, marginTop: 2 }}>{virtualAccount.accountNumber}</Text>
              </View>
              <Ionicons name="copy-outline" size={18} color="#e0e7ff" />
            </TouchableOpacity>
          )}
        </View>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView
        style={s.body}
        contentContainerStyle={{ paddingBottom: 40 }}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} colors={[colors.accent]} />}
      >
        {announcement && !announcementDismissed && (
          <View
            style={{
              flexDirection: 'row',
              alignItems: 'flex-start',
              backgroundColor:
                announcement.type === 'issue' ? '#fee2e2' : announcement.type === 'warning' ? '#fef3c7' : colors.iconWrap,
              borderRadius: 12,
              padding: 12,
              marginBottom: 16,
              borderWidth: 1,
              borderColor:
                announcement.type === 'issue' ? '#fca5a5' : announcement.type === 'warning' ? '#fde68a' : colors.inputBorder,
            }}
          >
            <Ionicons
              name={announcement.type === 'issue' ? 'alert-circle' : announcement.type === 'warning' ? 'warning' : 'information-circle'}
              size={20}
              color={announcement.type === 'issue' ? '#b91c1c' : announcement.type === 'warning' ? '#92400e' : colors.accent}
              style={{ marginRight: 10, marginTop: 1 }}
            />
            <Text
              style={{
                flex: 1,
                fontSize: 13,
                lineHeight: 18,
                color: announcement.type === 'issue' ? '#7f1d1d' : announcement.type === 'warning' ? '#78350f' : colors.text,
              }}
            >
              {announcement.message}
            </Text>
            <TouchableOpacity onPress={dismissAnnouncement} hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }} style={{ marginLeft: 8 }}>
              <Ionicons name="close" size={16} color={announcement.type === 'issue' ? '#b91c1c' : announcement.type === 'warning' ? '#92400e' : colors.subtext} />
            </TouchableOpacity>
          </View>
        )}

        <Text style={s.sectionTitle}>Services</Text>
        <View style={s.grid}>
          {services.map((sv, i) => (
            <TouchableOpacity
              key={i}
              style={s.serviceCard}
              onPress={() => {
                if (sv.key === 'data') onOpenService('data');
                else if (sv.key === 'airtime') onOpenService('airtime');
                else if (sv.key === 'electric') onOpenService('electric');
                else if (sv.key === 'cable') onOpenService('cable');
                else if (sv.key === 'isp') onOpenService('isp');
                else if (sv.key === 'social') onOpenService('social');
                else if (sv.key === 'sms') onOpenService('sms');
                else if (sv.key === 'exam') onOpenService('exam');
                else if (sv.key === 'jamb') onOpenService('jamb');
                else if (sv.key === 'recharge') onOpenService('recharge');
                else if (sv.key === 'a2c') onOpenService('a2c');
                else if (sv.key === 'betting') onOpenService('betting');
                else if (sv.key === 'referral') onOpenService('referral');
                else Alert.alert('Coming soon', `${sv.name} purchase screen is not built yet.`);
              }}
            >
              <View style={s.serviceIconWrap}>
                <Ionicons name={sv.icon} size={24} color={colors.accent} />
              </View>
              <Text style={s.serviceLabel}>{sv.name}</Text>
            </TouchableOpacity>
          ))}
        </View>

        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginTop: 8 }}>
          <Text style={s.sectionTitle}>Recent Transactions</Text>
          <TouchableOpacity onPress={() => onOpenService('transactions')}>
            <Text style={{ color: colors.accent, fontWeight: '600', fontSize: 13 }}>See All →</Text>
          </TouchableOpacity>
        </View>

        {txnsLoading ? (
          <ActivityIndicator color={colors.accent} style={{ marginTop: 10 }} />
        ) : recentTxns.length === 0 ? (
          <View style={{ alignItems: 'center', marginTop: 10, marginBottom: 10 }}>
            <Ionicons name="receipt-outline" size={40} color={colors.subtext} />
            <Text style={{ color: colors.subtext, marginTop: 10 }}>No transactions yet</Text>
          </View>
        ) : (
          recentTxns.map((t, i) => {
            const isCredit = txnIsCredit(t);
            const amt = Math.abs(Number(t.amount) || 0);
            return (
              <View key={t.id || t._id || t.reference || i} style={s.txnCard}>
                <View style={[s.notifIconWrap, { backgroundColor: colors.iconWrap }]}>
                  <Ionicons name={isCredit ? 'arrow-down-circle' : 'arrow-up-circle'} size={22} color={isCredit ? '#059669' : colors.accent} />
                </View>
                <View style={{ flex: 1 }}>
                  <Text style={s.notifTitle}>{t.description || t.narration || (isCredit ? 'Wallet Credit' : 'Wallet Debit')}</Text>
                  <Text style={s.notifTime}>{timeAgo(t.createdAt || t.created_at)}</Text>
                </View>
                <View style={{ alignItems: 'flex-end' }}>
                  <Text style={{ fontWeight: 'bold', fontSize: 14.5, color: isCredit ? '#059669' : colors.text }}>
                    {isCredit ? '+' : '-'}₦{amt.toLocaleString()}
                  </Text>
                  <Text style={{ fontSize: 11, color: txnStatusColor(t.status), marginTop: 3, fontWeight: '600', }}>
                    {txnStatusLabel(t.status)}
                  </Text>
                </View>
              </View>
            );
          })
        )}
      </ScrollView>
      </KeyboardAvoidingView>

      <FundWalletModal visible={fundModalVisible} onClose={() => setFundModalVisible(false)} token={token} user={user} onFunded={() => { loadWallet(); loadVirtualAccount(); }} onUserRefresh={onUserRefresh} />
      <WithdrawModal visible={withdrawModalVisible} onClose={() => setWithdrawModalVisible(false)} token={token} user={user} wallet={wallet} onWithdrawn={loadWallet} />
      <TransferModal visible={transferModalVisible} onClose={() => setTransferModalVisible(false)} token={token} user={user} wallet={wallet} onTransferred={loadWallet} />
    </SafeAreaView>
  );
}

// ─── Admin Tool Header (shared back-nav header for admin sub-screens) ─────────
function AdminToolHeader({ title, subtitle, onBack, colors }) {
  return (
    <View style={{ backgroundColor: colors.headerBg, paddingHorizontal: 20, paddingTop: 20, paddingBottom: 18, borderBottomLeftRadius: 24, borderBottomRightRadius: 24, flexDirection: 'row', alignItems: 'center' }}>
      <TouchableOpacity onPress={onBack} style={{ backgroundColor: 'rgba(255,255,255,0.15)', padding: 10, borderRadius: 12, marginRight: 12 }}>
        <Ionicons name="arrow-back" size={20} color="#fff" />
      </TouchableOpacity>
      <View style={{ flex: 1 }}>
        <Text style={{ color: '#fff', fontSize: 19, fontWeight: 'bold' }}>{title}</Text>
        {subtitle ? <Text style={{ color: '#e0e7ff', fontSize: 12.5, marginTop: 2 }}>{subtitle}</Text> : null}
      </View>
    </View>
  );
}

const adminCardStyle = (colors) => ({ backgroundColor: colors.card, borderRadius: 14, padding: 14, marginBottom: 10, borderWidth: 1, borderColor: colors.inputBorder });
const adminInputStyle = (colors) => ({ backgroundColor: colors.inputBg, borderRadius: 12, paddingHorizontal: 14, paddingVertical: 12, fontSize: 14, marginBottom: 10, borderWidth: 1, borderColor: colors.inputBorder, color: colors.text });
const adminPillStyle = (colors, active) => ({ borderWidth: 2, borderColor: colors.accent, borderRadius: 10, paddingVertical: 8, paddingHorizontal: 14, marginRight: 8, marginBottom: 8, backgroundColor: active ? colors.accent : 'transparent' });
const adminBtnStyle = (colors, tone = 'default') => ({
  borderRadius: 12, paddingVertical: 13, alignItems: 'center', marginTop: 6,
  backgroundColor: tone === 'danger' ? '#dc2626' : tone === 'success' ? '#059669' : colors.headerBg,
});

// ─── Admin: Service Controls (Kill-Switch) ─────────────────────────────────────
function AdminServiceControlsScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [controls, setControls] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyKey, setBusyKey] = useState(null);

  const load = useCallback(async () => {
    try {
      const data = await api('/api/v1/admin/service-controls', { token });
      setControls(data);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const toggle = async (row) => {
    const key = `${row.network}:${row.service}`;
    setBusyKey(key);
    try {
      await api('/api/v1/admin/service-controls/toggle', { method: 'POST', token, body: { network: row.network, service: row.service, enabled: !row.enabled } });
      setControls((prev) => prev.map((c) => (c.network === row.network && c.service === row.service ? { ...c, enabled: !c.enabled } : c)));
    } catch (e) { Alert.alert('Failed', e.message); }
    setBusyKey(null);
  };

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Service Controls" subtitle="One-tap kill-switch per network & service" onBack={onBack} colors={colors} />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 16 }} contentContainerStyle={{ paddingBottom: 40 }}>
        {loading && <ActivityIndicator color={colors.accent} style={{ marginTop: 20 }} />}
        {!loading && controls.length === 0 && <Text style={{ color: colors.subtext }}>No service control rows found.</Text>}
        {controls.map((c, i) => {
          const key = `${c.network}:${c.service}`;
          return (
            <View key={i} style={[adminCardStyle(colors), { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }]}>
              <View>
                <Text style={{ fontSize: 15, fontWeight: 'bold', color: colors.text }}>{c.network}</Text>
                <Text style={{ fontSize: 12.5, color: colors.subtext, marginTop: 2, textTransform: 'capitalize' }}>{c.service}</Text>
              </View>
              <TouchableOpacity
                disabled={busyKey === key}
                onPress={() => toggle(c)}
                style={{ width: 52, height: 30, borderRadius: 15, backgroundColor: c.enabled ? '#059669' : '#dc2626', justifyContent: 'center', paddingHorizontal: 3 }}
              >
                {busyKey === key ? (
                  <ActivityIndicator size="small" color="#fff" />
                ) : (
                  <View style={{ width: 24, height: 24, borderRadius: 12, backgroundColor: '#fff', alignSelf: c.enabled ? 'flex-end' : 'flex-start' }} />
                )}
              </TouchableOpacity>
            </View>
          );
        })}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Granular Provider Routing ───────────────────────────────────────────
const ADMIN_NETWORKS = ['MTN', 'Glo', 'Airtel', '9mobile'];
const ADMIN_SERVICES = ['data', 'airtime', 'electric', 'cable', 'isp', 'exam', 'jamb', 'recharge_pin', 'betting'];
// These services aren't tied to a mobile network (they route by biller/provider directly), so the
// backend always looks them up under network 'ALL' — recharge_pin can be per-network (buying MTN/Glo/
// etc pins) so it's NOT in this list. Keep this in sync with the getProviderForRoute('ALL', ...) calls
// in server.js for electric/cable/isp/exam/jamb/betting.
const NETWORK_LESS_SERVICES = ['electric', 'cable', 'isp', 'exam', 'jamb', 'betting'];
// Pricing/margin endpoints key electricity as 'electricity' (not 'electric' like provider routing/
// kill-switch do) and also support 'social' — kept as a separate list so margins can be set
// correctly for both without breaking the Provider Routing screen above, which needs 'electric'.
const ADMIN_PRICING_SERVICES = ['data', 'airtime', 'electricity', 'cable', 'isp', 'exam', 'jamb', 'recharge_pin', 'betting', 'social', 'sms', 'withdrawal'];
const ADMIN_PROVIDERS = ['bigisub', 'klubconnect'];

function AdminProviderRoutingScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [routes, setRoutes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [network, setNetwork] = useState('MTN');
  const [service, setService] = useState('data');
  const [saving, setSaving] = useState(false);
  const isNetworkLess = NETWORK_LESS_SERVICES.includes(service);

  const load = useCallback(async () => {
    try {
      const data = await api('/api/v1/admin/provider-routes', { token });
      setRoutes(data);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const currentRoute = routes.find((r) => r.network === (isNetworkLess ? 'ALL' : network) && r.service === service);

  const setRoute = async (provider) => {
    setSaving(true);
    try {
      await api('/api/v1/admin/provider-routes', { method: 'POST', token, body: { network: isNetworkLess ? 'ALL' : network, service, provider } });
      await load();
    } catch (e) { Alert.alert('Failed', e.message); }
    setSaving(false);
  };

  const clearRoute = async () => {
    setSaving(true);
    try {
      await api(`/api/v1/admin/provider-routes/${isNetworkLess ? 'ALL' : network}/${service}`, { method: 'DELETE', token });
      await load();
    } catch (e) { Alert.alert('Failed', e.message); }
    setSaving(false);
  };

  // Deletes a route using its OWN saved network/service values directly, instead of
  // relying on the currently-selected pills above. This matters because some existing
  // overrides were saved with a specific network (e.g. 'MTN') for a service that is
  // now classified as network-less (isNetworkLess), so the pill-based lookup above can
  // never match them — this lets any row in "Active Overrides" be cleared regardless.
  const clearSpecificRoute = async (routeNetwork, routeService) => {
    setSaving(true);
    try {
      await api(`/api/v1/admin/provider-routes/${routeNetwork}/${routeService}`, { method: 'DELETE', token });
      await load();
    } catch (e) { Alert.alert('Failed', e.message); }
    setSaving(false);
  };

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Provider Routing" subtitle="Send specific network + service combos to a chosen provider" onBack={onBack} colors={colors} />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 16 }} contentContainerStyle={{ paddingBottom: 40 }}>
        {!isNetworkLess && (
          <>
            <Text style={{ fontSize: 13, fontWeight: '700', color: colors.text, marginBottom: 8 }}>Network</Text>
            <View style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
              {ADMIN_NETWORKS.map((n) => (
                <TouchableOpacity key={n} style={adminPillStyle(colors, network === n)} onPress={() => setNetwork(n)}>
                  <Text style={{ color: network === n ? '#fff' : colors.text, fontWeight: '600', fontSize: 12.5 }}>{n}</Text>
                </TouchableOpacity>
              ))}
            </View>
          </>
        )}
        <Text style={{ fontSize: 13, fontWeight: '700', color: colors.text, marginBottom: 8, marginTop: 10 }}>Service</Text>
        <View style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
          {ADMIN_SERVICES.map((sv) => (
            <TouchableOpacity key={sv} style={adminPillStyle(colors, service === sv)} onPress={() => setService(sv)}>
              <Text style={{ color: service === sv ? '#fff' : colors.text, fontWeight: '600', fontSize: 12.5, textTransform: 'capitalize' }}>{sv.replace('_', ' ')}</Text>
            </TouchableOpacity>
          ))}
        </View>
        {isNetworkLess && (
          <Text style={{ fontSize: 11.5, color: colors.subtext, marginTop: 8 }}>
            {service.replace('_', ' ')} routes by biller, not by mobile network — this override applies to all of them.
          </Text>
        )}

        <View style={[adminCardStyle(colors), { marginTop: 16 }]}>
          <Text style={{ fontSize: 12.5, color: colors.subtext, marginBottom: 10 }}>
            {currentRoute ? `${isNetworkLess ? '' : network + ' '}${service.replace('_', ' ')} is pinned to ${currentRoute.provider}.` : `${isNetworkLess ? '' : network + ' '}${service.replace('_', ' ')} is using the default active provider (no override).`}
          </Text>
          <View style={{ flexDirection: 'row' }}>
            {ADMIN_PROVIDERS.map((p) => (
              <TouchableOpacity
                key={p}
                disabled={saving}
                style={[adminPillStyle(colors, currentRoute?.provider === p), { marginRight: 10 }]}
                onPress={() => setRoute(p)}
              >
                <Text style={{ color: currentRoute?.provider === p ? '#fff' : colors.text, fontWeight: '700', fontSize: 12.5 }}>{p === 'bigisub' ? 'Bigisub' : 'KlubConnect'}</Text>
              </TouchableOpacity>
            ))}
            {saving && <ActivityIndicator color={colors.accent} style={{ marginLeft: 6 }} />}
          </View>
          {currentRoute && (
            <TouchableOpacity onPress={clearRoute} disabled={saving} style={{ marginTop: 10 }}>
              <Text style={{ color: '#b91c1c', fontWeight: '600', fontSize: 12.5 }}>Clear override (use default)</Text>
            </TouchableOpacity>
          )}
        </View>

        <Text style={[{ fontSize: 15, fontWeight: 'bold', color: colors.text, marginTop: 24, marginBottom: 10 }]}>Active Overrides ({routes.length})</Text>
        {loading && <ActivityIndicator color={colors.accent} />}
        {!loading && routes.length === 0 && <Text style={{ color: colors.subtext }}>No overrides set — everything uses the default provider.</Text>}
        {routes.map((r, i) => (
          <View key={i} style={[adminCardStyle(colors), { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }]}>
            <Text style={{ color: colors.text, fontWeight: '600', fontSize: 13 }}>{r.network === 'ALL' ? '' : `${r.network} · `}{r.service.replace('_', ' ')}</Text>
            <View style={{ flexDirection: 'row', alignItems: 'center' }}>
              <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 12.5, marginRight: 14 }}>{r.provider}</Text>
              <TouchableOpacity disabled={saving} onPress={() => clearSpecificRoute(r.network, r.service)}>
                <Ionicons name="trash-outline" size={18} color="#b91c1c" />
              </TouchableOpacity>
            </View>
          </View>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Manual Wallet Adjustment ─────────────────────────────────────────
function AdminWalletAdjustScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [userId, setUserId] = useState('');
  const [customerQuery, setCustomerQuery] = useState('');
  const [customerResults, setCustomerResults] = useState([]);
  const [searchingCustomer, setSearchingCustomer] = useState(false);
  const [selectedCustomer, setSelectedCustomer] = useState(null);
  const [amount, setAmount] = useState('');
  const [type, setType] = useState('credit');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [history, setHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(true);

  const loadHistory = useCallback(async () => {
    try {
      const data = await api('/api/v1/admin/wallet/adjustments', { token });
      setHistory(data);
    } catch (e) { /* silent */ }
    setLoadingHistory(false);
  }, [token]);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  const searchCustomer = async () => {
    if (!customerQuery.trim()) return;
    setSearchingCustomer(true);
    setSelectedCustomer(null);
    setUserId('');
    try {
      const data = await api(`/api/v1/admin/users/search?q=${encodeURIComponent(customerQuery.trim())}`, { token });
      setCustomerResults(Array.isArray(data) ? data : []);
    } catch (e) { Alert.alert('Search failed', e.message); }
    setSearchingCustomer(false);
  };

  const pickCustomer = (u) => {
    setSelectedCustomer(u);
    setUserId(u.id);
    setCustomerResults([]);
    setCustomerQuery('');
  };

  const submit = async () => {
    if (!userId.trim() || !amount || !reason.trim()) {
      Alert.alert('Missing info', 'Customer, amount and reason are all required — the reason is logged for audit.');
      return;
    }
    setSubmitting(true);
    try {
      await api('/api/v1/admin/wallet/adjust', { method: 'POST', token, body: { userId: userId.trim(), amount: Number(amount), type, reason: reason.trim() } });
      Alert.alert('Done', `Wallet ${type === 'credit' ? 'credited' : 'debited'} successfully.`);
      setAmount(''); setReason(''); setSelectedCustomer(null); setUserId('');
      loadHistory();
    } catch (e) { Alert.alert('Failed', e.message); }
    setSubmitting(false);
  };

  const naira = (n) => `₦${(n || 0).toLocaleString()}`;

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Wallet Adjustment" subtitle="Manually credit or debit a user — every action is logged with a reason" onBack={onBack} colors={colors} />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 16 }} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={{ fontSize: 11, fontWeight: '700', color: colors.subtext, marginBottom: 6 }}>FIND CUSTOMER</Text>
        {selectedCustomer ? (
          <View style={[adminCardStyle(colors), { marginBottom: 12 }]}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
              <View style={{ flex: 1 }}>
                <Text style={{ fontWeight: 'bold', color: colors.text, fontSize: 14.5 }}>{selectedCustomer.full_name || 'Unnamed'}</Text>
                <Text style={{ color: colors.subtext, fontSize: 12.5, marginTop: 2 }}>{selectedCustomer.phone} {selectedCustomer.email ? `· ${selectedCustomer.email}` : ''}</Text>
              </View>
              <TouchableOpacity onPress={() => { setSelectedCustomer(null); setUserId(''); }}>
                <Ionicons name="close-circle" size={22} color={colors.subtext} />
              </TouchableOpacity>
            </View>
          </View>
        ) : (
          <>
            <View style={{ flexDirection: 'row', marginBottom: customerResults.length ? 8 : 12 }}>
              <TextInput
                style={[adminInputStyle(colors), { flex: 1, marginRight: 8, marginBottom: 0 }]}
                placeholder="Search by phone, email or name"
                placeholderTextColor={colors.subtext}
                value={customerQuery}
                onChangeText={setCustomerQuery}
                onSubmitEditing={searchCustomer}
                autoCapitalize="none"
              />
              <TouchableOpacity style={{ backgroundColor: colors.headerBg, borderRadius: 12, width: 48, justifyContent: 'center', alignItems: 'center' }} onPress={searchCustomer} disabled={searchingCustomer}>
                {searchingCustomer ? <ActivityIndicator color="#fff" size="small" /> : <Ionicons name="search" size={20} color="#fff" />}
              </TouchableOpacity>
            </View>
            {customerResults.map((u, i) => (
              <TouchableOpacity key={i} style={[adminCardStyle(colors), { marginBottom: 8 }]} onPress={() => pickCustomer(u)}>
                <Text style={{ fontWeight: 'bold', color: colors.text, fontSize: 14 }}>{u.full_name || 'Unnamed'}</Text>
                <Text style={{ color: colors.subtext, fontSize: 12.5, marginTop: 2 }}>{u.phone} {u.email ? `· ${u.email}` : ''}</Text>
              </TouchableOpacity>
            ))}
          </>
        )}

        <TextInput style={adminInputStyle(colors)} placeholder="Amount (₦)" placeholderTextColor={colors.subtext} value={amount} onChangeText={setAmount} keyboardType="numeric" />
        <View style={{ flexDirection: 'row', marginBottom: 10 }}>
          <TouchableOpacity style={[adminPillStyle(colors, type === 'credit'), { flex: 1, alignItems: 'center' }]} onPress={() => setType('credit')}>
            <Text style={{ color: type === 'credit' ? '#fff' : colors.text, fontWeight: '700' }}>Credit (+)</Text>
          </TouchableOpacity>
          <TouchableOpacity style={[adminPillStyle(colors, type === 'debit'), { flex: 1, alignItems: 'center' }]} onPress={() => setType('debit')}>
            <Text style={{ color: type === 'debit' ? '#fff' : colors.text, fontWeight: '700' }}>Debit (-)</Text>
          </TouchableOpacity>
        </View>
        <TextInput style={[adminInputStyle(colors), { height: 80, textAlignVertical: 'top' }]} placeholder="Reason (required — shown in the audit log)" placeholderTextColor={colors.subtext} value={reason} onChangeText={setReason} multiline />
        <TouchableOpacity style={adminBtnStyle(colors, type === 'debit' ? 'danger' : 'success')} onPress={submit} disabled={submitting}>
          {submitting ? <ActivityIndicator color="#fff" /> : <Text style={{ color: '#fff', fontWeight: 'bold', fontSize: 15 }}>{type === 'credit' ? 'Credit Wallet' : 'Debit Wallet'}</Text>}
        </TouchableOpacity>

        <Text style={{ fontSize: 15, fontWeight: 'bold', color: colors.text, marginTop: 28, marginBottom: 10 }}>Recent Adjustments</Text>
        {loadingHistory && <ActivityIndicator color={colors.accent} />}
        {!loadingHistory && history.length === 0 && <Text style={{ color: colors.subtext }}>No manual adjustments yet.</Text>}
        {history.map((h, i) => (
          <View key={i} style={adminCardStyle(colors)}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              <Text style={{ color: h.type === 'credit' ? '#059669' : '#b91c1c', fontWeight: '700', fontSize: 14 }}>{h.type === 'credit' ? '+' : '-'}{naira(h.amount)}</Text>
              <Text style={{ color: colors.subtext, fontSize: 11 }}>{new Date(h.created_at).toLocaleString()}</Text>
            </View>
            <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 4 }}>{h.description}</Text>
          </View>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: User Management (search, freeze, block, tier) ──────────────────────
function AdminUsersScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [q, setQ] = useState('');
  const [results, setResults] = useState([]);
  const [searching, setSearching] = useState(false);
  const [busyId, setBusyId] = useState(null);
  const [loadingList, setLoadingList] = useState(true);
  const [messageUser, setMessageUser] = useState(null); // user object being messaged, or null
  const [msgTitle, setMsgTitle] = useState('');
  const [msgBody, setMsgBody] = useState('');
  const [sendingMsg, setSendingMsg] = useState(false);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkTitle, setBulkTitle] = useState('');
  const [bulkBody, setBulkBody] = useState('');
  const [bulkRole, setBulkRole] = useState(null);
  const [bulkTier, setBulkTier] = useState(null);
  const [bulkActive, setBulkActive] = useState(null);
  const [bulkFrozen, setBulkFrozen] = useState(null);
  const [sendingBulk, setSendingBulk] = useState(false);

  // Show everyone by default (newest first), not just search results.
  const loadAllUsers = useCallback(async () => {
    setLoadingList(true);
    try {
      const data = await api('/api/v1/admin/users?limit=50', { token });
      setResults(data.users || []);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoadingList(false);
  }, [token]);

  useEffect(() => { loadAllUsers(); }, [loadAllUsers]);

  const search = async () => {
    if (!q.trim()) return loadAllUsers();
    setSearching(true);
    try {
      const data = await api(`/api/v1/admin/users/search?q=${encodeURIComponent(q.trim())}`, { token });
      setResults(data);
    } catch (e) { Alert.alert('Error', e.message); }
    setSearching(false);
  };

  const openMessage = (u) => { setMessageUser(u); setMsgTitle(''); setMsgBody(''); };
  const closeMessage = () => { setMessageUser(null); setMsgTitle(''); setMsgBody(''); };

  const openBulk = () => { setBulkOpen(true); setBulkTitle(''); setBulkBody(''); setBulkRole(null); setBulkTier(null); setBulkActive(null); setBulkFrozen(null); };
  const closeBulk = () => setBulkOpen(false);

  const sendBulk = async () => {
    if (!bulkBody.trim()) return Alert.alert('Message required', 'Type something to send.');
    setSendingBulk(true);
    try {
      const data = await api('/api/v1/admin/users/message-bulk', {
        method: 'POST',
        token,
        body: {
          title: bulkTitle.trim() || undefined,
          body: bulkBody.trim(),
          role: bulkRole || undefined,
          tier: bulkTier || undefined,
          active: bulkActive === null ? undefined : bulkActive,
          frozen: bulkFrozen === null ? undefined : bulkFrozen,
        },
      });
      Alert.alert('Sent', data?.message || `Message sent to ${data?.sent ?? 0} user(s)`);
      closeBulk();
    } catch (e) { Alert.alert('Failed', e.message); }
    setSendingBulk(false);
  };

  const sendMessage = async () => {
    if (!msgBody.trim()) return Alert.alert('Message required', 'Type something to send.');
    setSendingMsg(true);
    try {
      await api(`/api/v1/admin/users/${messageUser.id}/message`, { method: 'POST', token, body: { title: msgTitle.trim() || undefined, body: msgBody.trim() } });
      Alert.alert('Sent', `Message sent to ${messageUser.full_name || messageUser.phone}`);
      closeMessage();
    } catch (e) { Alert.alert('Failed', e.message); }
    setSendingMsg(false);
  };

  const toggleFreeze = async (u) => {
    setBusyId(u.id);
    try {
      await api(`/api/v1/admin/users/${u.id}/freeze`, { method: 'POST', token, body: { frozen: !u.is_frozen, reason: 'Toggled from admin dashboard' } });
      setResults((prev) => prev.map((r) => (r.id === u.id ? { ...r, is_frozen: !r.is_frozen } : r)));
    } catch (e) { Alert.alert('Failed', e.message); }
    setBusyId(null);
  };

  const toggleBlock = async (u) => {
    const blocking = u.is_active;
    Alert.alert(
      blocking ? 'Block this user?' : 'Unblock this user?',
      blocking ? 'They will not be able to log in until unblocked.' : 'They will be able to log in again.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Confirm',
          style: blocking ? 'destructive' : 'default',
          onPress: async () => {
            setBusyId(u.id);
            try {
              await api(`/api/v1/admin/users/${u.id}/block`, { method: 'POST', token, body: { blocked: blocking } });
              setResults((prev) => prev.map((r) => (r.id === u.id ? { ...r, is_active: !r.is_active } : r)));
            } catch (e) { Alert.alert('Failed', e.message); }
            setBusyId(null);
          },
        },
      ]
    );
  };

  const setTier = async (u, tier) => {
    setBusyId(u.id);
    try {
      await api(`/api/v1/admin/users/${u.id}/tier`, { method: 'POST', token, body: { tier } });
      setResults((prev) => prev.map((r) => (r.id === u.id ? { ...r, tier } : r)));
    } catch (e) { Alert.alert('Failed', e.message); }
    setBusyId(null);
  };

  const resetPin = async (u) => {
    Alert.alert(
      'Reset Transaction PIN?',
      `${u.full_name || u.phone} will be asked to set a new 4-digit PIN before their next purchase or withdrawal.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Reset PIN',
          style: 'destructive',
          onPress: async () => {
            setBusyId(u.id);
            try {
              const data = await api(`/api/v1/admin/users/${u.id}/pin/reset`, { method: 'POST', token });
              Alert.alert('Done', data?.message || "User's transaction PIN has been reset");
            } catch (e) { Alert.alert('Failed', e.message); }
            setBusyId(null);
          },
        },
      ]
    );
  };

  const resetPassword = async (u) => {
    Alert.alert(
      'Reset Login Password?',
      `A new temporary password will be generated for ${u.full_name || u.phone}. Only share it with them after confirming their identity — they should change it right after logging in.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Reset Password',
          style: 'destructive',
          onPress: async () => {
            setBusyId(u.id);
            try {
              const data = await api(`/api/v1/admin/users/${u.id}/password/reset`, { method: 'POST', token });
              Alert.alert(
                'Temporary Password Generated',
                `${data?.tempPassword}\n\nShare this with the user through a verified channel only — do not text or email it unencrypted.`
              );
            } catch (e) { Alert.alert('Failed', e.message); }
            setBusyId(null);
          },
        },
      ]
    );
  };

  const deleteUser = async (u) => {
    if (u.wallets?.balance && Number(u.wallets.balance) > 0) {
      return Alert.alert('Cannot delete', `${u.full_name || u.phone} still has a wallet balance of ₦${Number(u.wallets.balance).toLocaleString()}. The balance must be zero before deletion.`);
    }
    Alert.alert(
      'Delete this user?',
      `${u.full_name || u.phone} will be permanently removed. Their name, phone, email, BVN/NIN and login PIN are erased and they can no longer log in. This cannot be undone.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            setBusyId(u.id);
            try {
              await api(`/api/v1/admin/users/${u.id}/delete`, { method: 'POST', token });
              Alert.alert('Deleted', 'User account has been deleted.');
              setResults((prev) => prev.filter((r) => r.id !== u.id));
            } catch (e) { Alert.alert('Failed', e.message); }
            setBusyId(null);
          },
        },
      ]
    );
  };

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="User Management" subtitle="Search, freeze/block, and set pricing tier" onBack={onBack} colors={colors} />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <View style={{ paddingHorizontal: 20, marginTop: 16 }}>
        <TouchableOpacity onPress={openBulk} style={{ backgroundColor: colors.headerBg, borderRadius: 12, paddingVertical: 12, alignItems: 'center', flexDirection: 'row', justifyContent: 'center', marginBottom: 12 }}>
          <Ionicons name="megaphone-outline" size={16} color="#fff" style={{ marginRight: 8 }} />
          <Text style={{ color: '#fff', fontWeight: '700', fontSize: 13 }}>Bulk Message</Text>
        </TouchableOpacity>
      </View>
      <View style={{ paddingHorizontal: 20, flexDirection: 'row' }}>
        <TextInput style={[adminInputStyle(colors), { flex: 1, marginRight: 8, marginBottom: 0 }]} placeholder="Search by phone, email or name" placeholderTextColor={colors.subtext} value={q} onChangeText={setQ} onSubmitEditing={search} autoCapitalize="none" />
        <TouchableOpacity style={{ backgroundColor: colors.headerBg, borderRadius: 12, width: 48, justifyContent: 'center', alignItems: 'center' }} onPress={search} disabled={searching}>
          {searching ? <ActivityIndicator color="#fff" size="small" /> : <Ionicons name="search" size={20} color="#fff" />}
        </TouchableOpacity>
      </View>
      <View style={{ paddingHorizontal: 20, marginTop: 10, backgroundColor: '#fef3c7', borderRadius: 10, padding: 10 }}>
        <Text style={{ color: '#92400e', fontSize: 11.5, lineHeight: 16 }}>
          Before sharing a registered phone number or email back to a customer, confirm their identity first — full name plus BVN/NIN or another detail only the real account owner would know. Don't read contact details to someone who can't confirm those.
        </Text>
      </View>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 14 }} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        {loadingList && <ActivityIndicator color={colors.accent} style={{ marginTop: 20 }} />}
        {!loadingList && results.length === 0 && <Text style={{ color: colors.subtext }}>No users found.</Text>}
        {results.map((u, i) => (
          <View key={i} style={adminCardStyle(colors)}>
            <Text style={{ fontWeight: 'bold', color: colors.text, fontSize: 14.5 }}>{u.full_name || 'Unnamed'}</Text>
            <Text style={{ color: colors.subtext, fontSize: 12.5, marginTop: 2 }}>{u.phone} {u.email ? `· ${u.email}` : ''}</Text>
            {u.wallets?.balance !== undefined && (
              <Text style={{ color: colors.accent, fontSize: 12.5, marginTop: 2, fontWeight: '600' }}>Wallet: ₦{Number(u.wallets.balance || 0).toLocaleString()}</Text>
            )}
            <View style={{ flexDirection: 'row', marginTop: 8 }}>
              <View style={{ backgroundColor: u.is_frozen ? '#fee2e2' : colors.iconWrap, borderRadius: 8, paddingHorizontal: 8, paddingVertical: 3, marginRight: 6 }}>
                <Text style={{ fontSize: 10.5, fontWeight: '700', color: u.is_frozen ? '#b91c1c' : colors.accent }}>{u.is_frozen ? 'FROZEN' : 'ACTIVE'}</Text>
              </View>
              <View style={{ backgroundColor: u.is_active ? colors.iconWrap : '#fee2e2', borderRadius: 8, paddingHorizontal: 8, paddingVertical: 3 }}>
                <Text style={{ fontSize: 10.5, fontWeight: '700', color: u.is_active ? colors.accent : '#b91c1c' }}>{u.is_active ? 'LOGIN OK' : 'BLOCKED'}</Text>
              </View>
            </View>

            <Text style={{ fontSize: 11, fontWeight: '700', color: colors.subtext, marginTop: 10, marginBottom: 6 }}>TIER</Text>
            <View style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
              {['standard', 'silver', 'gold', 'vip'].map((t) => (
                <TouchableOpacity key={t} disabled={busyId === u.id} style={adminPillStyle(colors, (u.tier || 'standard') === t)} onPress={() => setTier(u, t)}>
                  <Text style={{ color: (u.tier || 'standard') === t ? '#fff' : colors.text, fontWeight: '600', fontSize: 11.5, textTransform: 'capitalize' }}>{t}</Text>
                </TouchableOpacity>
              ))}
            </View>

            <View style={{ flexDirection: 'row', marginTop: 8 }}>
              <TouchableOpacity disabled={busyId === u.id} onPress={() => toggleFreeze(u)} style={{ flex: 1, backgroundColor: colors.iconWrap, borderRadius: 10, paddingVertical: 10, alignItems: 'center', marginRight: 8 }}>
                <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 12.5 }}>{u.is_frozen ? 'Unfreeze Wallet' : 'Freeze Wallet'}</Text>
              </TouchableOpacity>
              <TouchableOpacity disabled={busyId === u.id} onPress={() => toggleBlock(u)} style={{ flex: 1, backgroundColor: '#fee2e2', borderRadius: 10, paddingVertical: 10, alignItems: 'center' }}>
                <Text style={{ color: '#b91c1c', fontWeight: '700', fontSize: 12.5 }}>{u.is_active ? 'Block Login' : 'Unblock Login'}</Text>
              </TouchableOpacity>
            </View>
            <TouchableOpacity disabled={busyId === u.id} onPress={() => openMessage(u)} style={{ marginTop: 8, backgroundColor: colors.headerBg, borderRadius: 10, paddingVertical: 10, alignItems: 'center', flexDirection: 'row', justifyContent: 'center' }}>
              <Ionicons name="chatbubble-ellipses-outline" size={15} color="#fff" style={{ marginRight: 6 }} />
              <Text style={{ color: '#fff', fontWeight: '700', fontSize: 12.5 }}>Message</Text>
            </TouchableOpacity>
            <TouchableOpacity disabled={busyId === u.id} onPress={() => resetPin(u)} style={{ marginTop: 8, backgroundColor: colors.iconWrap, borderRadius: 10, paddingVertical: 10, alignItems: 'center', flexDirection: 'row', justifyContent: 'center' }}>
              <Ionicons name="keypad-outline" size={15} color={colors.accent} style={{ marginRight: 6 }} />
              <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 12.5 }}>Reset Transaction PIN</Text>
            </TouchableOpacity>
            <TouchableOpacity disabled={busyId === u.id} onPress={() => resetPassword(u)} style={{ marginTop: 8, backgroundColor: colors.iconWrap, borderRadius: 10, paddingVertical: 10, alignItems: 'center', flexDirection: 'row', justifyContent: 'center' }}>
              <Ionicons name="lock-closed-outline" size={15} color={colors.accent} style={{ marginRight: 6 }} />
              <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 12.5 }}>Reset Login Password</Text>
            </TouchableOpacity>
            <TouchableOpacity disabled={busyId === u.id} onPress={() => deleteUser(u)} style={{ marginTop: 8, backgroundColor: '#fee2e2', borderRadius: 10, paddingVertical: 10, alignItems: 'center', flexDirection: 'row', justifyContent: 'center' }}>
              <Ionicons name="trash-outline" size={15} color="#b91c1c" style={{ marginRight: 6 }} />
              <Text style={{ color: '#b91c1c', fontWeight: '700', fontSize: 12.5 }}>Delete User</Text>
            </TouchableOpacity>
            {busyId === u.id && <ActivityIndicator color={colors.accent} style={{ marginTop: 8 }} />}
          </View>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>

      <Modal visible={!!messageUser} animationType="slide" transparent onRequestClose={closeMessage}>
        <View style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.4)', justifyContent: 'flex-end' }}>
          <View style={{ backgroundColor: colors.card, borderTopLeftRadius: 24, borderTopRightRadius: 24, padding: 24, paddingBottom: 36 }}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <Text style={{ fontSize: 17, fontWeight: 'bold', color: colors.text }}>
                Message {messageUser?.full_name || messageUser?.phone || ''}
              </Text>
              <TouchableOpacity onPress={closeMessage}><Ionicons name="close" size={22} color={colors.subtext} /></TouchableOpacity>
            </View>
            <TextInput
              style={adminInputStyle(colors)}
              placeholder="Title (optional)"
              placeholderTextColor={colors.subtext}
              value={msgTitle}
              onChangeText={setMsgTitle}
            />
            <TextInput
              style={[adminInputStyle(colors), { height: 100, textAlignVertical: 'top' }]}
              placeholder="Message"
              placeholderTextColor={colors.subtext}
              value={msgBody}
              onChangeText={setMsgBody}
              multiline
            />
            <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: -6, marginBottom: 14 }}>
              Sent as SMS and saved to their in-app notifications.
            </Text>
            <TouchableOpacity
              disabled={sendingMsg}
              onPress={sendMessage}
              style={{ backgroundColor: colors.headerBg, borderRadius: 12, paddingVertical: 14, alignItems: 'center' }}
            >
              {sendingMsg ? <ActivityIndicator color="#fff" /> : <Text style={{ color: '#fff', fontWeight: 'bold', fontSize: 15 }}>Send</Text>}
            </TouchableOpacity>
          </View>
        </View>
      </Modal>

      <Modal visible={bulkOpen} animationType="slide" transparent onRequestClose={closeBulk}>
        <View style={{ flex: 1, backgroundColor: 'rgba(0,0,0,0.4)', justifyContent: 'flex-end' }}>
          <View style={{ backgroundColor: colors.card, borderTopLeftRadius: 24, borderTopRightRadius: 24, padding: 24, paddingBottom: 36 }}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <Text style={{ fontSize: 17, fontWeight: 'bold', color: colors.text }}>Bulk Message</Text>
              <TouchableOpacity onPress={closeBulk}><Ionicons name="close" size={22} color={colors.subtext} /></TouchableOpacity>
            </View>

            <Text style={{ fontSize: 11, fontWeight: '700', color: colors.subtext, marginBottom: 6 }}>ROLE (optional)</Text>
            <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 12 }}>
              {[null, 'user', 'admin'].map((r) => (
                <TouchableOpacity key={r || 'any'} onPress={() => setBulkRole(r)} style={adminPillStyle(colors, bulkRole === r)}>
                  <Text style={{ color: bulkRole === r ? '#fff' : colors.text, fontWeight: '600', fontSize: 11.5, textTransform: 'capitalize' }}>{r || 'Any'}</Text>
                </TouchableOpacity>
              ))}
            </View>

            <Text style={{ fontSize: 11, fontWeight: '700', color: colors.subtext, marginBottom: 6 }}>TIER (optional)</Text>
            <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 12 }}>
              {[null, 'standard', 'silver', 'gold', 'vip'].map((t) => (
                <TouchableOpacity key={t || 'any'} onPress={() => setBulkTier(t)} style={adminPillStyle(colors, bulkTier === t)}>
                  <Text style={{ color: bulkTier === t ? '#fff' : colors.text, fontWeight: '600', fontSize: 11.5, textTransform: 'capitalize' }}>{t || 'Any'}</Text>
                </TouchableOpacity>
              ))}
            </View>

            <Text style={{ fontSize: 11, fontWeight: '700', color: colors.subtext, marginBottom: 6 }}>LOGIN STATUS (optional)</Text>
            <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 12 }}>
              {[{ label: 'Any', v: null }, { label: 'Active', v: true }, { label: 'Blocked', v: false }].map((o) => (
                <TouchableOpacity key={o.label} onPress={() => setBulkActive(o.v)} style={adminPillStyle(colors, bulkActive === o.v)}>
                  <Text style={{ color: bulkActive === o.v ? '#fff' : colors.text, fontWeight: '600', fontSize: 11.5 }}>{o.label}</Text>
                </TouchableOpacity>
              ))}
            </View>

            <Text style={{ fontSize: 11, fontWeight: '700', color: colors.subtext, marginBottom: 6 }}>WALLET STATUS (optional)</Text>
            <View style={{ flexDirection: 'row', flexWrap: 'wrap', marginBottom: 14 }}>
              {[{ label: 'Any', v: null }, { label: 'Frozen', v: true }, { label: 'Not Frozen', v: false }].map((o) => (
                <TouchableOpacity key={o.label} onPress={() => setBulkFrozen(o.v)} style={adminPillStyle(colors, bulkFrozen === o.v)}>
                  <Text style={{ color: bulkFrozen === o.v ? '#fff' : colors.text, fontWeight: '600', fontSize: 11.5 }}>{o.label}</Text>
                </TouchableOpacity>
              ))}
            </View>

            <TextInput
              style={adminInputStyle(colors)}
              placeholder="Title (optional)"
              placeholderTextColor={colors.subtext}
              value={bulkTitle}
              onChangeText={setBulkTitle}
            />
            <TextInput
              style={[adminInputStyle(colors), { height: 100, textAlignVertical: 'top' }]}
              placeholder="Message"
              placeholderTextColor={colors.subtext}
              value={bulkBody}
              onChangeText={setBulkBody}
              multiline
            />
            <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: -6, marginBottom: 14 }}>
              Leave filters on "Any" to message every user. Sent as SMS and saved to their in-app notifications.
            </Text>
            <TouchableOpacity
              disabled={sendingBulk}
              onPress={sendBulk}
              style={{ backgroundColor: colors.headerBg, borderRadius: 12, paddingVertical: 14, alignItems: 'center' }}
            >
              {sendingBulk ? <ActivityIndicator color="#fff" /> : <Text style={{ color: '#fff', fontWeight: 'bold', fontSize: 15 }}>Send to All Matching</Text>}
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

// ─── Admin: Pricing & Margins (global + tier overrides) ────────────────────────
// Ensures every known service shows up in Global Margins even before it has a database row
// (e.g. a brand-new service like 'isp') — defaults missing ones to 0% until an admin sets one.
function mergeGlobalMargins(rows) {
  const byService = {};
  (rows || []).forEach((r) => { byService[r.service] = r; });
  return ADMIN_PRICING_SERVICES.map((service) => byService[service] || { service, markup_percent: 0 });
}

function AdminPricingScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [tab, setTab] = useState('global');
  const [globalMargins, setGlobalMargins] = useState([]);
  const [tierMargins, setTierMargins] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editKey, setEditKey] = useState(null);
  const [editValue, setEditValue] = useState('');
  const [tierPick, setTierPick] = useState('vip');
  const [servicePick, setServicePick] = useState('data');

  const load = useCallback(async () => {
    try {
      const [g, t] = await Promise.all([
        api('/api/v1/admin/pricing', { token }),
        api('/api/v1/admin/tier-pricing', { token }),
      ]);
      setGlobalMargins(mergeGlobalMargins(g));
      setTierMargins(t);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const saveGlobal = async (service) => {
    if (editValue === '' || isNaN(editValue)) return;
    try {
      await api(`/api/v1/admin/pricing/${service}`, { method: 'PUT', token, body: { markupPercent: Number(editValue) } });
      setEditKey(null); setEditValue('');
      load();
    } catch (e) { Alert.alert('Failed', e.message); }
  };

  const saveTier = async () => {
    if (editValue === '' || isNaN(editValue)) return;
    try {
      await api(`/api/v1/admin/tier-pricing/${tierPick}/${servicePick}`, { method: 'PUT', token, body: { markupPercent: Number(editValue) } });
      setEditValue('');
      load();
    } catch (e) { Alert.alert('Failed', e.message); }
  };

  const clearTierOverride = async (tier, service) => {
    try {
      await api(`/api/v1/admin/tier-pricing/${tier}/${service}`, { method: 'DELETE', token });
      load();
    } catch (e) { Alert.alert('Failed', e.message); }
  };

  const tierRow = tierMargins.find((r) => r.tier === tierPick && r.service === servicePick);

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Pricing & Margins" subtitle="Cost vs. selling price per network plan, and per-tier discounts" onBack={onBack} colors={colors} />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <View style={{ flexDirection: 'row', paddingHorizontal: 20, marginTop: 16 }}>
        <TouchableOpacity style={[adminPillStyle(colors, tab === 'global'), { flex: 1, alignItems: 'center' }]} onPress={() => setTab('global')}>
          <Text style={{ color: tab === 'global' ? '#fff' : colors.text, fontWeight: '700' }}>Global Margins</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[adminPillStyle(colors, tab === 'tier'), { flex: 1, alignItems: 'center' }]} onPress={() => setTab('tier')}>
          <Text style={{ color: tab === 'tier' ? '#fff' : colors.text, fontWeight: '700' }}>Tier Pricing</Text>
        </TouchableOpacity>
      </View>

      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 14 }} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        {loading && <ActivityIndicator color={colors.accent} />}

        {!loading && tab === 'global' && globalMargins.map((m, i) => (
          <View key={i} style={[adminCardStyle(colors), { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }]}>
            <Text style={{ color: colors.text, fontWeight: '600', fontSize: 13.5, textTransform: 'capitalize' }}>{m.service.replace('_', ' ')}</Text>
            {editKey === m.service ? (
              <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                <TextInput style={[adminInputStyle(colors), { width: 70, marginBottom: 0, paddingVertical: 6, textAlign: 'center' }]} keyboardType="numeric" value={editValue} onChangeText={setEditValue} autoFocus />
                <TouchableOpacity onPress={() => saveGlobal(m.service)} style={{ marginLeft: 8 }}>
                  <Ionicons name="checkmark-circle" size={26} color="#059669" />
                </TouchableOpacity>
              </View>
            ) : (
              <TouchableOpacity onPress={() => { setEditKey(m.service); setEditValue(String(m.markup_percent)); }} style={{ flexDirection: 'row', alignItems: 'center' }}>
                <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 14, marginRight: 6 }}>{m.markup_percent}%</Text>
                <Ionicons name="pencil" size={15} color={colors.subtext} />
              </TouchableOpacity>
            )}
          </View>
        ))}

        {!loading && tab === 'tier' && (
          <>
            <Text style={{ fontSize: 12.5, fontWeight: '700', color: colors.text, marginBottom: 8 }}>Tier</Text>
            <View style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
              {['standard', 'silver', 'gold', 'vip'].map((t) => (
                <TouchableOpacity key={t} style={adminPillStyle(colors, tierPick === t)} onPress={() => setTierPick(t)}>
                  <Text style={{ color: tierPick === t ? '#fff' : colors.text, fontWeight: '600', fontSize: 12, textTransform: 'capitalize' }}>{t}</Text>
                </TouchableOpacity>
              ))}
            </View>
            <Text style={{ fontSize: 12.5, fontWeight: '700', color: colors.text, marginBottom: 8, marginTop: 8 }}>Service</Text>
            <View style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
              {ADMIN_PRICING_SERVICES.map((sv) => (
                <TouchableOpacity key={sv} style={adminPillStyle(colors, servicePick === sv)} onPress={() => setServicePick(sv)}>
                  <Text style={{ color: servicePick === sv ? '#fff' : colors.text, fontWeight: '600', fontSize: 12, textTransform: 'capitalize' }}>{sv.replace('_', ' ')}</Text>
                </TouchableOpacity>
              ))}
            </View>

            <View style={[adminCardStyle(colors), { marginTop: 14 }]}>
              <Text style={{ color: colors.subtext, fontSize: 12.5, marginBottom: 10 }}>
                {tierRow ? `${tierPick} pays ${tierRow.markup_percent}% markup on ${servicePick.replace('_', ' ')} (overrides the global rate).` : `No override — ${tierPick} uses the global margin for ${servicePick.replace('_', ' ')}.`}
              </Text>
              <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                <TextInput style={[adminInputStyle(colors), { flex: 1, marginBottom: 0, marginRight: 8 }]} placeholder="Markup %" placeholderTextColor={colors.subtext} keyboardType="numeric" value={editValue} onChangeText={setEditValue} />
                <TouchableOpacity style={{ backgroundColor: colors.headerBg, borderRadius: 10, paddingHorizontal: 16, paddingVertical: 13 }} onPress={saveTier}>
                  <Text style={{ color: '#fff', fontWeight: '700', fontSize: 12.5 }}>Save</Text>
                </TouchableOpacity>
              </View>
              {tierRow && (
                <TouchableOpacity onPress={() => clearTierOverride(tierPick, servicePick)} style={{ marginTop: 10 }}>
                  <Text style={{ color: '#b91c1c', fontWeight: '600', fontSize: 12.5 }}>Remove override (use global rate)</Text>
                </TouchableOpacity>
              )}
            </View>
          </>
        )}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Automated Failover Log ──────────────────────────────────────────────
function AdminFailoverLogScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const data = await api('/api/v1/admin/failover-events?limit=100', { token });
      setEvents(data);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Failover Log" subtitle="Every automatic switch from a failed provider to the backup" onBack={onBack} colors={colors} />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 16 }} contentContainerStyle={{ paddingBottom: 40 }} refreshControl={<RefreshControl refreshing={false} onRefresh={load} colors={[colors.accent]} />}>
        {loading && <ActivityIndicator color={colors.accent} />}
        {!loading && events.length === 0 && <Text style={{ color: colors.subtext }}>No failovers recorded — both providers have been healthy.</Text>}
        {events.map((e, i) => (
          <View key={i} style={adminCardStyle(colors)}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              <Text style={{ color: colors.text, fontWeight: '700', fontSize: 13.5 }}>{e.network} · {e.service}</Text>
              <Text style={{ color: colors.subtext, fontSize: 11 }}>{new Date(e.created_at).toLocaleString()}</Text>
            </View>
            <Text style={{ color: '#d97706', fontSize: 12.5, marginTop: 4, fontWeight: '600' }}>{e.from_provider} → {e.to_provider}</Text>
            <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 4 }}>{e.reason}</Text>
            {e.reference && <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 4 }}>Ref: {e.reference}</Text>}
          </View>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Audit Log (WHO did WHAT to WHOM, and WHEN) ─────────────────────────
function AdminAuditLogScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [targetType, setTargetType] = useState('all');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      let path = '/api/v1/admin/audit-log?limit=100';
      if (targetType !== 'all') path += `&targetType=${targetType}`;
      const data = await api(path, { token });
      setEntries(data);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token, targetType]);

  useEffect(() => { load(); }, [load]);

  // Turns 'freeze_user' into 'Freeze user' for display — the backend logs a short
  // machine-friendly action string, this just makes it readable without a lookup table.
  const formatAction = (action) => {
    const s = String(action || '').replace(/_/g, ' ');
    return s.charAt(0).toUpperCase() + s.slice(1);
  };

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Audit Log" subtitle="Every admin action — who did it, to what, and when" onBack={onBack} colors={colors} />
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', paddingHorizontal: 20, marginTop: 16 }}>
        {['all', 'user', 'transaction', 'service_control', 'tier_pricing', 'provider_route'].map((f) => (
          <TouchableOpacity key={f} style={adminPillStyle(colors, targetType === f)} onPress={() => setTargetType(f)}>
            <Text style={{ color: targetType === f ? '#fff' : colors.text, fontWeight: '600', fontSize: 12, textTransform: 'capitalize' }}>{f.replace(/_/g, ' ')}</Text>
          </TouchableOpacity>
        ))}
      </View>
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 8 }} contentContainerStyle={{ paddingBottom: 40 }} refreshControl={<RefreshControl refreshing={false} onRefresh={load} colors={[colors.accent]} />}>
        {loading && <ActivityIndicator color={colors.accent} />}
        {!loading && entries.length === 0 && <Text style={{ color: colors.subtext }}>No admin actions recorded yet.</Text>}
        {entries.map((e) => (
          <View key={e.id} style={adminCardStyle(colors)}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              <Text style={{ color: colors.text, fontWeight: '700', fontSize: 13.5 }}>{formatAction(e.action)}</Text>
              <Text style={{ color: colors.subtext, fontSize: 11 }}>{new Date(e.created_at).toLocaleString()}</Text>
            </View>
            <Text style={{ color: colors.accent, fontSize: 12.5, marginTop: 4, fontWeight: '600' }}>
              {e.admin?.full_name || 'Unknown admin'}{e.admin?.phone ? ` (${e.admin.phone})` : ''}
            </Text>
            {e.target_type && (
              <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 4 }}>
                Target: {e.target_type}{e.target_id ? ` · ${e.target_id}` : ''}
              </Text>
            )}
            {e.details && Object.keys(e.details).length > 0 && (
              <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 4 }} numberOfLines={3}>
                {Object.entries(e.details).filter(([, v]) => v !== null && v !== undefined && v !== '').map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join('  ·  ')}
              </Text>
            )}
          </View>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Provider API Log Viewer ─────────────────────────────────────────────
function AdminProviderLogsScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [expandedId, setExpandedId] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      let path = '/api/v1/admin/provider-logs?limit=100';
      if (filter === 'failed') path += '&success=false';
      if (filter === 'success') path += '&success=true';
      const data = await api(path, { token });
      setLogs(data);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token, filter]);

  useEffect(() => { load(); }, [load]);

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Provider API Logs" subtitle="Raw request/response payloads sent to Bigisub & KlubConnect" onBack={onBack} colors={colors} />
      <View style={{ flexDirection: 'row', paddingHorizontal: 20, marginTop: 16 }}>
        {['all', 'failed', 'success'].map((f) => (
          <TouchableOpacity key={f} style={adminPillStyle(colors, filter === f)} onPress={() => setFilter(f)}>
            <Text style={{ color: filter === f ? '#fff' : colors.text, fontWeight: '600', fontSize: 12, textTransform: 'capitalize' }}>{f}</Text>
          </TouchableOpacity>
        ))}
      </View>
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 10 }} contentContainerStyle={{ paddingBottom: 40 }}>
        {loading && <ActivityIndicator color={colors.accent} />}
        {!loading && logs.length === 0 && <Text style={{ color: colors.subtext }}>No matching log entries.</Text>}
        {logs.map((l, i) => (
          <TouchableOpacity key={i} style={adminCardStyle(colors)} onPress={() => setExpandedId(expandedId === l.id ? null : l.id)} activeOpacity={0.8}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              <Text style={{ color: colors.text, fontWeight: '700', fontSize: 13.5 }}>{l.provider} · {l.service}</Text>
              <View style={{ backgroundColor: l.success ? '#dcfce7' : '#fee2e2', borderRadius: 8, paddingHorizontal: 8, paddingVertical: 2 }}>
                <Text style={{ fontSize: 10.5, fontWeight: '700', color: l.success ? '#059669' : '#b91c1c' }}>{l.success ? 'SUCCESS' : 'FAILED'}</Text>
              </View>
            </View>
            <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 4 }}>{l.reference || 'no reference'} · {new Date(l.created_at).toLocaleString()}</Text>
            {l.error_message && <Text style={{ color: '#b91c1c', fontSize: 12, marginTop: 4 }}>{l.error_message}</Text>}
            {expandedId === l.id && (
              <View style={{ marginTop: 10, backgroundColor: colors.iconWrap, borderRadius: 10, padding: 10 }}>
                <Text style={{ fontSize: 10.5, fontWeight: '700', color: colors.subtext, marginBottom: 4 }}>REQUEST</Text>
                <Text style={{ fontSize: 11, color: colors.text, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' }}>{JSON.stringify(l.request_payload, null, 2)}</Text>
                <Text style={{ fontSize: 10.5, fontWeight: '700', color: colors.subtext, marginBottom: 4, marginTop: 10 }}>RESPONSE</Text>
                <Text style={{ fontSize: 11, color: colors.text, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' }}>{JSON.stringify(l.response_payload, null, 2)}</Text>
              </View>
            )}
          </TouchableOpacity>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}
// ─── Admin: Virtual Account / Gateway Reconciler ────────────────────────────────
function AdminGatewayReconcilerScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [unmatchedOnly, setUnmatchedOnly] = useState(true);
  const [resolvingId, setResolvingId] = useState(null);
  const [userIdInput, setUserIdInput] = useState('');
  const [customerQuery, setCustomerQuery] = useState('');
  const [customerResults, setCustomerResults] = useState([]);
  const [searchingCustomer, setSearchingCustomer] = useState(false);
  const [selectedCustomer, setSelectedCustomer] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api(`/api/v1/admin/gateway-events?limit=100${unmatchedOnly ? '&unmatchedOnly=true' : ''}`, { token });
      setEvents(data);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token, unmatchedOnly]);

  useEffect(() => { load(); }, [load]);

  const searchCustomer = async () => {
    if (!customerQuery.trim()) return;
    setSearchingCustomer(true);
    try {
      const data = await api(`/api/v1/admin/users/search?q=${encodeURIComponent(customerQuery.trim())}`, { token });
      setCustomerResults(Array.isArray(data) ? data : []);
    } catch (e) { Alert.alert('Search failed', e.message); }
    setSearchingCustomer(false);
  };

  const pickCustomer = (u) => {
    setSelectedCustomer(u);
    setUserIdInput(u.id);
    setCustomerResults([]);
    setCustomerQuery('');
  };

  const startResolving = (eventId) => {
    setResolvingId(eventId);
    setUserIdInput('');
    setSelectedCustomer(null);
    setCustomerQuery('');
    setCustomerResults([]);
  };

  const resolve = async (eventId) => {
    if (!userIdInput.trim()) {
      Alert.alert('Customer required', 'Search for and select the customer to credit before resolving.');
      return;
    }
    try {
      await api(`/api/v1/admin/gateway-events/${eventId}/resolve`, { method: 'POST', token, body: { userId: userIdInput.trim() } });
      Alert.alert('Resolved', 'Wallet credited and event marked resolved.');
      setUserIdInput(''); setResolvingId(null); setSelectedCustomer(null);
      load();
    } catch (e) { Alert.alert('Failed', e.message); }
  };

  const naira = (n) => `₦${(n || 0).toLocaleString()}`;

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Gateway Reconciler" subtitle="Match webhook payments to wallets — resolve 'paid but not credited'" onBack={onBack} colors={colors} />
      <View style={{ flexDirection: 'row', paddingHorizontal: 20, marginTop: 16, alignItems: 'center' }}>
        <TouchableOpacity style={adminPillStyle(colors, unmatchedOnly)} onPress={() => setUnmatchedOnly(true)}>
          <Text style={{ color: unmatchedOnly ? '#fff' : colors.text, fontWeight: '600', fontSize: 12 }}>Unmatched only</Text>
        </TouchableOpacity>
        <TouchableOpacity style={adminPillStyle(colors, !unmatchedOnly)} onPress={() => setUnmatchedOnly(false)}>
          <Text style={{ color: !unmatchedOnly ? '#fff' : colors.text, fontWeight: '600', fontSize: 12 }}>All events</Text>
        </TouchableOpacity>
      </View>
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 10 }} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        {loading && <ActivityIndicator color={colors.accent} />}
        {!loading && events.length === 0 && <Text style={{ color: colors.subtext }}>Nothing to reconcile — all webhooks matched cleanly.</Text>}
        {events.map((e, i) => (
          <View key={i} style={adminCardStyle(colors)}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              <Text style={{ color: colors.text, fontWeight: '700', fontSize: 14 }}>{naira(e.amount)}</Text>
              <View style={{ backgroundColor: e.wallet_credited ? '#dcfce7' : '#fee2e2', borderRadius: 8, paddingHorizontal: 8, paddingVertical: 2 }}>
                <Text style={{ fontSize: 10.5, fontWeight: '700', color: e.wallet_credited ? '#059669' : '#b91c1c' }}>{e.wallet_credited ? 'CREDITED' : 'UNMATCHED'}</Text>
              </View>
            </View>
            <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 4 }}>{e.provider} · {e.tx_ref}</Text>
            <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 2 }}>{new Date(e.created_at).toLocaleString()}</Text>
            {!e.wallet_credited && (
              resolvingId === e.id ? (
                <View style={{ marginTop: 10 }}>
                  {selectedCustomer ? (
                    <View style={[adminCardStyle(colors), { marginBottom: 10 }]}>
                      <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
                        <View style={{ flex: 1 }}>
                          <Text style={{ fontWeight: 'bold', color: colors.text, fontSize: 13.5 }}>{selectedCustomer.full_name || 'Unnamed'}</Text>
                          <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 2 }}>{selectedCustomer.phone} {selectedCustomer.email ? `· ${selectedCustomer.email}` : ''}</Text>
                        </View>
                        <TouchableOpacity onPress={() => { setSelectedCustomer(null); setUserIdInput(''); }}>
                          <Ionicons name="close-circle" size={20} color={colors.subtext} />
                        </TouchableOpacity>
                      </View>
                    </View>
                  ) : (
                    <>
                      <View style={{ flexDirection: 'row', marginBottom: customerResults.length ? 8 : 10 }}>
                        <TextInput
                          style={[adminInputStyle(colors), { flex: 1, marginRight: 8, marginBottom: 0 }]}
                          placeholder="Search customer by phone, email or name"
                          placeholderTextColor={colors.subtext}
                          value={customerQuery}
                          onChangeText={setCustomerQuery}
                          onSubmitEditing={searchCustomer}
                          autoCapitalize="none"
                        />
                        <TouchableOpacity style={{ backgroundColor: colors.headerBg, borderRadius: 12, width: 44, justifyContent: 'center', alignItems: 'center' }} onPress={searchCustomer} disabled={searchingCustomer}>
                          {searchingCustomer ? <ActivityIndicator color="#fff" size="small" /> : <Ionicons name="search" size={18} color="#fff" />}
                        </TouchableOpacity>
                      </View>
                      {customerResults.map((u, i) => (
                        <TouchableOpacity key={i} style={[adminCardStyle(colors), { marginBottom: 8 }]} onPress={() => pickCustomer(u)}>
                          <Text style={{ fontWeight: 'bold', color: colors.text, fontSize: 13 }}>{u.full_name || 'Unnamed'}</Text>
                          <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: 2 }}>{u.phone} {u.email ? `· ${u.email}` : ''}</Text>
                        </TouchableOpacity>
                      ))}
                    </>
                  )}
                  <TouchableOpacity style={adminBtnStyle(colors, 'success')} onPress={() => resolve(e.id)}>
                    <Text style={{ color: '#fff', fontWeight: 'bold' }}>Credit & Resolve</Text>
                  </TouchableOpacity>
                </View>
              ) : (
                <TouchableOpacity onPress={() => startResolving(e.id)} style={{ marginTop: 10, backgroundColor: colors.iconWrap, borderRadius: 10, paddingVertical: 10, alignItems: 'center' }}>
                  <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 12.5 }}>Resolve Manually</Text>
                </TouchableOpacity>
              )
            )}
          </View>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Pending Purchases (ambiguous provider failures needing manual review) ──
function AdminPendingPurchasesScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [resolvingRef, setResolvingRef] = useState(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api('/api/v1/admin/pending-purchases?limit=100', { token });
      setItems(Array.isArray(data) ? data : []);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const startResolving = (reference) => { setResolvingRef(reference); setNote(''); };

  const resolve = (reference, action) => {
    const labels = { delivered: 'Mark as delivered (no refund)?', refund: 'Refund this customer?' };
    const messages = {
      delivered: 'Only confirm this if you\'ve checked with the provider and the purchase actually went through.',
      refund: 'This will credit the customer\'s wallet back. Only confirm if you\'ve checked with the provider and it did NOT go through.',
    };
    Alert.alert(labels[action], messages[action], [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Confirm',
        style: action === 'refund' ? 'default' : 'default',
        onPress: async () => {
          setBusy(true);
          try {
            await api(`/api/v1/admin/pending-purchases/${reference}/resolve`, { method: 'POST', token, body: { action, note } });
            Alert.alert('Done', action === 'delivered' ? 'Marked as delivered' : 'Refunded to customer wallet');
            setResolvingRef(null); setNote('');
            load();
          } catch (e) { Alert.alert('Failed', e.message); }
          setBusy(false);
        },
      },
    ]);
  };

  const naira = (n) => `₦${(n || 0).toLocaleString()}`;

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Pending Purchases" subtitle="Ambiguous provider failures — confirm delivered or refund" onBack={onBack} colors={colors} />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 16 }} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        {loading && <ActivityIndicator color={colors.accent} />}
        {!loading && items.length === 0 && <Text style={{ color: colors.subtext }}>Nothing pending — all purchases resolved cleanly.</Text>}
        {items.map((t) => (
          <View key={t.reference} style={adminCardStyle(colors)}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              <Text style={{ color: colors.text, fontWeight: '700', fontSize: 14 }}>{naira(t.amount)} · {t.category}</Text>
              <View style={{ backgroundColor: '#fef3c7', borderRadius: 8, paddingHorizontal: 8, paddingVertical: 2 }}>
                <Text style={{ fontSize: 10.5, fontWeight: '700', color: '#92400e' }}>NEEDS REVIEW</Text>
              </View>
            </View>
            <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 4 }}>{t.description}</Text>
            <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: 2 }}>{t.users?.full_name || 'Unnamed'} · {t.users?.phone || t.phone}</Text>
            <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 2 }}>{new Date(t.created_at).toLocaleString()} · Ref: {t.reference}</Text>

            {resolvingRef === t.reference ? (
              <View style={{ marginTop: 10 }}>
                <TextInput
                  style={[adminInputStyle(colors), { marginBottom: 10 }]}
                  placeholder="Note (optional) — e.g. what the provider dashboard showed"
                  placeholderTextColor={colors.subtext}
                  value={note}
                  onChangeText={setNote}
                  multiline
                />
                <View style={{ flexDirection: 'row' }}>
                  <TouchableOpacity style={[adminBtnStyle(colors, 'success'), { flex: 1, marginRight: 8 }]} disabled={busy} onPress={() => resolve(t.reference, 'delivered')}>
                    <Text style={{ color: '#fff', fontWeight: 'bold' }}>Mark Delivered</Text>
                  </TouchableOpacity>
                  <TouchableOpacity style={[adminBtnStyle(colors, 'danger'), { flex: 1 }]} disabled={busy} onPress={() => resolve(t.reference, 'refund')}>
                    <Text style={{ color: '#fff', fontWeight: 'bold' }}>Refund</Text>
                  </TouchableOpacity>
                </View>
                <TouchableOpacity onPress={() => setResolvingRef(null)} style={{ marginTop: 8, alignItems: 'center' }}>
                  <Text style={{ color: colors.subtext, fontSize: 12 }}>Cancel</Text>
                </TouchableOpacity>
              </View>
            ) : (
              <TouchableOpacity onPress={() => startResolving(t.reference)} style={{ marginTop: 10, backgroundColor: colors.iconWrap, borderRadius: 10, paddingVertical: 10, alignItems: 'center' }}>
                <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 12.5 }}>Review</Text>
              </TouchableOpacity>
            )}
          </View>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Wallet Withdrawals ──────────────────────────────────────────────────
function AdminWithdrawalsScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('pending_review'); // 'pending_review' | 'success' | 'failed' | ''
  const [resolvingRef, setResolvingRef] = useState(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  const [settings, setSettings] = useState({ enabled: true, maxAmount: null });
  const [settingsLoading, setSettingsLoading] = useState(true);
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [maxAmountInput, setMaxAmountInput] = useState('');
  const [editingMax, setEditingMax] = useState(false);

  const loadSettings = useCallback(async () => {
    try {
      const data = await api('/api/v1/admin/withdrawal-settings', { token });
      setSettings(data);
      setMaxAmountInput(data.maxAmount !== null ? String(data.maxAmount) : '');
    } catch (e) { Alert.alert('Error', e.message); }
    setSettingsLoading(false);
  }, [token]);

  useEffect(() => { loadSettings(); }, [loadSettings]);

  const toggleEnabled = async () => {
    setSettingsBusy(true);
    try {
      const data = await api('/api/v1/admin/withdrawal-settings', { method: 'PUT', token, body: { enabled: !settings.enabled } });
      setSettings(data);
    } catch (e) { Alert.alert('Failed', e.message); }
    setSettingsBusy(false);
  };

  const saveMaxAmount = async () => {
    const value = maxAmountInput.trim() === '' ? null : Number(maxAmountInput);
    if (value !== null && (isNaN(value) || value <= 0)) return Alert.alert('Invalid amount', 'Enter a positive number, or leave blank for no limit');
    setSettingsBusy(true);
    try {
      const data = await api('/api/v1/admin/withdrawal-settings', { method: 'PUT', token, body: { maxAmount: value } });
      setSettings(data);
      setEditingMax(false);
    } catch (e) { Alert.alert('Failed', e.message); }
    setSettingsBusy(false);
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const qs = filter ? `?status=${filter}&limit=100` : '?limit=100';
      const data = await api(`/api/v1/admin/withdrawals${qs}`, { token });
      setItems(Array.isArray(data) ? data : []);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token, filter]);

  useEffect(() => { load(); }, [load]);

  const startResolving = (reference) => { setResolvingRef(reference); setNote(''); };

  const resolve = (reference, action) => {
    const labels = { paid: 'Mark as paid (no refund)?', refund: 'Refund this customer?' };
    const messages = {
      paid: 'Only confirm this if you\'ve checked the Flutterwave dashboard and the transfer actually settled.',
      refund: 'This will credit the customer\'s wallet back. Only confirm if you\'ve checked and the transfer did NOT land.',
    };
    Alert.alert(labels[action], messages[action], [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Confirm',
        onPress: async () => {
          setBusy(true);
          try {
            await api(`/api/v1/admin/withdrawals/${reference}/resolve`, { method: 'POST', token, body: { action, note } });
            Alert.alert('Done', action === 'paid' ? 'Marked as paid' : 'Refunded to customer wallet');
            setResolvingRef(null); setNote('');
            load();
          } catch (e) { Alert.alert('Failed', e.message); }
          setBusy(false);
        },
      },
    ]);
  };

  const naira = (n) => `₦${(n || 0).toLocaleString()}`;
  const statusColors = { pending_review: { bg: '#fef3c7', text: '#92400e', label: 'PENDING' }, success: { bg: '#dcfce7', text: '#166534', label: 'PAID' }, failed: { bg: '#fee2e2', text: '#991b1b', label: 'REFUNDED' } };

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Wallet Withdrawals" subtitle="Bank payouts from customer wallets" onBack={onBack} colors={colors} />

      <View style={{ paddingHorizontal: 20, marginTop: 14 }}>
        {settingsLoading ? (
          <ActivityIndicator color={colors.accent} />
        ) : (
          <View style={adminCardStyle(colors)}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
              <View>
                <Text style={{ fontSize: 14, fontWeight: 'bold', color: colors.text }}>Withdrawals {settings.enabled ? 'Enabled' : 'Disabled'}</Text>
                <Text style={{ fontSize: 11.5, color: colors.subtext, marginTop: 2 }}>Turn off to pause all customer withdrawals instantly</Text>
              </View>
              <TouchableOpacity
                disabled={settingsBusy}
                onPress={toggleEnabled}
                style={{ width: 52, height: 30, borderRadius: 15, backgroundColor: settings.enabled ? '#059669' : '#dc2626', justifyContent: 'center', paddingHorizontal: 3 }}
              >
                {settingsBusy ? (
                  <ActivityIndicator size="small" color="#fff" />
                ) : (
                  <View style={{ width: 24, height: 24, borderRadius: 12, backgroundColor: '#fff', alignSelf: settings.enabled ? 'flex-end' : 'flex-start' }} />
                )}
              </TouchableOpacity>
            </View>

            <View style={{ marginTop: 14, paddingTop: 14, borderTopWidth: 1, borderTopColor: colors.inputBorder }}>
              <Text style={{ fontSize: 13, fontWeight: '600', color: colors.text, marginBottom: 8 }}>Maximum per withdrawal</Text>
              {editingMax ? (
                <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                  <TextInput
                    style={[adminInputStyle(colors), { flex: 1, marginBottom: 0, marginRight: 8 }]}
                    placeholder="No limit"
                    placeholderTextColor={colors.subtext}
                    keyboardType="numeric"
                    value={maxAmountInput}
                    onChangeText={setMaxAmountInput}
                    autoFocus
                  />
                  <TouchableOpacity onPress={saveMaxAmount} disabled={settingsBusy}>
                    <Ionicons name="checkmark-circle" size={28} color="#059669" />
                  </TouchableOpacity>
                </View>
              ) : (
                <TouchableOpacity onPress={() => setEditingMax(true)} style={{ flexDirection: 'row', alignItems: 'center' }}>
                  <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 15, marginRight: 8 }}>
                    {settings.maxAmount !== null ? `₦${settings.maxAmount.toLocaleString()}` : 'No limit'}
                  </Text>
                  <Ionicons name="pencil" size={14} color={colors.subtext} />
                </TouchableOpacity>
              )}
            </View>
          </View>
        )}
      </View>

      <ScrollView horizontal showsHorizontalScrollIndicator={false} style={{ paddingHorizontal: 20, marginTop: 4, flexGrow: 0 }}>
        {[{ key: 'pending_review', label: 'Pending' }, { key: 'success', label: 'Paid' }, { key: 'failed', label: 'Refunded' }, { key: '', label: 'All' }].map((f) => (
          <TouchableOpacity
            key={f.key || 'all'}
            onPress={() => setFilter(f.key)}
            style={{ paddingHorizontal: 14, paddingVertical: 8, borderRadius: 10, marginRight: 8, backgroundColor: filter === f.key ? colors.accent : colors.iconWrap }}
          >
            <Text style={{ color: filter === f.key ? '#fff' : colors.text, fontWeight: '700', fontSize: 12.5 }}>{f.label}</Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 14 }} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        {loading && <ActivityIndicator color={colors.accent} />}
        {!loading && items.length === 0 && <Text style={{ color: colors.subtext }}>No withdrawals in this view.</Text>}
        {items.map((t) => {
          const st = statusColors[t.status] || { bg: colors.iconWrap, text: colors.subtext, label: t.status?.toUpperCase() };
          return (
            <View key={t.reference} style={adminCardStyle(colors)}>
              <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
                <Text style={{ color: colors.text, fontWeight: '700', fontSize: 14 }}>{naira(t.amount)}</Text>
                <View style={{ backgroundColor: st.bg, borderRadius: 8, paddingHorizontal: 8, paddingVertical: 2 }}>
                  <Text style={{ fontSize: 10.5, fontWeight: '700', color: st.text }}>{st.label}</Text>
                </View>
              </View>
              <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 4 }}>{t.metadata?.accountName} — {t.metadata?.bankCode} ({t.metadata?.accountNumber})</Text>
              <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: 2 }}>{t.users?.full_name || 'Unnamed'} · {t.users?.phone || t.phone}</Text>
              <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 2 }}>{new Date(t.created_at).toLocaleString()} · Ref: {t.reference}</Text>
              {t.metadata?.flwTransferStatus && (
                <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 2 }}>Flutterwave status: {t.metadata.flwTransferStatus}</Text>
              )}
              {t.metadata?.flwComplaint && (
                // Flutterwave's own reason the transfer didn't land (e.g. "Invalid account number",
                // "Insufficient balance in wallet") — captured automatically by the webhook handler
                // and the reconciliation job, shown here so an admin doesn't have to open the
                // Flutterwave dashboard just to see why a withdrawal failed.
                <View style={{ backgroundColor: '#fee2e2', borderRadius: 8, paddingHorizontal: 10, paddingVertical: 6, marginTop: 6 }}>
                  <Text style={{ color: '#991b1b', fontSize: 11.5, fontWeight: '600' }}>Reason: {t.metadata.flwComplaint}</Text>
                </View>
              )}
              {t.metadata?.manualNote && (
                <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 4, fontStyle: 'italic' }}>Admin note: {t.metadata.manualNote}</Text>
              )}

              {t.status === 'pending_review' && (
                resolvingRef === t.reference ? (
                  <View style={{ marginTop: 10 }}>
                    <TextInput
                      style={[adminInputStyle(colors), { marginBottom: 10 }]}
                      placeholder="Note (optional) — e.g. what the Flutterwave dashboard showed"
                      placeholderTextColor={colors.subtext}
                      value={note}
                      onChangeText={setNote}
                      multiline
                    />
                    <View style={{ flexDirection: 'row' }}>
                      <TouchableOpacity style={[adminBtnStyle(colors, 'success'), { flex: 1, marginRight: 8 }]} disabled={busy} onPress={() => resolve(t.reference, 'paid')}>
                        <Text style={{ color: '#fff', fontWeight: 'bold' }}>Mark Paid</Text>
                      </TouchableOpacity>
                      <TouchableOpacity style={[adminBtnStyle(colors, 'danger'), { flex: 1 }]} disabled={busy} onPress={() => resolve(t.reference, 'refund')}>
                        <Text style={{ color: '#fff', fontWeight: 'bold' }}>Refund</Text>
                      </TouchableOpacity>
                    </View>
                    <TouchableOpacity onPress={() => setResolvingRef(null)} style={{ marginTop: 8, alignItems: 'center' }}>
                      <Text style={{ color: colors.subtext, fontSize: 12 }}>Cancel</Text>
                    </TouchableOpacity>
                  </View>
                ) : (
                  <TouchableOpacity onPress={() => startResolving(t.reference)} style={{ marginTop: 10, backgroundColor: colors.iconWrap, borderRadius: 10, paddingVertical: 10, alignItems: 'center' }}>
                    <Text style={{ color: colors.accent, fontWeight: '700', fontSize: 12.5 }}>Review</Text>
                  </TouchableOpacity>
                )
              )}
            </View>
          );
        })}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Account Deletion Requests ───────────────────────────────────────
function AdminAccountDeletionsScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [rejectingId, setRejectingId] = useState(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api('/api/v1/admin/account-deletions', { token });
      setItems(Array.isArray(data) ? data : []);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const approve = (u) => {
    Alert.alert(
      'Delete this account?',
      `This will permanently remove ${u.full_name || u.phone}'s personal data (name, email, phone, BVN/NIN). Transaction history is kept. This cannot be undone.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            setBusy(true);
            try {
              await api(`/api/v1/admin/account-deletions/${u.id}/approve`, { method: 'POST', token, body: {} });
              Alert.alert('Done', 'Account deleted');
              load();
            } catch (e) { Alert.alert('Failed', e.message); }
            setBusy(false);
          },
        },
      ]
    );
  };

  const startRejecting = (id) => { setRejectingId(id); setReason(''); };

  const submitReject = async (id) => {
    if (!reason.trim()) return Alert.alert('Reason required', 'Let the user know why their request was declined.');
    setBusy(true);
    try {
      await api(`/api/v1/admin/account-deletions/${id}/reject`, { method: 'POST', token, body: { reason } });
      Alert.alert('Done', 'Request rejected — the user has been notified');
      setRejectingId(null); setReason('');
      load();
    } catch (e) { Alert.alert('Failed', e.message); }
    setBusy(false);
  };

  const naira = (n) => `₦${(n || 0).toLocaleString()}`;

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Account Deletions" subtitle="Users who've requested to delete their account" onBack={onBack} colors={colors} />

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 14 }} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        {loading && <ActivityIndicator color={colors.accent} />}
        {!loading && items.length === 0 && <Text style={{ color: colors.subtext }}>No pending deletion requests.</Text>}
        {items.map((u) => {
          const balance = parseFloat(u.wallets?.balance || 0);
          return (
            <View key={u.id} style={adminCardStyle(colors)}>
              <Text style={{ color: colors.text, fontWeight: '700', fontSize: 14 }}>{u.full_name || 'Unnamed'}</Text>
              <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 2 }}>{u.phone || '—'} · {u.email || '—'}</Text>
              <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: 4 }}>Requested {new Date(u.deletion_requested_at).toLocaleString()}</Text>
              <Text style={{ color: balance > 0 ? '#dc2626' : colors.subtext, fontSize: 12, marginTop: 4, fontWeight: balance > 0 ? '700' : '400' }}>
                Wallet balance: {naira(balance)}{balance > 0 ? ' — cannot approve until this is zero' : ''}
              </Text>
              {u.deletion_reason ? (
                <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 4, fontStyle: 'italic' }}>"{u.deletion_reason}"</Text>
              ) : null}

              {rejectingId === u.id ? (
                <View style={{ marginTop: 10 }}>
                  <TextInput
                    style={[adminInputStyle(colors), { marginBottom: 10 }]}
                    placeholder="Reason for declining (shown to the user)"
                    placeholderTextColor={colors.subtext}
                    value={reason}
                    onChangeText={setReason}
                    multiline
                  />
                  <View style={{ flexDirection: 'row' }}>
                    <TouchableOpacity style={[adminBtnStyle(colors, 'danger'), { flex: 1, marginRight: 8 }]} disabled={busy} onPress={() => submitReject(u.id)}>
                      <Text style={{ color: '#fff', fontWeight: 'bold' }}>Submit Decline</Text>
                    </TouchableOpacity>
                    <TouchableOpacity onPress={() => setRejectingId(null)} style={{ paddingVertical: 13, paddingHorizontal: 14 }}>
                      <Text style={{ color: colors.subtext, fontSize: 12.5 }}>Cancel</Text>
                    </TouchableOpacity>
                  </View>
                </View>
              ) : (
                <View style={{ flexDirection: 'row', marginTop: 10 }}>
                  <TouchableOpacity
                    style={[adminBtnStyle(colors, 'danger'), { flex: 1, marginRight: 8, opacity: balance > 0 || busy ? 0.5 : 1 }]}
                    disabled={balance > 0 || busy}
                    onPress={() => approve(u)}
                  >
                    <Text style={{ color: '#fff', fontWeight: 'bold' }}>Approve & Delete</Text>
                  </TouchableOpacity>
                  <TouchableOpacity style={[adminBtnStyle(colors), { flex: 1 }]} disabled={busy} onPress={() => startRejecting(u.id)}>
                    <Text style={{ color: '#fff', fontWeight: 'bold' }}>Decline</Text>
                  </TouchableOpacity>
                </View>
              )}
            </View>
          );
        })}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Announcements (banner shown to every user on Home) ─────────────────
function AdminAnnouncementsScreen({ token, onBack }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [message, setMessage] = useState('');
  const [type, setType] = useState('info');
  const [submitting, setSubmitting] = useState(false);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const data = await api('/api/v1/admin/announcements', { token });
      setHistory(Array.isArray(data) ? data : []);
    } catch (e) { /* silent */ }
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const publish = async () => {
    if (!message.trim()) return Alert.alert('Missing message', 'Type what you want every user to see.');
    setSubmitting(true);
    try {
      await api('/api/v1/admin/announcements', { method: 'POST', token, body: { message: message.trim(), type } });
      Alert.alert('Published', 'Every user will see this on Home the next time they load it.');
      setMessage('');
      load();
    } catch (e) { Alert.alert('Failed', e.message); }
    setSubmitting(false);
  };

  const deactivate = async (id) => {
    try {
      await api(`/api/v1/admin/announcements/${id}/deactivate`, { method: 'POST', token });
      load();
    } catch (e) { Alert.alert('Failed', e.message); }
  };

  const typeOptions = [
    { key: 'info', label: 'Info' },
    { key: 'warning', label: 'Warning' },
    { key: 'issue', label: 'Issue' },
  ];

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Announcements" subtitle="Publish a banner every user sees on Home" onBack={onBack} colors={colors} />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 16 }} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        <Text style={{ fontSize: 11, fontWeight: '700', color: colors.subtext, marginBottom: 6 }}>NEW ANNOUNCEMENT</Text>
        <TextInput
          style={[adminInputStyle(colors), { height: 90, textAlignVertical: 'top', paddingTop: 10 }]}
          placeholder="e.g. Cable TV is currently experiencing delays — we're on it."
          placeholderTextColor={colors.subtext}
          value={message}
          onChangeText={setMessage}
          multiline
        />
        <View style={{ flexDirection: 'row', marginTop: 10, marginBottom: 16 }}>
          {typeOptions.map((opt) => (
            <TouchableOpacity
              key={opt.key}
              onPress={() => setType(opt.key)}
              style={{
                paddingVertical: 8, paddingHorizontal: 14, borderRadius: 20, marginRight: 8,
                borderWidth: 1, borderColor: type === opt.key ? colors.accent : colors.inputBorder,
                backgroundColor: type === opt.key ? colors.accent : 'transparent',
              }}
            >
              <Text style={{ color: type === opt.key ? '#fff' : colors.text, fontWeight: '600', fontSize: 12.5 }}>{opt.label}</Text>
            </TouchableOpacity>
          ))}
        </View>
        <TouchableOpacity style={s.loginBtn} onPress={publish} disabled={submitting}>
          {submitting ? <ActivityIndicator color="#fff" /> : <Text style={s.loginBtnText}>Publish to all users</Text>}
        </TouchableOpacity>

        <Text style={{ fontSize: 11, fontWeight: '700', color: colors.subtext, marginTop: 28, marginBottom: 6 }}>HISTORY</Text>
        {loading && <ActivityIndicator color={colors.accent} />}
        {!loading && history.length === 0 && <Text style={{ color: colors.subtext }}>No announcements published yet.</Text>}
        {history.map((a) => (
          <View key={a.id} style={adminCardStyle(colors)}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <Text style={{ flex: 1, color: colors.text, fontSize: 13.5, marginRight: 10 }}>{a.message}</Text>
              <View style={{ backgroundColor: a.active ? '#dcfce7' : colors.iconWrap, borderRadius: 8, paddingHorizontal: 8, paddingVertical: 3 }}>
                <Text style={{ fontSize: 10.5, fontWeight: '700', color: a.active ? '#166534' : colors.subtext }}>{a.active ? 'LIVE' : 'REMOVED'}</Text>
              </View>
            </View>
            <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 6 }}>{a.type} · {new Date(a.created_at).toLocaleString()}</Text>
            {a.active && (
              <TouchableOpacity onPress={() => deactivate(a.id)} style={{ marginTop: 10 }}>
                <Text style={{ color: '#dc2626', fontWeight: '600', fontSize: 12.5 }}>Remove</Text>
              </TouchableOpacity>
            )}
          </View>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Transaction Trace ───────────────────────────────────────────────────
function AdminTransactionTraceScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [reference, setReference] = useState('');
  const [trace, setTrace] = useState(null);
  const [loading, setLoading] = useState(false);

  const search = async () => {
    if (!reference.trim()) return;
    setLoading(true);
    setTrace(null);
    try {
      const data = await api(`/api/v1/admin/transactions/${reference.trim()}/trace`, { token });
      setTrace(data);
    } catch (e) { Alert.alert('Not found', e.message); }
    setLoading(false);
  };

  const naira = (n) => `₦${(n || 0).toLocaleString()}`;

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Transaction Trace" subtitle="Follow one reference: click → gateway → provider → delivery" onBack={onBack} colors={colors} />
      <View style={{ flexDirection: 'row', paddingHorizontal: 20, marginTop: 16 }}>
        <TextInput style={[adminInputStyle(colors), { flex: 1, marginRight: 8, marginBottom: 0 }]} placeholder="Transaction reference" placeholderTextColor={colors.subtext} value={reference} onChangeText={setReference} autoCapitalize="none" onSubmitEditing={search} />
        <TouchableOpacity style={{ backgroundColor: colors.headerBg, borderRadius: 12, width: 48, justifyContent: 'center', alignItems: 'center' }} onPress={search} disabled={loading}>
          {loading ? <ActivityIndicator color="#fff" size="small" /> : <Ionicons name="search" size={20} color="#fff" />}
        </TouchableOpacity>
      </View>
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 14 }} contentContainerStyle={{ paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
        {!trace && !loading && <Text style={{ color: colors.subtext }}>Enter a transaction reference to see its full journey.</Text>}

        {trace && (
          <>
            <View style={adminCardStyle(colors)}>
              <Text style={{ fontSize: 11, fontWeight: '700', color: colors.subtext, marginBottom: 6 }}>TRANSACTION</Text>
              <Text style={{ color: colors.text, fontWeight: 'bold', fontSize: 15 }}>{trace.transaction.category} — {naira(trace.transaction.amount)}</Text>
              <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 4 }}>Status: {trace.transaction.status} · {new Date(trace.transaction.created_at).toLocaleString()}</Text>
            </View>

            <Text style={{ fontSize: 13, fontWeight: '700', color: colors.text, marginTop: 18, marginBottom: 8 }}>Provider Calls ({trace.providerCalls.length})</Text>
            {trace.providerCalls.length === 0 && <Text style={{ color: colors.subtext, fontSize: 12.5 }}>No provider calls logged.</Text>}
            {trace.providerCalls.map((p, i) => (
              <View key={i} style={adminCardStyle(colors)}>
                <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
                  <Text style={{ color: colors.text, fontWeight: '600', fontSize: 13 }}>{p.provider} · {p.service}</Text>
                  <Text style={{ color: p.success ? '#059669' : '#b91c1c', fontWeight: '700', fontSize: 12 }}>{p.success ? 'OK' : 'FAILED'}</Text>
                </View>
                <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 4 }}>{new Date(p.created_at).toLocaleString()}</Text>
              </View>
            ))}

            <Text style={{ fontSize: 13, fontWeight: '700', color: colors.text, marginTop: 18, marginBottom: 8 }}>Failover Events ({trace.failoverEvents.length})</Text>
            {trace.failoverEvents.length === 0 && <Text style={{ color: colors.subtext, fontSize: 12.5 }}>No failover triggered for this transaction.</Text>}
            {trace.failoverEvents.map((f, i) => (
              <View key={i} style={adminCardStyle(colors)}>
                <Text style={{ color: '#d97706', fontWeight: '600', fontSize: 13 }}>{f.from_provider} → {f.to_provider}</Text>
                <Text style={{ color: colors.subtext, fontSize: 12, marginTop: 4 }}>{f.reason}</Text>
              </View>
            ))}
          </>
        )}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin: Commission (your profit from every sale) ───────────────────────
const SERVICE_LABELS = {
  data: 'Data', airtime: 'Airtime', cable: 'Cable TV', electric: 'Electricity',
  exam: 'Exam Pins', recharge_pin: 'Recharge Pin', betting: 'Betting',
};

function AdminCommissionScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [summary, setSummary] = useState(null);
  const [withdrawals, setWithdrawals] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [amount, setAmount] = useState('');
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    try {
      const [summaryData, withdrawalsData] = await Promise.all([
        api('/api/v1/admin/commission', { token }),
        api('/api/v1/admin/commission/withdrawals', { token }),
      ]);
      setSummary(summaryData);
      setWithdrawals(withdrawalsData || []);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const onRefresh = async () => {
    setRefreshing(true);
    await load();
    setRefreshing(false);
  };

  const naira = (n) => `₦${(n || 0).toLocaleString(undefined, { minimumFractionDigits: 2 })}`;

  const totalWithdrawn = withdrawals.reduce((sum, w) => sum + parseFloat(w.amount || 0), 0);
  const available = (summary?.totalCommission || 0) - totalWithdrawn;

  const submitWithdrawal = async () => {
    const amt = parseFloat(amount);
    if (!amt || amt <= 0) return Alert.alert('Error', 'Enter a valid amount');
    if (amt > available) return Alert.alert('Error', `You only have ${naira(available)} available`);
    setSubmitting(true);
    try {
      await api('/api/v1/admin/commission/withdrawals', {
        token,
        method: 'POST',
        body: { amount: amt, note: note || undefined },
      });
      setAmount('');
      setNote('');
      setShowModal(false);
      await load();
      Alert.alert('Recorded', `${naira(amt)} marked as withdrawn.`);
    } catch (e) { Alert.alert('Error', e.message); }
    setSubmitting(false);
  };

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Commission" subtitle="Your profit across every completed sale" onBack={onBack} colors={colors} />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView
        style={{ flex: 1, paddingHorizontal: 20, marginTop: 16 }}
        contentContainerStyle={{ paddingBottom: 40 }}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} colors={[colors.accent]} />}
      >
        {loading && <ActivityIndicator color={colors.accent} />}

        {!loading && summary && (
          <>
            <View style={[adminCardStyle(colors), { alignItems: 'center', paddingVertical: 22 }]}>
              <Text style={{ color: colors.subtext, fontSize: 12.5 }}>Total Commission (All-Time)</Text>
              <Text style={{ color: colors.accent, fontSize: 30, fontWeight: 'bold', marginTop: 6 }}>{naira(summary.totalCommission)}</Text>
              <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: 4 }}>from {summary.transactionCount} successful sales</Text>
            </View>

            <View style={[adminCardStyle(colors), { alignItems: 'center', paddingVertical: 18, marginTop: 12, backgroundColor: '#05966915' }]}>
              <Text style={{ color: colors.subtext, fontSize: 12.5 }}>Available to Withdraw</Text>
              <Text style={{ color: '#059669', fontSize: 24, fontWeight: 'bold', marginTop: 4 }}>{naira(available)}</Text>
              <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 2 }}>{naira(totalWithdrawn)} already withdrawn</Text>
              <TouchableOpacity
                onPress={() => setShowModal(true)}
                style={{ backgroundColor: '#059669', paddingHorizontal: 24, paddingVertical: 10, borderRadius: 8, marginTop: 12 }}
              >
                <Text style={{ color: '#fff', fontWeight: 'bold', fontSize: 13.5 }}>Mark as Withdrawn</Text>
              </TouchableOpacity>
            </View>

            <View style={{ flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'space-between', marginTop: 12 }}>
              <View style={[adminCardStyle(colors), { width: '31%', alignItems: 'center' }]}>
                <Text style={{ color: colors.subtext, fontSize: 11 }}>Today</Text>
                <Text style={{ color: colors.text, fontSize: 14, fontWeight: 'bold', marginTop: 4 }}>{naira(summary.todayCommission)}</Text>
              </View>
              <View style={[adminCardStyle(colors), { width: '31%', alignItems: 'center' }]}>
                <Text style={{ color: colors.subtext, fontSize: 11 }}>This Week</Text>
                <Text style={{ color: colors.text, fontSize: 14, fontWeight: 'bold', marginTop: 4 }}>{naira(summary.weekCommission)}</Text>
              </View>
              <View style={[adminCardStyle(colors), { width: '31%', alignItems: 'center' }]}>
                <Text style={{ color: colors.subtext, fontSize: 11 }}>This Month</Text>
                <Text style={{ color: colors.text, fontSize: 14, fontWeight: 'bold', marginTop: 4 }}>{naira(summary.monthCommission)}</Text>
              </View>
            </View>

            <Text style={{ fontSize: 15, fontWeight: 'bold', color: colors.text, marginTop: 26, marginBottom: 10 }}>By Service</Text>
            {Object.keys(summary.byService || {}).length === 0 && (
              <Text style={{ color: colors.subtext }}>No commission recorded yet.</Text>
            )}
            {Object.entries(summary.byService || {})
              .sort((a, b) => b[1].commission - a[1].commission)
              .map(([service, s], i) => (
                <View key={i} style={[adminCardStyle(colors), { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }]}>
                  <View>
                    <Text style={{ color: colors.text, fontWeight: '600', fontSize: 13.5 }}>{SERVICE_LABELS[service] || service}</Text>
                    <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: 2 }}>{s.count} sales</Text>
                  </View>
                  <Text style={{ color: '#059669', fontWeight: 'bold', fontSize: 14 }}>{naira(s.commission)}</Text>
                </View>
              ))}

            <Text style={{ fontSize: 15, fontWeight: 'bold', color: colors.text, marginTop: 26, marginBottom: 10 }}>Withdrawal History</Text>
            {withdrawals.length === 0 && (
              <Text style={{ color: colors.subtext }}>No withdrawals recorded yet.</Text>
            )}
            {withdrawals.map((w) => (
              <View key={w.id} style={[adminCardStyle(colors), { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }]}>
                <View>
                  <Text style={{ color: colors.text, fontWeight: '600', fontSize: 13.5 }}>{naira(w.amount)}</Text>
                  {!!w.note && <Text style={{ color: colors.subtext, fontSize: 11.5, marginTop: 2 }}>{w.note}</Text>}
                </View>
                <Text style={{ color: colors.subtext, fontSize: 11.5 }}>{new Date(w.created_at).toLocaleDateString()}</Text>
              </View>
            ))}
          </>
        )}
      </ScrollView>
      </KeyboardAvoidingView>

      <Modal visible={showModal} transparent animationType="fade" onRequestClose={() => setShowModal(false)}>
        <View style={{ flex: 1, backgroundColor: '#00000088', justifyContent: 'center', padding: 24 }}>
          <View style={{ backgroundColor: colors.bg, borderRadius: 14, padding: 20 }}>
            <Text style={{ color: colors.text, fontSize: 16, fontWeight: 'bold', marginBottom: 4 }}>Mark as Withdrawn</Text>
            <Text style={{ color: colors.subtext, fontSize: 12, marginBottom: 16 }}>
              Only record this after you've actually sent the money to yourself. Available: {naira(available)}
            </Text>
            <TextInput
              placeholder="Amount (₦)"
              placeholderTextColor={colors.subtext}
              keyboardType="numeric"
              value={amount}
              onChangeText={setAmount}
              style={{ borderWidth: 1, borderColor: colors.inputBorder, borderRadius: 8, padding: 12, color: colors.text, marginBottom: 10 }}
            />
            <TextInput
              placeholder="Note (optional)"
              placeholderTextColor={colors.subtext}
              value={note}
              onChangeText={setNote}
              style={{ borderWidth: 1, borderColor: colors.inputBorder, borderRadius: 8, padding: 12, color: colors.text, marginBottom: 16 }}
            />
            <View style={{ flexDirection: 'row', justifyContent: 'flex-end' }}>
              <TouchableOpacity onPress={() => setShowModal(false)} style={{ paddingHorizontal: 16, paddingVertical: 10 }}>
                <Text style={{ color: colors.subtext, fontWeight: '600' }}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                onPress={submitWithdrawal}
                disabled={submitting}
                style={{ backgroundColor: '#059669', paddingHorizontal: 20, paddingVertical: 10, borderRadius: 8, opacity: submitting ? 0.6 : 1 }}
              >
                <Text style={{ color: '#fff', fontWeight: 'bold' }}>{submitting ? 'Saving...' : 'Confirm'}</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

// ─── Admin: Today's Transactions (list view for the Overview "Txns Today" card) ─
function AdminTodayTransactionsScreen({ token, onBack }) {
  const { colors } = useTheme();
  const [txns, setTxns] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const data = await api('/api/v1/admin/transactions/today', { token });
      setTxns(data.transactions || []);
    } catch (e) { Alert.alert('Error', e.message); }
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const naira = (n) => `₦${Number(n || 0).toLocaleString()}`;

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }}>
      <AdminToolHeader title="Today's Transactions" subtitle={`${txns.length} transaction${txns.length === 1 ? '' : 's'} so far today`} onBack={onBack} colors={colors} />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={{ flex: 1, paddingHorizontal: 20, marginTop: 16 }} contentContainerStyle={{ paddingBottom: 40 }} refreshControl={<RefreshControl refreshing={false} onRefresh={load} colors={[colors.accent]} />}>
        {loading && <ActivityIndicator color={colors.accent} />}
        {!loading && txns.length === 0 && <Text style={{ color: colors.subtext }}>No transactions yet today.</Text>}
        {txns.map((t, i) => (
          <View key={t.id || i} style={adminCardStyle(colors)}>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              <Text style={{ color: colors.text, fontWeight: '700', fontSize: 13.5 }}>
                {t.users?.full_name || t.users?.phone || 'Unknown user'}
              </Text>
              <Text style={{ color: colors.subtext, fontSize: 11 }}>{new Date(t.created_at).toLocaleTimeString()}</Text>
            </View>
            <Text style={{ color: colors.subtext, fontSize: 12.5, marginTop: 4 }}>
              {t.category} · {t.type} · {t.status}
            </Text>
            <Text style={{ color: colors.accent, fontSize: 14, marginTop: 4, fontWeight: '700' }}>{naira(t.amount)}</Text>
            {t.reference && <Text style={{ color: colors.subtext, fontSize: 11, marginTop: 4 }}>Ref: {t.reference}</Text>}
          </View>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Admin Screen (router: hub + tool sub-screens) ─────────────────────────────
function AdminScreen({ token }) {
  const [tool, setTool] = useState(null);
  const back = () => setTool(null);

  if (tool === 'serviceControls') return <AdminServiceControlsScreen token={token} onBack={back} />;
  if (tool === 'providerRouting') return <AdminProviderRoutingScreen token={token} onBack={back} />;
  if (tool === 'walletAdjust') return <AdminWalletAdjustScreen token={token} onBack={back} />;
  if (tool === 'users') return <AdminUsersScreen token={token} onBack={back} />;
  if (tool === 'pricing') return <AdminPricingScreen token={token} onBack={back} />;
  if (tool === 'failoverLog') return <AdminFailoverLogScreen token={token} onBack={back} />;
  if (tool === 'auditLog') return <AdminAuditLogScreen token={token} onBack={back} />;
  if (tool === 'providerLogs') return <AdminProviderLogsScreen token={token} onBack={back} />;
  if (tool === 'reconciler') return <AdminGatewayReconcilerScreen token={token} onBack={back} />;
  if (tool === 'pendingPurchases') return <AdminPendingPurchasesScreen token={token} onBack={back} />;
  if (tool === 'withdrawals') return <AdminWithdrawalsScreen token={token} onBack={back} />;
  if (tool === 'trace') return <AdminTransactionTraceScreen token={token} onBack={back} />;
  if (tool === 'todayTxns') return <AdminTodayTransactionsScreen token={token} onBack={back} />;
  if (tool === 'commission') return <AdminCommissionScreen token={token} onBack={back} />;
  if (tool === 'accountDeletions') return <AdminAccountDeletionsScreen token={token} onBack={back} />;
  if (tool === 'announcements') return <AdminAnnouncementsScreen token={token} onBack={back} />;

  return <AdminOverview token={token} onOpenTool={setTool} />;
}

// ─── Admin Overview (original dashboard: provider switch, totals, airtime-to-cash) ─
function AdminOverview({ token, onOpenTool }) {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [overview, setOverview] = useState(null);
  const [networkTotals, setNetworkTotals] = useState({});
  const [pendingRequests, setPendingRequests] = useState([]);
  const [activeProvider, setActiveProvider] = useState(null);
  const [switchingProvider, setSwitchingProvider] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const loadAll = useCallback(async () => {
    try {
      const [ov, nt, pr, pv] = await Promise.all([
        api('/api/v1/admin/overview', { token }),
        api('/api/v1/admin/airtime-to-cash/network-totals', { token }),
        api('/api/v1/admin/airtime-to-cash/pending', { token }),
        api('/api/v1/admin/provider', { token }),
      ]);
      setOverview(ov);
      setNetworkTotals(nt);
      setPendingRequests(pr);
      setActiveProvider(pv.active);
    } catch (e) {
      Alert.alert('Error loading admin data', e.message);
    }
  }, [token]);

  useEffect(() => { loadAll(); }, [loadAll]);

  const onRefresh = async () => {
    setRefreshing(true);
    await loadAll();
    setRefreshing(false);
  };

  const handleAction = (action, reference) => {
    const titles = { approve: 'Send payout now?', 'mark-paid': 'Mark as paid?', reject: 'Reject request?' };
    const messages = {
      approve: 'This will send the payout automatically via Flutterwave transfer. Only do this after confirming the airtime has arrived.',
      'mark-paid': 'Confirm you have sent the payout via Flutterwave dashboard before marking paid.',
      reject: 'This will reject the airtime-to-cash request.',
    };
    Alert.alert(
      titles[action],
      messages[action],
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Confirm',
          style: action === 'reject' ? 'destructive' : 'default',
          onPress: async () => {
            try {
              await api(`/api/v1/admin/airtime-to-cash/${reference}/${action}`, { method: 'POST', token, body: {} });
              Alert.alert('Done', action === 'approve' ? 'Payout initiated via Flutterwave' : action === 'mark-paid' ? 'Request marked as paid' : 'Request rejected');
              loadAll();
            } catch (e) {
              Alert.alert('Failed', e.message);
            }
          },
        },
      ]
    );
  };

  const switchProvider = (provider) => {
    if (provider === activeProvider || switchingProvider) return;
    Alert.alert(
      'Switch VTU Provider?',
      `All new data/airtime purchases will start going through ${provider === 'klubconnect' ? 'KlubConnect' : 'Bigisub'} immediately.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Switch',
          onPress: async () => {
            setSwitchingProvider(true);
            try {
              const data = await api('/api/v1/admin/provider', { method: 'POST', token, body: { provider } });
              setActiveProvider(data.active);
            } catch (e) {
              Alert.alert('Could not switch provider', e.message);
            } finally {
              setSwitchingProvider(false);
            }
          },
        },
      ]
    );
  };

  const naira = (n) => `₦${(n || 0).toLocaleString()}`;

  if (!overview) {
    return (
      <SafeAreaView style={[s.safeArea, { justifyContent: 'center', alignItems: 'center' }]}>
        <ActivityIndicator color={colors.accent} size="large" />
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safeArea}>
      <View style={[s.header, { paddingBottom: 20 }]}>
        <Text style={s.nameText}>Admin Dashboard</Text>
        <Text style={s.greetingText}>Live data</Text>
      </View>

      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView style={s.body} contentContainerStyle={{ paddingBottom: 40 }} refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} colors={[colors.accent]} />}>
        <Text style={s.sectionTitle}>VTU Provider</Text>
        <View style={s.providerCard}>
          <Text style={s.providerHint}>All data/airtime purchases route through the active provider.</Text>
          <View style={{ flexDirection: 'row', marginTop: 12 }}>
            <TouchableOpacity
              style={[s.providerPill, { borderColor: colors.accent, backgroundColor: activeProvider === 'bigisub' ? colors.accent : 'transparent', marginRight: 10 }]}
              onPress={() => switchProvider('bigisub')}
              disabled={switchingProvider}
            >
              <Text style={{ color: activeProvider === 'bigisub' ? '#fff' : colors.text, fontWeight: '700' }}>Bigisub</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[s.providerPill, { borderColor: colors.accent, backgroundColor: activeProvider === 'klubconnect' ? colors.accent : 'transparent' }]}
              onPress={() => switchProvider('klubconnect')}
              disabled={switchingProvider}
            >
              <Text style={{ color: activeProvider === 'klubconnect' ? '#fff' : colors.text, fontWeight: '700' }}>KlubConnect</Text>
            </TouchableOpacity>
            {switchingProvider && <ActivityIndicator color={colors.accent} style={{ marginLeft: 12 }} />}
          </View>
        </View>

        <Text style={[s.sectionTitle, { marginTop: 24 }]}>Admin Tools</Text>
        {[
          { key: 'serviceControls', icon: 'power-outline', label: 'Service Controls', hint: 'Kill-switch per network/service' },
          { key: 'providerRouting', icon: 'git-branch-outline', label: 'Provider Routing', hint: 'Pin network+service to a provider' },
          { key: 'walletAdjust', icon: 'cash-outline', label: 'Wallet Adjustment', hint: 'Manual credit/debit with audit log' },
          { key: 'users', icon: 'people-outline', label: 'User Management', hint: 'Search, freeze/block, set tier' },
          { key: 'pricing', icon: 'pricetag-outline', label: 'Pricing & Margins', hint: 'Global and per-tier markups' },
          { key: 'failoverLog', icon: 'swap-horizontal-outline', label: 'Failover Log', hint: 'Automatic provider switch history' },
          { key: 'auditLog', icon: 'shield-checkmark-outline', label: 'Audit Log', hint: 'Every admin action — who, what, when' },
          { key: 'providerLogs', icon: 'document-text-outline', label: 'Provider API Logs', hint: 'Raw request/response payloads' },
          { key: 'reconciler', icon: 'git-compare-outline', label: 'Gateway Reconciler', hint: 'Match webhooks to wallets' },
          { key: 'pendingPurchases', icon: 'alert-circle-outline', label: 'Pending Purchases', hint: 'Ambiguous provider failures — confirm or refund' },
          { key: 'withdrawals', icon: 'arrow-redo-outline', label: 'Wallet Withdrawals', hint: 'Bank payouts — confirm settled or refund' },
          { key: 'trace', icon: 'search-outline', label: 'Transaction Trace', hint: 'Full journey for one reference' },
          { key: 'commission', icon: 'trending-up-outline', label: 'Commission', hint: 'Your total profit across every sale' },
          { key: 'accountDeletions', icon: 'trash-outline', label: 'Account Deletions', hint: 'Review and approve/decline deletion requests' },
          { key: 'announcements', icon: 'megaphone-outline', label: 'Announcements', hint: 'Publish a banner every user sees on Home' },
        ].map((tool) => (
          <TouchableOpacity
            key={tool.key}
            onPress={() => onOpenTool(tool.key)}
            style={{ backgroundColor: colors.card, borderRadius: 14, padding: 14, marginBottom: 10, flexDirection: 'row', alignItems: 'center', borderWidth: 1, borderColor: colors.inputBorder }}
          >
            <View style={{ backgroundColor: colors.iconWrap, width: 42, height: 42, borderRadius: 12, justifyContent: 'center', alignItems: 'center', marginRight: 12 }}>
              <Ionicons name={tool.icon} size={20} color={colors.accent} />
            </View>
            <View style={{ flex: 1 }}>
              <Text style={{ fontSize: 14, fontWeight: 'bold', color: colors.text }}>{tool.label}</Text>
              <Text style={{ fontSize: 11.5, color: colors.subtext, marginTop: 1 }}>{tool.hint}</Text>
            </View>
            <Ionicons name="chevron-forward" size={18} color={colors.subtext} />
          </TouchableOpacity>
        ))}

        <Text style={[s.sectionTitle, { marginTop: 24 }]}>Overview</Text>
        <View style={s.overviewRow}>
          <TouchableOpacity style={s.overviewCard} onPress={() => onOpenTool('users')}>
            <Text style={s.overviewLabel}>Wallet Balances</Text>
            <Text style={s.overviewValue}>{naira(overview.totalWalletBalance)}</Text>
          </TouchableOpacity>
          <TouchableOpacity style={s.overviewCard} onPress={() => onOpenTool('users')}>
            <Text style={s.overviewLabel}>Users</Text>
            <Text style={s.overviewValue}>{overview.totalUsers}</Text>
          </TouchableOpacity>
          <TouchableOpacity style={s.overviewCard} onPress={() => onOpenTool('todayTxns')}>
            <Text style={s.overviewLabel}>Txns Today</Text>
            <Text style={s.overviewValue}>{overview.transactionsToday}</Text>
          </TouchableOpacity>
        </View>

        <Text style={[s.sectionTitle, { marginTop: 24 }]}>Airtime Per Network</Text>
        {Object.entries(networkTotals).map(([network, n], i) => (
          <View key={i} style={s.networkCard}>
            <View style={s.networkHeader}>
              <Text style={s.networkName}>{network}</Text>
              <Text style={s.networkCollected}>{naira(n.collectedAirtime)} collected</Text>
            </View>
            {n.pendingAirtime > 0 && <Text style={s.networkPending}>{naira(n.pendingAirtime)} pending confirmation</Text>}
          </View>
        ))}

        <Text style={[s.sectionTitle, { marginTop: 24 }]}>Pending Airtime-to-Cash ({pendingRequests.length})</Text>
        {pendingRequests.length === 0 && <Text style={{ color: colors.subtext, marginBottom: 20 }}>No pending requests right now.</Text>}
        {pendingRequests.map((r, i) => (
          <View key={i} style={s.requestCard}>
            <View style={s.requestTop}>
              <Text style={s.requestNetwork}>{r.metadata?.network} — {naira(r.metadata?.airtimeAmount)}</Text>
              <Text style={s.requestCash}>Payout: {naira(r.metadata?.cashAmount)}</Text>
            </View>
            <Text style={s.requestPhone}>From: {r.phone}</Text>
            <Text style={s.requestPhone}>To: {r.metadata?.payoutAccountName} — {r.metadata?.payoutAccountNumber} ({r.metadata?.payoutBankCode})</Text>
            <View style={s.requestActions}>
              <TouchableOpacity style={[s.actionBtn, s.approveBtn]} onPress={() => handleAction('approve', r.reference)}>
                <Text style={s.actionBtnText}>Approve (Auto)</Text>
              </TouchableOpacity>
              <TouchableOpacity style={[s.actionBtn, s.approveBtn]} onPress={() => handleAction('mark-paid', r.reference)}>
                <Text style={s.actionBtnText}>Mark Paid</Text>
              </TouchableOpacity>
              <TouchableOpacity style={[s.actionBtn, s.rejectBtn]} onPress={() => handleAction('reject', r.reference)}>
                <Text style={[s.actionBtnText, { color: '#b91c1c' }]}>Reject</Text>
              </TouchableOpacity>
            </View>
          </View>
        ))}
      </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// ─── Auth Flow Wrapper ──────────────────────────────────────────────────────
function AuthFlow({ onLoggedIn }) {
  const [screen, setScreen] = useState('login');
  const [pendingPhone, setPendingPhone] = useState('');
  const [devOtp, setDevOtp] = useState(null);
  const [resetIdentifier, setResetIdentifier] = useState('');
  const [resetUserId, setResetUserId] = useState(null);
  const [resetMethod, setResetMethod] = useState('sms');
  const [resetToken, setResetToken] = useState(null);
  const [legalDoc, setLegalDoc] = useState(null); // 'terms' | 'privacy' | null
  const [preLegalScreen, setPreLegalScreen] = useState('signup');

  if (legalDoc) {
    return (
      <LegalDocScreen
        title={legalDoc === 'terms' ? 'Terms of Service' : 'Privacy Policy'}
        text={legalDoc === 'terms' ? TERMS_OF_SERVICE_TEXT : PRIVACY_POLICY_TEXT}
        onBack={() => { setLegalDoc(null); setScreen(preLegalScreen); }}
      />
    );
  }

  if (screen === 'signup') {
    return (
      <SignupScreen
        onSwitchToLogin={() => setScreen('login')}
        onRegistered={(phone, otp) => { setPendingPhone(phone); setDevOtp(otp); setScreen('verify'); }}
        onOpenLegal={(doc) => { setPreLegalScreen('signup'); setLegalDoc(doc); }}
      />
    );
  }
  if (screen === 'verify') {
    return <VerifyScreen phone={pendingPhone} devOtp={devOtp} onBack={() => setScreen('signup')} onVerified={onLoggedIn} />;
  }
  if (screen === 'forgot') {
    return (
      <ForgotPasswordScreen
        onBack={() => setScreen('login')}
        onCodeSent={(identifier, userId, method) => { setResetIdentifier(identifier); setResetUserId(userId); setResetMethod(method); setScreen('resetVerify'); }}
      />
    );
  }
  if (screen === 'resetVerify') {
    return (
      <VerifyResetCodeScreen
        identifier={resetIdentifier}
        userId={resetUserId}
        method={resetMethod}
        onBack={() => setScreen('forgot')}
        onVerified={(token) => { setResetToken(token); setScreen('resetPassword'); }}
      />
    );
  }
  if (screen === 'resetPassword') {
    return <ResetPasswordScreen resetToken={resetToken} onDone={() => setScreen('login')} />;
  }
  return (
    <LoginScreen
      onLoggedIn={onLoggedIn}
      onSwitchToSignup={() => setScreen('signup')}
      onForgotPassword={() => setScreen('forgot')}
    />
  );
}

// ─── Root App ───────────────────────────────────────────────────────────────
// ─── Biometric Lock Screen ──────────────────────────────────────────────────
// Shown after a saved session is restored, before any wallet/account content
// is rendered, when the user has biometric login switched on.
function BiometricLockScreen({ label, onUnlocked, onFallbackLogout }) {
  const { colors } = useTheme();
  const [checking, setChecking] = useState(false);
  const [failed, setFailed] = useState(false);

  const tryUnlock = useCallback(async () => {
    setChecking(true);
    setFailed(false);
    try {
      const success = await promptBiometricUnlock(`Unlock Gora with ${label}`);
      if (success) onUnlocked();
      else setFailed(true);
    } catch (e) {
      setFailed(true);
    } finally {
      setChecking(false);
    }
  }, [label, onUnlocked]);

  useEffect(() => { tryUnlock(); }, []);

  return (
    <View style={{ flex: 1, backgroundColor: colors.bg, justifyContent: 'center', alignItems: 'center', paddingHorizontal: 32 }}>
      <View style={{ backgroundColor: colors.headerBg, width: 76, height: 76, borderRadius: 22, justifyContent: 'center', alignItems: 'center', marginBottom: 20 }}>
        <Ionicons name={label === 'Face ID' ? 'scan-outline' : 'finger-print-outline'} size={36} color="#fff" />
      </View>
      <Text style={{ fontSize: 18, fontWeight: 'bold', color: colors.text, marginBottom: 6 }}>Gora is locked</Text>
      <Text style={{ fontSize: 13.5, color: colors.subtext, textAlign: 'center', marginBottom: 28 }}>
        {checking ? `Waiting for ${label}…` : failed ? `${label} didn't confirm — try again` : `Use ${label} to continue`}
      </Text>

      <TouchableOpacity
        onPress={tryUnlock}
        disabled={checking}
        style={{ backgroundColor: colors.headerBg, borderRadius: 12, paddingVertical: 14, paddingHorizontal: 28, opacity: checking ? 0.7 : 1 }}
      >
        <Text style={{ color: '#fff', fontWeight: 'bold', fontSize: 15 }}>{checking ? 'Checking…' : `Unlock with ${label}`}</Text>
      </TouchableOpacity>

      <TouchableOpacity onPress={onFallbackLogout} style={{ marginTop: 18 }}>
        <Text style={{ color: colors.subtext, fontSize: 13, textDecorationLine: 'underline' }}>Log out instead</Text>
      </TouchableOpacity>
    </View>
  );
}

function AppInner() {
  const { colors } = useTheme();
  const s = makeStyles(colors);
  const [booting, setBooting] = useState(true);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [biometricGate, setBiometricGate] = useState(null); // null = not needed, or { label }
  const [activeTab, setActiveTab] = useState('Home');
  const [openService, setOpenService] = useState(null);
  const [walletRefreshKey, setWalletRefreshKey] = useState(0);
  const [unreadCount, setUnreadCount] = useState(0);

  const refreshUser = useCallback(async () => {
    try {
      const me = await api('/api/v1/auth/me', { token: currentAccessToken });
      setUser(me);
    } catch (e) {}
  }, []);

  useEffect(() => {
    // Keep the "token" prop (still threaded through screens for backward
    // compatibility) in sync whenever the background refresh mints a new one.
    setOnTokenUpdated((t) => setToken(t));
    // If the refresh token itself is invalid/expired, there's nothing left
    // to do but sign the user out cleanly instead of leaving them stuck on
    // silently-failing screens.
    setOnAuthExpired(() => { handleLogout(); });
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const savedToken = await AsyncStorage.getItem('accessToken');
        const savedRefreshToken = await AsyncStorage.getItem('refreshToken');
        if (savedToken) {
          setApiTokens(savedToken, savedRefreshToken);
          const me = await api('/api/v1/auth/me', { token: savedToken });
          setUser(me);
          setToken(currentAccessToken);
          registerForPushNotificationsAsync(currentAccessToken);

          // Gate access behind Face ID / fingerprint if the user turned this on.
          // Only applies to a *restored* session (app relaunch / backgrounding),
          // not a fresh login — entering the password is already an auth step.
          const bioEnabled = await isBiometricLoginEnabled();
          if (bioEnabled) {
            const { available, label } = await getBiometricSupport();
            if (available) setBiometricGate({ label });
          }
        }
      } catch (e) {
        await AsyncStorage.removeItem('accessToken');
        await AsyncStorage.removeItem('refreshToken');
        setApiTokens(null, null);
      } finally {
        setBooting(false);
      }
    })();
  }, []);

  const loadUnreadCount = useCallback(async (t) => {
    if (!t) return;
    try {
      const data = await api('/api/v1/notifications/unread-count', { token: t });
      setUnreadCount(data?.count ?? data?.unreadCount ?? (typeof data === 'number' ? data : 0));
    } catch (e) {
      // notifications badge is non-critical — fail silently
    }
  }, []);

  useEffect(() => {
    if (token) loadUnreadCount(token);
  }, [token, loadUnreadCount]);

  useEffect(() => {
    const receivedSub = Notifications.addNotificationReceivedListener(() => {
      if (token) loadUnreadCount(token);
    });
    const responseSub = Notifications.addNotificationResponseReceivedListener(() => {
      setOpenService('notifications');
    });
    return () => {
      receivedSub.remove();
      responseSub.remove();
    };
  }, [token, loadUnreadCount]);

  useEffect(() => {
    if (!user || !token) return; // only handle back button once inside the main app (post-login)
    const onHardwareBack = () => {
      if (openService) {
        setOpenService(null);
        return true; // handled — don't let Android exit the app
      }
      if (activeTab !== 'Home') {
        setActiveTab('Home');
        return true;
      }
      return false; // on the Home root tab — let the OS handle it (exits/backgrounds the app, normal behavior)
    };
    const sub = BackHandler.addEventListener('hardwareBackPress', onHardwareBack);
    return () => sub.remove();
  }, [user, token, openService, activeTab]);

  const handleLoggedIn = (u, t, refreshT) => {
    setApiTokens(t, refreshT);
    setUser(u);
    setToken(t);
    registerForPushNotificationsAsync(t);
  };

  const handleLogout = async () => {
    const savedRefreshToken = await AsyncStorage.getItem('refreshToken');
    if (savedRefreshToken) {
      try { await api('/api/v1/auth/logout', { method: 'POST', body: { refreshToken: savedRefreshToken } }); }
      catch (e) { /* best-effort — still clear local session below even if the network call fails */ }
    }
    await AsyncStorage.removeItem('accessToken');
    await AsyncStorage.removeItem('refreshToken');
    setApiTokens(null, null);
    setUser(null);
    setToken(null);
    setActiveTab('Home');
    setOpenService(null);
  };

  if (booting) {
    return (
      <View style={[s.safeArea, { justifyContent: 'center', alignItems: 'center' }]}>
        <ActivityIndicator color={colors.accent} size="large" />
      </View>
    );
  }

  if (!user || !token) {
    return <AuthFlow onLoggedIn={handleLoggedIn} />;
  }

  if (biometricGate) {
    return (
      <BiometricLockScreen
        label={biometricGate.label}
        onUnlocked={() => setBiometricGate(null)}
        onFallbackLogout={handleLogout}
      />
    );
  }

  if (openService === 'data') {
    return (
      <DataScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'airtime') {
    return (
      <AirtimeScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'electric') {
    return (
      <ElectricityScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'cable') {
    return (
      <CableScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'isp') {
    return (
      <ISPScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'social') {
    return (
      <SocialBoostScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'sms') {
    return (
      <BulkSmsScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'exam') {
    return (
      <ExamScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'jamb') {
    return (
      <JambScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'recharge') {
    return (
      <RechargePinScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'a2c') {
    return (
      <AirtimeToCashScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
      />
    );
  }

  if (openService === 'betting') {
    return (
      <BettingScreen
        token={token}
        user={user}
        onBack={() => setOpenService(null)}
        onWalletChanged={() => setWalletRefreshKey((k) => k + 1)}
      />
    );
  }

  if (openService === 'referral') {
    return (
      <ReferralScreen
        token={token}
        onBack={() => setOpenService(null)}
      />
    );
  }

  if (openService === 'transactions') {
    return (
      <TransactionsScreen
        token={token}
        onBack={() => setOpenService(null)}
      />
    );
  }

  if (openService === 'notifications') {
    return (
      <NotificationsScreen
        token={token}
        onBack={() => { setOpenService(null); loadUnreadCount(token); }}
        onUnreadChanged={() => loadUnreadCount(token)}
      />
    );
  }

  if (openService === 'settings') {
    return (
      <SettingsScreen
        user={user}
        onBack={() => setOpenService(null)}
        onNavigate={(key) => setOpenService(key)}
        onLogout={handleLogout}
      />
    );
  }

  if (openService === 'changePhone') {
    return (
      <ChangePhoneScreen
        token={token}
        currentPhone={user?.phone}
        onBack={() => setOpenService('settings')}
        onChanged={(newPhone) => {
          setUser((prev) => ({ ...prev, phone: newPhone }));
          setOpenService('settings');
        }}
      />
    );
  }

  if (openService === 'changeEmail') {
    return (
      <ChangeEmailScreen
        token={token}
        currentEmail={user?.email}
        onBack={() => setOpenService('settings')}
        onChanged={(newEmail) => {
          setUser((prev) => ({ ...prev, email: newEmail }));
          setOpenService('settings');
        }}
      />
    );
  }

  if (openService === 'changePassword') {
    return (
      <ChangePasswordScreen
        token={token}
        onBack={() => setOpenService('settings')}
      />
    );
  }

  if (openService === 'transactionPin') {
    return (
      <ChangePinScreen
        token={token}
        user={user}
        onBack={() => setOpenService('settings')}
        onForgotPin={() => setOpenService('forgotPin')}
      />
    );
  }

  if (openService === 'forgotPin') {
    return (
      <ForgotPinScreen
        token={token}
        user={user}
        onBack={() => setOpenService('transactionPin')}
        onReset={() => setOpenService('settings')}
      />
    );
  }

  if (openService === 'support') {
    return <SupportScreen onBack={() => setOpenService('settings')} />;
  }

  if (openService === 'terms') {
    return <LegalDocScreen title="Terms of Service" text={TERMS_OF_SERVICE_TEXT} onBack={() => setOpenService('settings')} />;
  }

  if (openService === 'privacy') {
    return <LegalDocScreen title="Privacy Policy" text={PRIVACY_POLICY_TEXT} onBack={() => setOpenService('settings')} />;
  }

  if (openService === 'deleteAccount') {
    return <DeleteAccountScreen token={token} onBack={() => setOpenService('settings')} onLogout={handleLogout} />;
  }

  return (
    <View style={{ flex: 1 }}>
      {activeTab === 'Home' ? (
        <HomeScreen key={walletRefreshKey} user={user} token={token} onOpenService={setOpenService} unreadCount={unreadCount} onUserRefresh={refreshUser} />
      ) : (
        <AdminScreen token={token} />
      )}

      <View style={s.tabBar}>
        <TouchableOpacity style={s.tabBtn} onPress={() => setActiveTab('Home')}>
          <Ionicons name="home" size={24} color={activeTab === 'Home' ? colors.accent : colors.inactiveTab} />
          <Text style={[s.tabLabel, { color: activeTab === 'Home' ? colors.accent : colors.inactiveTab }]}>Home</Text>
        </TouchableOpacity>
        {user.role === 'admin' && (
          <TouchableOpacity style={s.tabBtn} onPress={() => setActiveTab('Admin')}>
            <Ionicons name="shield-checkmark" size={24} color={activeTab === 'Admin' ? colors.accent : colors.inactiveTab} />
            <Text style={[s.tabLabel, { color: activeTab === 'Admin' ? colors.accent : colors.inactiveTab }]}>Admin</Text>
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
}

// ─── Error boundary ─────────────────────────────────────────────────────────
// React error boundaries can only be class components — hooks can't catch
// render errors. Without this, any screen that throws during render white-
// screens the whole app instead of showing just that screen failed. Reports
// the crash to Sentry (if configured above) and shows a recoverable screen
// instead of a blank one.
class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }
  static getDerivedStateFromError() {
    return { hasError: true };
  }
  componentDidCatch(error, errorInfo) {
    Sentry.captureException(error, { extra: { componentStack: errorInfo?.componentStack } });
  }
  handleReset = () => {
    this.setState({ hasError: false });
  };
  render() {
    if (this.state.hasError) {
      return (
        <SafeAreaView style={{ flex: 1, backgroundColor: '#fff', justifyContent: 'center', alignItems: 'center', padding: 24 }}>
          <Ionicons name="alert-circle-outline" size={48} color="#dc2626" />
          <Text style={{ fontSize: 17, fontWeight: '700', marginTop: 16, textAlign: 'center' }}>Something went wrong</Text>
          <Text style={{ fontSize: 13, color: '#6b7280', marginTop: 8, textAlign: 'center' }}>
            This screen ran into a problem. It's been reported automatically.
          </Text>
          <TouchableOpacity
            onPress={this.handleReset}
            style={{ backgroundColor: '#4f46e5', paddingHorizontal: 24, paddingVertical: 12, borderRadius: 10, marginTop: 20 }}
          >
            <Text style={{ color: '#fff', fontWeight: '600' }}>Try Again</Text>
          </TouchableOpacity>
        </SafeAreaView>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <AppErrorBoundary>
      <ThemeProvider>
        <AppInner />
        <TransactionPinModalHost />
      </ThemeProvider>
    </AppErrorBoundary>
  );
}

// ─── Styles (theme-aware) ───────────────────────────────────────────────────
function makeStyles(colors) {
  return StyleSheet.create({
    safeArea: { flex: 1, backgroundColor: colors.bg },
    header: { backgroundColor: colors.headerBg, paddingHorizontal: 20, paddingTop: 20, paddingBottom: 30, borderBottomLeftRadius: 24, borderBottomRightRadius: 24 },
    headerTop: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start' },
    greetingRow: { flexDirection: 'row', alignItems: 'center' },
    greetingText: { color: '#fff', fontSize: 15, marginLeft: 6, opacity: 0.9 },
    nameText: { color: '#fff', fontSize: 22, fontWeight: 'bold', marginTop: 4 },
    notifBtn: { backgroundColor: 'rgba(255,255,255,0.15)', padding: 10, borderRadius: 12 },
    notifBadge: { position: 'absolute', top: -4, right: -4, backgroundColor: '#dc2626', borderRadius: 9, minWidth: 18, height: 18, justifyContent: 'center', alignItems: 'center', paddingHorizontal: 4 },
    notifBadgeText: { color: '#fff', fontSize: 10, fontWeight: 'bold' },
    walletCard: { backgroundColor: colors.overlay, borderRadius: 18, padding: 18, marginTop: 24 },
    walletLabel: { color: '#e0e7ff', fontSize: 13 },
    walletAmount: { color: '#fff', fontSize: 32, fontWeight: 'bold', marginTop: 4 },
    fundBtn: { backgroundColor: '#fff', alignSelf: 'flex-start', paddingHorizontal: 16, paddingVertical: 8, borderRadius: 10, marginTop: 14 },
    fundBtnText: { color: colors.headerBg, fontWeight: '600' },
    body: { flex: 1, paddingHorizontal: 20, marginTop: 16 },
    sectionTitle: { fontSize: 17, fontWeight: 'bold', color: colors.text, marginBottom: 14 },
    grid: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'space-between' },
    serviceCard: { width: '23%', alignItems: 'center', marginBottom: 20 },
    serviceIconWrap: { backgroundColor: colors.iconWrap, width: 54, height: 54, borderRadius: 16, justifyContent: 'center', alignItems: 'center' },
    serviceLabel: { fontSize: 11, color: colors.text, marginTop: 6, textAlign: 'center' },

    notifCard: { backgroundColor: colors.card, borderRadius: 14, padding: 14, marginBottom: 10, flexDirection: 'row', alignItems: 'flex-start', borderWidth: 1, borderColor: colors.inputBorder },
    notifIconWrap: { width: 40, height: 40, borderRadius: 12, justifyContent: 'center', alignItems: 'center', marginRight: 12 },
    notifTitle: { fontSize: 14.5, fontWeight: 'bold', color: colors.text },
    notifMessage: { fontSize: 13, color: colors.subtext, marginTop: 3, lineHeight: 18 },
    notifTime: { fontSize: 11, color: colors.subtext, marginTop: 6 },
    notifDot: { width: 8, height: 8, borderRadius: 4, backgroundColor: colors.accent, marginLeft: 8, marginTop: 4 },
    txnCard: { backgroundColor: colors.card, borderRadius: 14, padding: 14, marginBottom: 10, flexDirection: 'row', alignItems: 'center', borderWidth: 1, borderColor: colors.inputBorder },

    providerCard: { backgroundColor: colors.card, borderRadius: 14, padding: 16, elevation: 1 },
    providerHint: { color: colors.subtext, fontSize: 12.5, lineHeight: 18 },
    providerPill: { borderWidth: 2, borderRadius: 12, paddingVertical: 10, paddingHorizontal: 18 },

    overviewRow: { flexDirection: 'row', justifyContent: 'space-between' },
    overviewCard: { backgroundColor: colors.card, borderRadius: 14, padding: 14, width: '31%', elevation: 1 },
    overviewLabel: { fontSize: 11, color: colors.subtext },
    overviewValue: { fontSize: 16, fontWeight: 'bold', color: colors.text, marginTop: 6 },

    networkCard: { backgroundColor: colors.card, borderRadius: 14, padding: 14, marginBottom: 10, elevation: 1 },
    networkHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
    networkName: { fontSize: 15, fontWeight: 'bold', color: colors.text },
    networkCollected: { fontSize: 13, color: '#059669', fontWeight: '600' },
    networkPending: { fontSize: 12, color: '#d97706', marginTop: 4 },

    requestCard: { backgroundColor: colors.card, borderRadius: 14, padding: 14, marginBottom: 10, elevation: 1 },
    requestTop: { flexDirection: 'row', justifyContent: 'space-between' },
    requestNetwork: { fontSize: 14, fontWeight: 'bold', color: colors.text },
    requestCash: { fontSize: 13, color: colors.accent, fontWeight: '600' },
    requestPhone: { fontSize: 12, color: colors.subtext, marginTop: 4 },
    requestActions: { flexDirection: 'row', flexWrap: 'wrap', marginTop: 12 },
    actionBtn: { paddingVertical: 8, paddingHorizontal: 16, borderRadius: 10, marginRight: 10, marginBottom: 8 },
    approveBtn: { backgroundColor: colors.iconWrap },
    rejectBtn: { backgroundColor: '#fee2e2' },
    actionBtnText: { fontWeight: '600', color: colors.accent, fontSize: 13 },

    tabBar: { flexDirection: 'row', backgroundColor: colors.tabBg, borderTopWidth: 1, borderTopColor: colors.tabBorder, paddingBottom: 20, paddingTop: 10 },
    tabBtn: { flex: 1, alignItems: 'center' },
    tabLabel: { fontSize: 11, marginTop: 2, fontWeight: '600' },

    loginWrap: { flex: 1, justifyContent: 'center', paddingHorizontal: 28 },
    loginLogoWrap: { backgroundColor: colors.headerBg, width: 70, height: 70, borderRadius: 20, justifyContent: 'center', alignItems: 'center', alignSelf: 'center', marginBottom: 16 },
    loginTitle: { fontSize: 26, fontWeight: 'bold', color: colors.text, textAlign: 'center' },
    loginSubtitle: { fontSize: 14, color: colors.subtext, textAlign: 'center', marginTop: 4, marginBottom: 30 },
    input: { backgroundColor: colors.inputBg, borderRadius: 12, paddingHorizontal: 16, paddingVertical: 14, fontSize: 15, marginBottom: 14, borderWidth: 1, borderColor: colors.inputBorder, color: colors.text },
    loginBtn: { backgroundColor: colors.headerBg, borderRadius: 12, paddingVertical: 15, alignItems: 'center', marginTop: 6 },
    loginBtnText: { color: '#fff', fontWeight: 'bold', fontSize: 15 },

    modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.4)', justifyContent: 'flex-end' },
    modalCard: { backgroundColor: colors.card, borderTopLeftRadius: 24, borderTopRightRadius: 24, padding: 24, paddingBottom: 40 },
    modalHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 },
    modalTitle: { fontSize: 18, fontWeight: 'bold', color: colors.text },
    modalHint: { color: colors.subtext, fontSize: 13, marginBottom: 16, lineHeight: 19 },
    vaCard: { backgroundColor: colors.iconWrap, borderRadius: 14, padding: 18, marginBottom: 20 },
    vaBank: { fontSize: 13, color: colors.subtext, marginBottom: 6 },
    vaAccountRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
    vaAccountNumber: { fontSize: 22, fontWeight: 'bold', color: colors.text, letterSpacing: 1 },

    networkPill: { borderWidth: 2, borderRadius: 12, paddingVertical: 10, paddingHorizontal: 18, marginRight: 10, marginBottom: 10 },
    planCard: { backgroundColor: colors.card, borderRadius: 14, padding: 16, marginBottom: 10, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', borderWidth: 1, borderColor: colors.inputBorder },
    planName: { fontSize: 15, fontWeight: 'bold', color: colors.text },
    planValidity: { fontSize: 12, color: colors.subtext, marginTop: 2 },
    planPrice: { fontSize: 16, fontWeight: 'bold', color: colors.accent },
    receiptCard: { backgroundColor: colors.card, borderRadius: 16, padding: 20, marginTop: 20, marginBottom: 20 },
    receiptRow: { fontSize: 14, color: colors.text, marginBottom: 10 },
  });
}
