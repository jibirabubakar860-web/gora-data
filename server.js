require('dotenv').config();

// ─── Crash reporting ────────────────────────────────────────────────────────
// Sentry docs are explicit that Sentry.init() must run before express (or
// anything else) is required, or its auto-instrumentation misses those
// modules entirely. Set SENTRY_DSN in the environment (same convention as
// every other secret in this file, e.g. FLUTTERWAVE_SECRET_KEY). Sentry.init
// with an undefined dsn just no-ops — safe to deploy before you have one.
const Sentry = require('@sentry/node');
Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV || 'development',
  tracesSampleRate: 0.2,
});

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const Joi = require('joi');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1); // trust Render's proxy so express-rate-limit can read X-Forwarded-For safely
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10kb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

// Tighter limit for auth, OTP, and withdrawal routes specifically. The global limiter above
// is shared across the entire app (browsing, purchases, everything), so someone brute-forcing
// login or OTP codes only needs to stay under the same 100-req/15min cap everyone else shares —
// meaning normal traffic on unrelated routes could also push a legit user into that shared limit.
// This applies on top of the global one, scoped only to routes where guessing (password, OTP,
// PIN reset code) or repeated money-movement attempts (withdraw) actually matters.
const sensitiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', message: 'Too many attempts — please wait a few minutes and try again' },
});

// ─── Public legal pages (Terms of Service / Privacy Policy) ────────────────
// Google Play requires a public URL (not just in-app text) for the app's
// Privacy Policy before it will let the app go live. These two routes serve
// the same copy shown inside the app as plain public webpages, so the URLs
// below can be pasted directly into Play Console:
//   https://gora-data.onrender.com/terms-of-service
//   https://gora-data.onrender.com/privacy-policy
const APP_NAME = 'Gora Data';
const SUPPORT_EMAIL = 'jibirabubakar860@gmail.com';
const SUPPORT_WHATSAPP_RAW = '2340712091041';
const LEGAL_LAST_UPDATED = 'July 24, 2026';

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
Questions about these Terms? Reach us at ${SUPPORT_EMAIL} or WhatsApp +${SUPPORT_WHATSAPP_RAW}.`;

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
- Request deletion of your account and associated personal data, subject to any records we are legally required to retain (e.g. transaction records for financial compliance).

6. Data Retention
We retain transaction and verification records for as long as required by applicable financial regulations, even after an account is deleted, where legally necessary.

7. Children
${APP_NAME} is not intended for use by anyone under 18, as it involves financial transactions requiring legal capacity to contract.

8. Changes to This Policy
We may update this Privacy Policy from time to time. Continued use of the app after a change means you accept the updated Policy.

9. Contact
Questions about your data or this Policy? Reach us at ${SUPPORT_EMAIL} or WhatsApp +${SUPPORT_WHATSAPP_RAW}.`;

function renderLegalPage(title, text) {
  const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${APP_NAME} — ${title}</title>
</head>
<body style="font-family: -apple-system, Helvetica, Arial, sans-serif; max-width: 700px; margin: 40px auto; padding: 0 20px; line-height: 1.7; color: #1f2937;">
<h1 style="font-size: 22px;">${APP_NAME} — ${title}</h1>
<pre style="white-space: pre-wrap; font-family: inherit; font-size: 15px;">${escaped}</pre>
</body>
</html>`;
}

app.get('/terms-of-service', (req, res) => {
  res.type('html').send(renderLegalPage('Terms of Service', TERMS_OF_SERVICE_TEXT));
});

app.get('/privacy-policy', (req, res) => {
  res.type('html').send(renderLegalPage('Privacy Policy', PRIVACY_POLICY_TEXT));
});


// ─── Supabase ─────────────────────────────────────────────────────────────────
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, { auth: { autoRefreshToken: false, persistSession: false } });

// ─── Bigisub ──────────────────────────────────────────────────────────────────
const bigisub = axios.create({ baseURL: process.env.BIGISUB_BASE_URL || 'https://api.bigisub.ng', headers: { Authorization: `Token ${process.env.BIGISUB_API_TOKEN}`, 'Content-Type': 'application/json' }, timeout: 30000 });
bigisub.interceptors.response.use(r => r, e => {
  const detail = e.response?.data;
  const msg = typeof detail === 'string' ? detail : (detail?.errors ? JSON.stringify(detail.errors) : (detail?.message || detail?.error || detail?.detail || JSON.stringify(detail) || e.message));
  return Promise.reject(Object.assign(new Error(msg), { status: e.response?.status }));
});
const NETWORKS = { MTN: '1', Glo: '2', Airtel: '3', '9mobile': '4' };

// ─── Network detection (prefix-based) ──────────────────────────────────────────
// Guards against a customer selecting "MTN" in the UI but typing an Airtel/Glo/9mobile
// number — without this, the wallet gets debited and the provider purchase fails or,
// worse, silently succeeds against the wrong network.
const NETWORK_PREFIXES = {
  MTN: ['0803', '0806', '0703', '0706', '0813', '0816', '0810', '0814', '0903', '0906', '0913', '0916', '0704'],
  Glo: ['0805', '0807', '0705', '0815', '0811', '0905', '0915'],
  Airtel: ['0802', '0808', '0708', '0812', '0902', '0907', '0901', '0904', '0912', '0701'],
  '9mobile': ['0809', '0817', '0818', '0908', '0909'],
};

function normalizePhone(phone) {
  let p = String(phone || '').trim().replace(/[^\d+]/g, '');
  if (p.startsWith('+234')) p = '0' + p.slice(4);
  else if (p.startsWith('234')) p = '0' + p.slice(3);
  return p;
}

// Returns the detected network name, or null if the prefix isn't recognized.
// NOTE: Nigerian number portability means a prefix is a strong signal, not a guarantee —
// pair this with your VTU provider's network-lookup/verify API when one is available.
function detectNetworkFromPhone(phone) {
  const p = normalizePhone(phone);
  if (!/^0\d{10}$/.test(p)) return null;
  const prefix = p.slice(0, 4);
  for (const [network, prefixes] of Object.entries(NETWORK_PREFIXES)) {
    if (prefixes.includes(prefix)) return network;
  }
  return null;
}

const AIRTIME_RECEIVE_NUMBERS = {
  MTN: '08032729581',
  Airtel: '07012091041',
  Glo: '09057264771',
};

// ─── KlubConnect (Nellobyte Systems) ───────────────────────────────────────────
const klubconnect = axios.create({ baseURL: 'https://www.nellobytesystems.com', timeout: 30000 });
const KC_CREDS = { UserID: process.env.KLUBCONNECT_USERID, APIKey: process.env.KLUBCONNECT_APIKEY };
const KC_NETWORKS = { MTN: '01', Glo: '02', '9mobile': '03', Airtel: '04' };

async function klubconnectRequest(path, params) {
  try {
    const { data } = await klubconnect.get(path, { params: { ...KC_CREDS, ...params } });
    return data;
  } catch (e) {
    const detail = e.response?.data;
    const msg = typeof detail === 'string' ? detail : (detail?.status || detail?.remark || JSON.stringify(detail) || e.message);
    throw Object.assign(new Error(msg), { status: e.response?.status });
  }
}

async function klubconnectBalance() {
  return klubconnectRequest('/APIWalletBalanceV1.asp', {});
}

async function klubconnectBuyData({ network, planCode, phone, requestId }) {
  const result = await klubconnectRequest('/APIDatabundleV1.asp', {
    MobileNetwork: KC_NETWORKS[network] || network,
    DataPlan: planCode,
    MobileNumber: phone,
    RequestID: requestId,
  });
  const status = (result?.status || result?.orderstatus || '').toString().toUpperCase();
  const success = status.includes('ORDER_RECEIVED') || status.includes('ORDER_COMPLETE') || status.includes('SUCCESS');
  if (!success) throw Object.assign(new Error(result?.remark || result?.status || 'KlubConnect data purchase failed'), { shouldReverse: true });
  return { success: true, providerRef: result?.orderid ? String(result.orderid) : null, raw: result };
}

async function klubconnectBuyAirtime({ network, amount, phone, requestId }) {
  const result = await klubconnectRequest('/APIAirtimeV1.asp', {
    MobileNetwork: KC_NETWORKS[network] || network,
    Amount: amount,
    MobileNumber: phone,
    RequestID: requestId,
  });
  const status = (result?.status || result?.orderstatus || '').toString().toUpperCase();
  const success = status.includes('ORDER_RECEIVED') || status.includes('ORDER_COMPLETE') || status.includes('SUCCESS');
  if (!success) throw Object.assign(new Error(result?.remark || result?.status || 'KlubConnect airtime purchase failed'), { shouldReverse: true });
  return { success: true, providerRef: result?.orderid ? String(result.orderid) : null, raw: result };
}

// ─── KlubConnect: Recharge Pin Cards (EPIN) ────────────────────────────────────
// Per KlubConnect's official Airtime Recharge PIN (EPIN) API docs.
async function klubconnectBuyRechargePin({ network, value, quantity, requestId, callBackURL }) {
  const params = {
    MobileNetwork: KC_NETWORKS[network] || network,
    Value: value,
    Quantity: quantity,
    RequestID: requestId,
  };
  if (callBackURL) params.CallBackURL = callBackURL;
  const result = await klubconnectRequest('/APIEPINV1.asp', params);
  const status = (result?.status || result?.orderstatus || '').toString().toUpperCase();
  const success = status.includes('ORDER_RECEIVED') || status.includes('ORDER_COMPLETE') || status.includes('SUCCESS');
  if (!success) throw Object.assign(new Error(result?.remark || result?.status || 'KlubConnect recharge pin purchase failed'), { shouldReverse: true });
  const pins = Array.isArray(result?.TXN_EPIN) ? result.TXN_EPIN.map(p => ({
    transactionId: p.transactionid, pin: p.pin, batchNo: p.batchno, amount: p.amount, network: p.network,
  })) : [];
  return { success: true, providerRef: result?.TXN_EPIN?.[0]?.transactionid ? String(result.TXN_EPIN[0].transactionid) : null, pins, raw: result };
}

// A KlubConnect purchase/verify call is considered successful when the response's
// status/orderstatus field contains one of these markers. Shared by every service below.
function kcIsSuccess(result) {
  const status = (result?.status || result?.orderstatus || '').toString().toUpperCase();
  return status.includes('ORDER_RECEIVED') || status.includes('ORDER_COMPLETE') || status.includes('SUCCESS') || status.includes('TRANSACTION SUCCESSFUL');
}

// ─── KlubConnect: Cable TV ─────────────────────────────────────────────────────
// CableTV codes are lowercase strings per KlubConnect (dstv, gotv, startimes, showmax).
async function klubconnectVerifyCableSmartcard({ cableTV, smartCardNo }) {
  return klubconnectRequest('/APIVerifyCableTVV1.asp', { CableTV: cableTV, SmartCardNo: smartCardNo });
}
async function klubconnectBuyCableTV({ cableTV, packageCode, smartCardNo, phone, requestId }) {
  const result = await klubconnectRequest('/APICableTVV1.asp', {
    CableTV: cableTV, Package: packageCode, SmartCardNo: smartCardNo, PhoneNo: phone, RequestID: requestId,
  });
  if (!kcIsSuccess(result)) throw Object.assign(new Error(result?.remark || result?.status || 'KlubConnect cable TV purchase failed'), { shouldReverse: true });
  return { success: true, providerRef: result?.orderid ? String(result.orderid) : null, raw: result };
}
async function klubconnectCableTVPlans() {
  return klubconnectRequest('/APICableTVPackagesV2.asp', {});
}

// ─── KlubConnect: Electricity ───────────────────────────────────────────────────
async function klubconnectVerifyMeter({ electricCompany, meterNo, meterType }) {
  return klubconnectRequest('/APIVerifyElectricityV1.asp', { ElectricCompany: electricCompany, MeterNo: meterNo, MeterType: meterType });
}
async function klubconnectBuyElectricity({ electricCompany, meterType, meterNo, amount, phone, requestId }) {
  const result = await klubconnectRequest('/APIElectricityV1.asp', {
    ElectricCompany: electricCompany, MeterType: meterType, MeterNo: meterNo, Amount: amount, PhoneNo: phone, RequestID: requestId,
  });
  if (!kcIsSuccess(result)) throw Object.assign(new Error(result?.remark || result?.status || 'KlubConnect electricity purchase failed'), { shouldReverse: true });
  return { success: true, providerRef: result?.orderid ? String(result.orderid) : null, token: result?.token || null, raw: result };
}
// NOTE: KlubConnect's electric-company code list is fetched live rather than hardcoded here,
// since the exact numeric codes (01, 02, 03...) must be confirmed against the live endpoint —
// see klubconnectElectricityCompanies() below.
async function klubconnectElectricityCompanies() {
  return klubconnectRequest('/APIElectricityCompaniesV2.asp', {}).catch(() => null); // endpoint path unconfirmed — verify against live docs before relying on this
}

// ─── KlubConnect: Betting ────────────────────────────────────────────────────────
async function klubconnectVerifyBettingCustomer({ bettingCompany, customerId }) {
  return klubconnectRequest('/APIVerifyBettingV1.asp', { BettingCompany: bettingCompany, CustomerID: customerId });
}
async function klubconnectFundBetting({ bettingCompany, customerId, amount, requestId }) {
  const result = await klubconnectRequest('/APIBettingV1.asp', {
    BettingCompany: bettingCompany, CustomerID: customerId, Amount: amount, RequestID: requestId,
  });
  if (!kcIsSuccess(result)) throw Object.assign(new Error(result?.remark || result?.status || 'KlubConnect betting funding failed'), { shouldReverse: true });
  return { success: true, providerRef: result?.orderid ? String(result.orderid) : null, raw: result };
}
async function klubconnectBettingCompanies() {
  return klubconnectRequest('/APIBettingTypesV2.asp', {});
}

// ─── KlubConnect: WAEC / Exam e-PIN ─────────────────────────────────────────────
async function klubconnectBuyExamPin({ examType, phone, requestId }) {
  const result = await klubconnectRequest('/APIWAECV1.asp', { ExamType: examType, PhoneNo: phone, RequestID: requestId });
  if (!kcIsSuccess(result)) throw Object.assign(new Error(result?.remark || result?.status || 'KlubConnect exam PIN purchase failed'), { shouldReverse: true });
  return { success: true, providerRef: result?.orderid ? String(result.orderid) : null, pins: result?.pins || null, raw: result };
}
async function klubconnectExamPackages() {
  return klubconnectRequest('/APIWAECPackagesV2.asp', {});
}

// ─── KlubConnect: JAMB e-PIN ─────────────────────────────────────────────────────
// Confirmed against live KlubConnect API docs (nellobytesystems.com) on 2026-07-25:
// - ExamType is a fixed set of 3 codes only: 'de' (Direct Entry), 'utme-mock'
//   (UTME PIN with mock), 'utme-no-mock' (UTME PIN without mock). No Quantity
//   param exists on the Buy endpoint — each request buys exactly 1 pin.
// - Verify requires ExamType=jamb (a literal, different from the 3 buy codes).
// - Verify response uses the SAME field for success and failure: on success
//   customer_name holds the real name; on failure it holds "INVALID_ACCOUNTNO".
const JAMB_EXAM_TYPES = [
  { code: 'de', name: 'Direct Entry (DE)' },
  { code: 'utme-mock', name: 'UTME PIN (with mock result)' },
  { code: 'utme-no-mock', name: 'UTME PIN (without mock result)' },
];
async function klubconnectVerifyJambProfile({ profileId }) {
  return klubconnectRequest('/APIVerifyJAMBV1.asp', { ExamType: 'jamb', ProfileID: profileId });
}
async function klubconnectBuyJambPin({ examType, phone, requestId }) {
  const result = await klubconnectRequest('/APIJAMBV1.asp', { ExamType: examType, PhoneNo: phone, RequestID: requestId });
  if (!kcIsSuccess(result)) throw Object.assign(new Error(result?.remark || result?.status || 'KlubConnect JAMB PIN purchase failed'), { shouldReverse: true });
  return { success: true, providerRef: result?.orderid ? String(result.orderid) : null, raw: result };
}
// carddetails comes back as a single confirmed string: "Serial No: WRN200343867, pin: 572871474684"
function parseJambCardDetails(carddetails) {
  if (!carddetails || typeof carddetails !== 'string') return null;
  const m = carddetails.match(/Serial No:\s*([^,]+),\s*pin:\s*(\S+)/i);
  if (!m) return { serial: null, pin: carddetails.trim() }; // fallback: show raw string rather than hide it
  return { serial: m[1].trim(), pin: m[2].trim() };
}
async function klubconnectJambPackages() {
  return klubconnectRequest('/APIJAMBPackagesV2.asp', {});
}

// ─── KlubConnect: Smile (ISP) ────────────────────────────────────────────────────
async function klubconnectVerifySmileAccount({ mobileNumber }) {
  return klubconnectRequest('/APIVerifySmileV1.asp', { MobileNetwork: 'smile-direct', MobileNumber: mobileNumber });
}
async function klubconnectBuySmileData({ dataPlan, mobileNumber, requestId }) {
  const result = await klubconnectRequest('/APISmileV1.asp', {
    MobileNetwork: 'smile-direct', DataPlan: dataPlan, MobileNumber: mobileNumber, RequestID: requestId,
  });
  if (!kcIsSuccess(result)) throw Object.assign(new Error(result?.remark || result?.status || 'KlubConnect Smile data purchase failed'), { shouldReverse: true });
  return { success: true, providerRef: result?.orderid ? String(result.orderid) : null, raw: result };
}
async function klubconnectSmilePlans() {
  return klubconnectRequest('/APISmilePackagesV2.asp', {});
}

// ─── KlubConnect: Data Bundle Plans (LIVE, replaces old hardcoded KC_RAW_PLANS) ─
// KlubConnect exposes a live plans+price endpoint (APIDatabundlePlansV2.asp).
// We call it, cache the result briefly to avoid hammering their server on every
// page load, and let the cache expire so price changes on their end flow through
// automatically without any code change or redeploy.
let kcDataPlansCache = { data: null, ts: 0 };
const KC_DATA_PLANS_CACHE_MS = 5 * 60 * 1000; // 5 minutes

async function klubconnectDataPlansLive() {
  const now = Date.now();
  if (kcDataPlansCache.data && now - kcDataPlansCache.ts < KC_DATA_PLANS_CACHE_MS) {
    return kcDataPlansCache.data;
  }
  const result = await klubconnectRequest('/APIDatabundlePlansV2.asp', {});
  // Response shape observed from KlubConnect docs: an object keyed by network name,
  // each holding an array of plan entries. Field names are normalized defensively
  // below since KlubConnect's JSON key casing isn't fully documented.
  const byNetwork = {};
  const rawByNetwork = result?.MOBILE_NETWORK || result?.mobile_network || result || {};
  for (const [networkKey, plans] of Object.entries(rawByNetwork)) {
    if (!Array.isArray(plans)) continue;
    byNetwork[networkKey] = plans.map(p => ({
      code: String(p.PRODUCT_CODE ?? p.plan_id ?? p.code ?? p.DataPlan ?? p.id ?? ''),
      size: p.PRODUCT_NAME ?? p.name ?? p.size ?? p.plan_name ?? '',
      validity: p.VALIDITY ?? p.validity ?? p.duration ?? '',
      costPrice: parseFloat(p.PRODUCT_AMOUNT ?? p.amount ?? p.price ?? p.cost_price ?? 0),
    })).filter(p => p.code && p.costPrice > 0);
  }
  kcDataPlansCache = { data: byNetwork, ts: now };
  return byNetwork;
}

// Kept as a safe fallback ONLY in case the live endpoint is briefly unreachable.
// Prices here may be stale — klubconnectDataPlansFor() always prefers live data.
const KC_RAW_PLANS_FALLBACK = {
  MTN: [
    ['500', '500MB', 'Weekly (SME)', 307.00],
    ['500.00', '500MB', 'Monthly (SME)', 307.00],
    ['1000', '1GB', 'Weekly (SME)', 410.00],
    ['1000.00', '1GB', 'Monthly (SME)', 563.00],
    ['2000', '2GB', 'Weekly (SME)', 820.00],
    ['2000.00', '2GB', 'Monthly (SME)', 1117.00],
    ['3000', '3GB', 'Weekly (SME)', 1230.00],
    ['3000.00', '3GB', 'Monthly (SME)', 1629.00],
    ['5000', '5GB', 'Weekly (SME)', 2050.00],
    ['5000.00', '5GB', 'Monthly (SME)', 2511.00],
    ['100.01', '110MB', '1 day (Awoof Data)', 97.00],
    ['200.01', '230MB', '1 day (Awoof Data)', 194.00],
    ['350.01', '500MB', '1 day (Awoof Data)', 339.50],
    ['500.01', '1GB + 1.5mins', '1 day (Awoof Data)', 485.00],
    ['750.01', '2.5GB', '1 day (Awoof Data)', 727.50],
    ['900.01', '2.5GB', '2 days (Awoof Data)', 873.00],
    ['1000.01', '3.2GB', '2 days (Awoof Data)', 970.00],
    ['500.02', '500MB', '7 days (Direct Data)', 485.00],
    ['800.01', '1GB', '7 days (Direct Data)', 776.00],
    ['1000.03', '1.5GB', '7 days (Direct Data)', 970.00],
    ['1500.03', '3.5GB', '7 days (Direct Data)', 1455.00],
    ['2500.01', '6GB', '7 days (Direct Data)', 2425.00],
    ['3500.01', '11GB', '7 days (Direct Data)', 3395.00],
    ['1500.02', '2GB + 2mins', '30 days (Direct Data)', 1455.00],
    ['2000.01', '2.7GB + 2mins', '30 days (Direct Data)', 1940.00],
    ['2500.02', '3.5GB + 5mins', '30 days (Direct Data)', 2425.00],
    ['3500.02', '7GB', '30 days (Direct Data)', 3395.00],
    ['4500.01', '10GB + 10mins', '30 days (Direct Data)', 4365.00],
    ['5500.01', '12.5GB', '30 days (Direct Data)', 5335.00],
    ['6500.01', '16.5GB + 10mins', '30 days (Direct Data)', 6305.00],
    ['7500.01', '20GB', '30 days (Direct Data)', 7275.00],
    ['9000.01', '25GB', '30 days (Direct Data)', 8730.00],
    ['11000.01', '36GB', '30 days (Direct Data)', 10670.00],
    ['18000.01', '75GB', '30 days (Direct Data)', 17460.00],
    ['35000.01', '165GB', '30 days (Direct Data)', 33950.00],
    ['40000.01', '150GB', '60 days (Direct Data)', 38800.00],
    ['5000.01', '20GB', '7 days (Direct Data)', 4850.00],
    ['90000.03', '480GB', '90 days (Direct Data)', 87300.00],
  ],
  Glo: [
    ['200', '200MB', '14 days (SME)', 94.00],
    ['500', '500MB', '7 days (SME)', 230.00],
    ['1000.11', '1GB', '3 days (SME)', 322.00],
    ['3000.11', '3GB', '3 days (SME)', 968.00],
    ['5000.11', '5GB', '3 days (SME)', 1614.00],
    ['1000.12', '1GB', '7 days (SME)', 357.00],
    ['3000.12', '3GB', '7 days (SME)', 1072.00],
    ['5000.12', '5GB', '7 days (SME)', 1787.00],
    ['1000.21', '1GB', '14 days Night (SME)', 357.00],
    ['3000.21', '3GB', '14 days Night (SME)', 1072.00],
    ['5000.21', '5GB', '14 days Night (SME)', 1787.00],
    ['10000.21', '10GB', '14 days Night (SME)', 3574.00],
    ['1000', '1GB', '30 days (SME)', 461.00],
    ['2000', '2GB', '30 days (SME)', 922.00],
    ['3000', '3GB', '30 days (SME)', 1383.00],
    ['5000', '5GB', '30 days (SME)', 2306.00],
    ['10000', '10GB', '30 days (SME)', 4612.00],
    ['100.01', '125MB', '1 day (Awoof Data)', 97.00],
    ['200.01', '260MB', '2 days (Awoof Data)', 194.00],
    ['500.01', '1.5GB', '14 days (Direct Data)', 485.00],
    ['1000.01', '2.6GB', '30 days (Direct Data)', 970.00],
    ['1500.01', '5GB', '30 days (Direct Data)', 1455.00],
    ['2000.01', '6.15GB', '30 days (Direct Data)', 1940.00],
    ['2500.01', '7.5GB', '30 days (Direct Data)', 2425.00],
    ['3000.01', '10GB', '30 days (Direct Data)', 2910.00],
    ['4000.01', '12.5GB', '30 days (Direct Data)', 3880.00],
    ['5000.01', '16GB', '30 days (Direct Data)', 4850.00],
    ['8000.01', '28GB', '30 days (Direct Data)', 7760.00],
    ['10000.01', '38GB', '30 days (Direct Data)', 9700.00],
    ['15000.01', '64GB', '30 days (Direct Data)', 14550.00],
    ['20000.01', '107GB', '30 days (Direct Data)', 19400.00],
    ['500.02', '2GB', '1 day (Awoof Data)', 485.00],
    ['1500.02', '6GB', '7 days (Direct Data)', 1455.00],
    ['500.03', '2.5GB', 'Weekend [Sat & Sun] (Awoof Data)', 485.00],
    ['200.02', '875MB', 'Weekend [Sun] (Awoof Data)', 194.00],
    ['30000.01', '165GB', '30 days (Direct Data)', 29100.00],
    ['36000.01', '220GB', '30 days (Direct Data)', 38800.00],
    ['50000.01', '320GB', '30 days (Direct Data)', 48500.00],
    ['60000.01', '380GB', '30 days (Direct Data)', 58200.00],
    ['75000.01', '475GB', '30 days (Direct Data)', 72750.00],
    ['150000.03', '1TB (1000GB)', '365 days (Direct Data)', 150000.00],
  ],
  Airtel: [
    ['499.91', '1GB', '1 day (Awoof Data)', 484.91],
    ['599.91', '1.5GB', '2 days (Awoof Data)', 581.91],
    ['749.91', '2GB', '2 days (Awoof Data)', 727.41],
    ['999.91', '3GB', '2 days (Awoof Data)', 969.91],
    ['1499.91', '5GB', '2 days (Awoof Data)', 1454.91],
    ['499.92', '500MB', '7 days (Direct Data)', 484.92],
    ['799.91', '1GB', '7 days (Direct Data)', 775.91],
    ['999.92', '1.5GB', '7 days (Direct Data)', 969.92],
    ['1499.92', '3.5GB', '7 days (Direct Data)', 1454.92],
    ['2499.91', '6GB', '7 days (Direct Data)', 2424.91],
    ['2999.91', '10GB', '7 days (Direct Data)', 2909.91],
    ['4999.91', '18GB', '7 days (Direct Data)', 4849.91],
    ['1499.93', '2GB', '30 days (Direct Data)', 1454.93],
    ['1999.91', '3GB', '30 days (Direct Data)', 1939.91],
    ['2499.92', '4GB', '30 days (Direct Data)', 2424.92],
    ['2999.92', '8GB', '30 days (Direct Data)', 2909.92],
    ['3999.91', '10GB', '30 days (Direct Data)', 3879.91],
    ['4999.92', '13GB', '30 days (Direct Data)', 4849.92],
    ['5999.91', '18GB', '30 days (Direct Data)', 5819.91],
    ['7999.91', '25GB', '30 days (Direct Data)', 7759.91],
    ['9999.91', '35GB', '30 days (Direct Data)', 9699.91],
    ['14999.91', '60GB', '30 days (Direct Data)', 14549.91],
    ['19999.91', '100GB', '30 days (Direct Data)', 19399.91],
    ['29999.91', '160GB', '30 days (Direct Data)', 29099.91],
    ['39999.91', '210GB', '30 days (Direct Data)', 38799.91],
    ['49999.91', '300GB', '90 days (Direct Data)', 48499.91],
    ['59999.91', '350GB', '90 days (Direct Data)', 58199.91],
  ],
  '9mobile': [
    ['50', '50MB', '30 days (SME)', 25.00],
    ['100', '100MB', '30 days (SME)', 51.00],
    ['300', '300MB', '30 days (SME)', 153.00],
    ['500', '500MB', '30 days (SME)', 246.00],
    ['1000', '1GB', '30 days (SME)', 492.00],
    ['2000', '2GB', '30 days (SME)', 984.00],
    ['3000', '3GB', '30 days (SME)', 1476.00],
    ['4000', '4GB', '30 days (SME)', 1968.00],
    ['5000', '5GB', '30 days (SME)', 2460.00],
    ['10000', '10GB', '30 days (SME)', 4920.00],
    ['15000', '15GB', '30 days (SME)', 7380.00],
    ['20000', '20GB', '30 days (SME)', 9840.00],
    ['25000', '25GB', '30 days (SME)', 12300.00],
    ['100.01', '100MB', '1 day (Awoof Data)', 93.00],
    ['150.01', '180MB', '1 day (Awoof Data)', 139.50],
    ['200.01', '250MB', '1 day (Awoof Data)', 186.00],
    ['350.01', '450MB', '1 day (Awoof Data)', 325.50],
    ['500.01', '650MB', '3 days (Awoof Data)', 465.00],
    ['1500.01', '1.75GB', '7 days (Direct Data)', 1395.00],
    ['600.01', '650MB', '14 days (Direct Data)', 558.00],
    ['1000.01', '1.1GB', '30 days (Direct Data)', 930.00],
    ['1200.01', '1.4GB', '30 days (Direct Data)', 1116.00],
    ['2000.01', '2.44GB', '30 days (Direct Data)', 1860.00],
    ['2500.01', '3.17GB', '30 days (Direct Data)', 2325.00],
    ['3000.01', '3.91GB', '30 days (Direct Data)', 2790.00],
    ['4000.01', '5.10GB', '30 days (Direct Data)', 3720.00],
    ['5000.01', '6.5GB', '30 days (Direct Data)', 4650.00],
    ['12000.01', '16GB', '30 days (Direct Data)', 11160.00],
    ['18500.01', '24.3GB', '30 days (Direct Data)', 17205.00],
    ['20000.01', '26.5GB', '30 days (Direct Data)', 18600.00],
    ['30000.01', '39GB', '60 days (Direct Data)', 27900.00],
  ],
};

async function klubconnectDataPlansFor(network) {
  try {
    const live = await klubconnectDataPlansLive();
    const plans = live[network];
    if (plans && plans.length) return plans;
  } catch (e) {
    console.error('KlubConnect live data plans fetch failed, using fallback prices:', e.message);
  }
  // Fallback only fires if the live endpoint is down/unreachable.
  return (KC_RAW_PLANS_FALLBACK[network] || []).map(([code, size, validity, costPrice]) => ({ code, size, validity, costPrice }));
}

// ─── Flutterwave ──────────────────────────────────────────────────────────────
const flutterwave = axios.create({ baseURL: 'https://api.flutterwave.com/v3', headers: { Authorization: `Bearer ${process.env.FLUTTERWAVE_SECRET_KEY}`, 'Content-Type': 'application/json' }, timeout: 30000 });
flutterwave.interceptors.response.use(r => r, e => {
  const detail = e.response?.data;
  const msg = typeof detail === 'string' ? detail : (detail?.message || JSON.stringify(detail) || e.message);
  return Promise.reject(Object.assign(new Error(msg), { status: e.response?.status }));
});

// ─── SMS (Termii) ─────────────────────────────────────────────────────────
// Switched from Sendchamp to Termii — see sendEmailOTP above for why. Uses the same
// TERMII_API_KEY and TERMII_BASE_URL as the email sender. Needs TERMII_SMS_SENDER_ID
// (your approved alphanumeric Sender ID, 3-11 chars, from Termii dashboard → Sender IDs —
// NOT the long request-ID string shown in that table, the actual short name once approved).
const termiiSms = axios.create({
  baseURL: process.env.TERMII_BASE_URL || 'https://v4.api.termii.com',
  timeout: 15000,
});
// Termii needs international format with no leading 0 or + (e.g. 2348012345678),
// but the rest of the app stores/uses local format (0801...) via normalizePhone — convert here.
function toInternationalPhone(phone) {
  const local = normalizePhone(phone); // 0XXXXXXXXXX
  if (/^0\d{10}$/.test(local)) return '234' + local.slice(1);
  return String(phone || '').replace(/[^\d]/g, ''); // fallback: strip everything but digits
}
async function sendSMS(phone, message) {
  if (!process.env.TERMII_API_KEY || !process.env.TERMII_SMS_SENDER_ID) {
    if (process.env.NODE_ENV !== 'production') console.log(`[DEV SMS to ${phone}]: ${message}`);
    return;
  }
  try {
    await termiiSms.post('/api/sms/send', {
      api_key: process.env.TERMII_API_KEY,
      to: toInternationalPhone(phone),
      from: process.env.TERMII_SMS_SENDER_ID,
      sms: message,
      type: 'plain',
      channel: process.env.TERMII_SMS_CHANNEL || 'dnd', // dnd = transactional, bypasses DND restrictions
    });
  } catch (e) {
    const detail = e.response?.data ? JSON.stringify(e.response.data) : e.message;
    throw new Error(`Termii SMS failed: ${detail}`);
  }
}

// ─── EMAIL (Termii Email OTP) ─────────────────────────────────────────────
// Switched from Sendchamp to Termii because Sendchamp email delivery was slow.
// Needs TERMII_API_KEY and TERMII_EMAIL_CONFIGURATION_ID (the ID of the verified
// "OTP Sender" configuration in the Termii dashboard → Email → Configuration).
const termiiEmail = axios.create({
  baseURL: process.env.TERMII_BASE_URL || 'https://v4.api.termii.com',
  timeout: 15000,
});
async function sendEmailOTP(email, code) {
  if (!process.env.TERMII_API_KEY || !process.env.TERMII_EMAIL_CONFIGURATION_ID) {
    if (process.env.NODE_ENV !== 'production') console.log(`[DEV EMAIL OTP to ${email}]: ${code}`);
    return;
  }
  try {
    await termiiEmail.post('/api/email/otp/send', {
      api_key: process.env.TERMII_API_KEY,
      email_address: email,
      code: String(code),
      email_configuration_id: process.env.TERMII_EMAIL_CONFIGURATION_ID,
    });
  } catch (e) {
    const detail = e.response?.data ? JSON.stringify(e.response.data) : e.message;
    throw new Error(`Termii Email failed: ${detail}`);
  }
}

// ─── EMAIL (Resend — generic transactional/alert email) ──────────────────
// Termii's email sender above is used for OTPs only, to keep OTP delivery isolated from
// bulk/alert traffic on a separate provider. This is a separate, generic sender for free-text
// alerts like the low-balance notice. Needs RESEND_API_KEY (from resend.com) and optionally
// RESEND_FROM_EMAIL (a verified sender).
const resend = axios.create({ baseURL: 'https://api.resend.com', timeout: 15000 });
async function sendAlertEmail(toEmail, subject, message) {
  if (!process.env.RESEND_API_KEY) { if (process.env.NODE_ENV !== 'production') console.log(`[DEV ALERT EMAIL to ${toEmail}] ${subject}: ${message}`); return; }
  try {
    await resend.post('/emails', {
      from: process.env.RESEND_FROM_EMAIL || 'Gora Data <alerts@goradata.com>',
      to: [toEmail],
      subject,
      text: message,
    }, { headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}` } });
  } catch (e) {
    console.error('Alert email failed:', e.response?.data?.message || e.message);
    throw e;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
const ok = (res, data, message = 'Success') => res.json({ status: 'success', message, data });
const err = (res, message = 'Error', code = 400, extra = {}) => res.status(code).json({ status: 'error', message, ...extra });
const genRef = (p = 'VTU') => `${p}-${Date.now().toString(36).toUpperCase()}-${uuidv4().slice(0, 8).toUpperCase()}`;
const genOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
// Readable temp password for admin-initiated resets: no ambiguous chars (0/O, 1/I/l),
// long enough to be safe as a one-time value the admin hands to the user out-of-band.
const genTempPassword = () => {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let pass = '';
  const bytes = crypto.randomBytes(10);
  for (let i = 0; i < 10; i++) pass += chars[bytes[i] % chars.length];
  return pass;
};
const genCode = (name = '') => (name.replace(/\s+/g, '').toUpperCase().slice(0, 5) || 'USER') + Math.floor(1000 + Math.random() * 9000);
const isValidEmail = (v) => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim());

// ─── Pricing / margins ──────────────────────────────────────────────────────
let marginCache = { data: null, ts: 0 };
const getMargins = async () => {
  const now = Date.now();
  if (marginCache.data && now - marginCache.ts < 30000) return marginCache.data;
  const { data } = await supabase.from('service_margins').select('service, markup_percent');
  const map = {};
  (data || []).forEach(r => { map[r.service] = parseFloat(r.markup_percent) || 0; });
  marginCache = { data: map, ts: now };
  return map;
};
// Every selling price in the app is computed by this one function, so the safety check lives
// here instead of being repeated at each of the 20+ call sites — it protects against a wrong
// formula, a bad admin-entered negative margin, or any future bug that could sell below cost.
const applyMargin = (costPrice, marginPercent) => {
  const cost = Number(costPrice) || 0;
  const margin = Number(marginPercent) || 0;
  const selling = Math.round(cost * (1 + margin / 100) * 100) / 100;
  if (cost > 0 && selling < cost) {
    console.error(`[PRICING GUARD] Blocked a price below cost — cost=₦${cost}, margin=${margin}%, would-be selling=₦${selling}`);
    const e = new Error('A pricing error was detected and this purchase was blocked to protect against selling below cost. Please try again shortly or contact support.');
    e.status = 500;
    throw e;
  }
  return selling;
};

// Generic Bigisub pagination follower. Several Bigisub list endpoints (cable plans, data
// plans, electricity providers, ISP plans) are paginated the same way as marketinghub/services
// (count/next/previous/results) but were previously only ever read from page 1 — meaning any
// plan/provider that landed on page 2+ was silently invisible to both the browse UI and the
// server-side cost-price lookups used at purchase time. This follows `next` until exhausted.
// Different Bigisub endpoints nest their list under different keys (results/providers/services/
// plans/billers/items) — this checks all of them at both the top level and one level under
// `data`, so a shape we haven't seen before doesn't silently resolve to an empty array.
const BIGISUB_LIST_KEYS = ['results', 'providers', 'services', 'plans', 'billers', 'items', 'data'];
function extractBigisubList(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return null;
  for (const key of BIGISUB_LIST_KEYS) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  return null;
}
async function fetchAllBigisubPages(path, params = {}) {
  const qs = new URLSearchParams(params).toString();
  let url = qs ? `${path}?${qs}` : path;
  let all = [];
  let guard = 0;
  while (url && guard < 50) {
    const { data } = await bigisub.get(url);
    let pageResults = extractBigisubList(data);
    if (pageResults === null && data?.data && typeof data.data === 'object') {
      pageResults = extractBigisubList(data.data);
    }
    if (pageResults === null) {
      console.log('[fetchAllBigisubPages] unrecognized response shape for', url, '— keys:', JSON.stringify(Object.keys(data || {})));
      pageResults = [];
    }
    all = all.concat(pageResults);
    const next = data?.next ?? data?.data?.next ?? null;
    url = next ? next.replace(bigisub.defaults.baseURL, '') : null;
    guard++;
  }
  return all;
}

// Fetch the true provider cost price for a specific cable plan by its planCode/variation_code.
// Mirrors getDataPlanCostPrice — the purchase route uses this instead of trusting a client-sent
// amount, so a customer is always charged exactly (real cost + margin), never margin-on-margin.
async function getCablePlanCostPrice(activeProvider, cableProvider, planCode) {
  if (activeProvider === 'klubconnect') {
    const result = await klubconnectCableTVPlans();
    const tvGroups = result?.TV_ID || {};
    for (const entries of Object.values(tvGroups)) {
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        const products = Array.isArray(entry?.PRODUCT) ? entry.PRODUCT : [];
        const match = products.find(p => String(p.PACKAGE_ID) === String(planCode));
        if (match) return parseFloat(match.PACKAGE_AMOUNT ?? 0);
      }
    }
    throw new Error('Selected package is no longer available');
  }
  const rawPlans = await fetchAllBigisubPages('/api/v2/vtu/cable/plans/');
  const plan = (Array.isArray(rawPlans) ? rawPlans : []).find(p => String(p.variation_code) === String(planCode));
  if (!plan) throw new Error('Selected package is no longer available');
  return parseFloat(plan.amount ?? 0);
}


// Fetch the true provider cost price for a specific data plan by its planCode.
// Used by BOTH the plans listing and the purchase route so the price a user sees
// is exactly the price they get charged (no re-margining on a client-sent amount).
async function getDataPlanCostPrice(provider, network, planCode) {
  if (provider === 'klubconnect') {
    const plans = await klubconnectDataPlansFor(network);
    const plan = plans.find(p => String(p.code) === String(planCode));
    if (!plan) throw new Error('Selected plan is no longer available for this network');
    return plan.costPrice;
  }
  const rawPlans = await fetchAllBigisubPages('/api/v2/vtu/data/plans/', { network: NETWORKS[network] || network });
  const plan = (Array.isArray(rawPlans) ? rawPlans : []).find(p => String(p.id ?? p.plan_id ?? p.code ?? p.plan ?? '') === String(planCode));
  if (!plan) throw new Error('Selected plan is no longer available for this network');
  return parseFloat(plan.price ?? plan.amount ?? plan.cost_price ?? plan.regular_price ?? 0);
}

// ─── Tiered / VIP pricing ───────────────────────────────────────────────────
const VALID_TIERS = ['standard', 'silver', 'gold', 'vip'];
let tierMarginCache = { data: null, ts: 0 };
const getTierMargins = async () => {
  const now = Date.now();
  if (tierMarginCache.data && now - tierMarginCache.ts < 30000) return tierMarginCache.data;
  const { data } = await supabase.from('tier_margins').select('tier, service, markup_percent');
  const map = {};
  (data || []).forEach(r => { map[`${r.tier}:${r.service}`] = parseFloat(r.markup_percent); });
  tierMarginCache = { data: map, ts: now };
  return map;
};
const invalidateTierMarginCache = () => { tierMarginCache = { data: null, ts: 0 }; };
// Returns the effective markup % for this user's tier + service, falling back to the global service margin if no tier override exists.
const getEffectiveMargin = async (userTier, service) => {
  const tier = VALID_TIERS.includes(userTier) ? userTier : 'standard';
  const tierMargins = await getTierMargins();
  const key = `${tier}:${service}`;
  if (tierMargins[key] !== undefined && !isNaN(tierMargins[key])) return tierMargins[key];
  const margins = await getMargins();
  return margins[service] || 0;
};

// ─── Service Controls (Kill-Switch) ────────────────────────────────────────
let serviceControlCache = { data: null, ts: 0 };
const getServiceControls = async () => {
  const now = Date.now();
  if (serviceControlCache.data && now - serviceControlCache.ts < 10000) return serviceControlCache.data;
  const { data } = await supabase.from('service_controls').select('network, service, enabled');
  const map = {};
  (data || []).forEach(r => { map[`${r.network}:${r.service}`] = r.enabled; });
  serviceControlCache = { data: map, ts: now };
  return map;
};
const isServiceEnabled = async (network, service) => {
  const controls = await getServiceControls();
  const key = `${network}:${service}`;
  return controls[key] !== false; // default to enabled if no row found
};
const invalidateServiceControlCache = () => { serviceControlCache = { data: null, ts: 0 }; };

// ─── Granular Provider Routing (per network+service override) ─────────────
let routeCache = { data: null, ts: 0 };
const getProviderRoutes = async () => {
  const now = Date.now();
  if (routeCache.data && now - routeCache.ts < 10000) return routeCache.data;
  const { data } = await supabase.from('provider_routes').select('network, service, provider');
  const map = {};
  (data || []).forEach(r => { map[`${r.network}:${r.service}`] = r.provider; });
  routeCache = { data: map, ts: now };
  return map;
};
const invalidateRouteCache = () => { routeCache = { data: null, ts: 0 }; };
const getProviderForRoute = async (network, service) => {
  const routes = await getProviderRoutes();
  const override = routes[`${network}:${service}`];
  if (override && VALID_PROVIDERS.includes(override)) return override;
  return getActiveProvider(); // falls back to global switch
};

// ─── KV Store (Supabase) ──────────────────────────────────────────────────────
const kvSet = async (key, value, ttl = null) => { const expires_at = ttl ? new Date(Date.now() + ttl * 1000).toISOString() : null; await supabase.from('kv_store').upsert({ key, value: JSON.stringify(value), expires_at }, { onConflict: 'key' }); };
const kvGet = async (key) => { const { data } = await supabase.from('kv_store').select('value, expires_at').eq('key', key).single(); if (!data) return null; if (data.expires_at && new Date(data.expires_at) < new Date()) { await kvDel(key); return null; } try { return JSON.parse(data.value); } catch { return data.value; } };
const kvDel = async (key) => { await supabase.from('kv_store').delete().eq('key', key); };
const kvIncr = async (key, ttl = null) => { const cur = await kvGet(key); const count = (parseInt(cur) || 0) + 1; await kvSet(key, count, count === 1 ? ttl : null); return count; };

// ─── Active VTU provider (admin-switchable, stored in kv_store) ───────────────
const VALID_PROVIDERS = ['bigisub', 'klubconnect'];
let providerCache = { value: null, ts: 0 };
const getActiveProvider = async () => {
  const now = Date.now();
  if (providerCache.value && now - providerCache.ts < 10000) return providerCache.value;
  const stored = await kvGet('active_provider');
  const value = VALID_PROVIDERS.includes(stored) ? stored : 'bigisub';
  providerCache = { value, ts: now };
  return value;
};
const setActiveProvider = async (provider) => { await kvSet('active_provider', provider); providerCache = { value: provider, ts: Date.now() }; };

// ─── Automated Failover ──────────────────────────────────────────────────────
const FAILOVER_ENABLED = process.env.FAILOVER_ENABLED !== 'false';

const logProviderCall = async (provider, service, reference, requestPayload, responsePayload, success, errorMessage = null) => {
  try {
    await supabase.from('provider_logs').insert({
      provider, service, reference: reference || null, success, error_message: errorMessage,
      request_payload: requestPayload ?? null,
      response_payload: responsePayload ?? null,
    });
  } catch (e) { console.error('logProviderCall failed:', e.message); }
};

// Wraps a single provider call: on success, logs the full request+response and returns the parsed result.
// On failure, logs the request + whatever error payload came back, then rethrows so callers/failover can react.
const withProviderLog = async (provider, service, reference, requestPayload, fn) => {
  try {
    const { result, raw } = await fn();
    await logProviderCall(provider, service, reference, requestPayload, raw ?? result, true);
    return result;
  } catch (e) {
    await logProviderCall(provider, service, reference, requestPayload, e.response?.data || { message: e.message }, false, e.message);
    throw e;
  }
};

const recordFailoverEvent = async (network, service, fromProvider, toProvider, reason, reference = null) => {
  try { await supabase.from('failover_events').insert({ network, service, from_provider: fromProvider, to_provider: toProvider, reason, reference }); } catch (e) { console.error('recordFailoverEvent failed:', e.message); }
};

// Runs `attempt(provider)` against the primary provider. If it throws, automatically retries once
// against the other provider, switches the global active provider to the healthy one, and logs a
// failover_events row. If the backup also fails, the ORIGINAL error is surfaced to the caller.
const executeWithFailover = async ({ network, service, primaryProvider, reference, attempt }) => {
  try {
    const result = await attempt(primaryProvider);
    return { result, providerUsed: primaryProvider, failedOver: false };
  } catch (primaryErr) {
    if (!FAILOVER_ENABLED) throw primaryErr;

    const backupProvider = VALID_PROVIDERS.find(p => p !== primaryProvider);
    if (!backupProvider) throw primaryErr;

    try {
      const result = await attempt(backupProvider);
      await setActiveProvider(backupProvider);
      await recordFailoverEvent(network, service, primaryProvider, backupProvider, primaryErr.message, reference);
      return { result, providerUsed: backupProvider, failedOver: true };
    } catch (backupErr) {
      throw primaryErr;
    }
  }
};

// ─── Auth middleware ──────────────────────────────────────────────────────────
const auth = async (req, res, next) => {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return err(res, 'No token', 401);
  try {
    const p = jwt.verify(h.split(' ')[1], process.env.JWT_ACCESS_SECRET);
    const { data, error } = await supabase.from('users').select('id, phone, email, full_name, role, is_active, is_frozen, tier, kyc_verified').eq('id', p.sub).single();
    if (error || !data) return err(res, 'User not found', 401);
    if (!data.is_active) return err(res, 'Account suspended', 403);
    req.user = data; next();
  } catch { return err(res, 'Invalid token', 401); }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return err(res, 'Admin access required', 403);
  next();
};

const requireUnfrozen = (req, res, next) => {
  if (req.user.is_frozen) return err(res, 'Your wallet is frozen. Contact support for assistance.', 403);
  next();
};

// Blocks funding and withdrawal-type actions until the user has submitted a BVN or NIN.
// Purchases (data/airtime/etc) are NOT gated by this — only money moving in or out.
const requireKYC = (req, res, next) => {
  if (!req.user.kyc_verified) return err(res, 'Please verify your identity (BVN or NIN) before funding or withdrawing.', 403, { code: 'KYC_REQUIRED' });
  next();
};

// ─── Transaction PIN ─────────────────────────────────────────────────────────
// Requires the users table to have: pin_hash text, pin_failed_attempts int default 0,
// pin_locked_until timestamptz, pin_set_at timestamptz, pin_reset_by uuid, pin_reset_at timestamptz.
// Run once in Supabase SQL editor:
//   alter table users add column if not exists pin_hash text;
//   alter table users add column if not exists pin_failed_attempts int not null default 0;
//   alter table users add column if not exists pin_locked_until timestamptz;
//   alter table users add column if not exists pin_set_at timestamptz;
//   alter table users add column if not exists pin_reset_by uuid references users(id);
//   alter table users add column if not exists pin_reset_at timestamptz;
//
// This gates every route that moves money out of the wallet (purchases + withdrawals),
// separate from the login password — losing an *unlocked* phone no longer means someone
// can drain the wallet. The client sends the raw 4-digit `pin` in the request body; on the
// client side this can be typed manually or auto-filled after a biometric prompt unlocks it
// from secure device storage, but the server never trusts that distinction — it only ever
// checks the PIN itself, with attempt-limited lockout.
const PIN_LOCK_MINUTES = 15;
const PIN_MAX_ATTEMPTS = 5;

const requireTransactionPin = async (req, res, next) => {
  const { pin } = req.body || {};
  if (!pin) return err(res, 'Transaction PIN required', 400, { code: 'PIN_REQUIRED' });
  if (!/^\d{4}$/.test(String(pin))) return err(res, 'PIN must be 4 digits', 400, { code: 'PIN_REQUIRED' });

  const { data: u, error } = await supabase.from('users').select('pin_hash, pin_failed_attempts, pin_locked_until').eq('id', req.user.id).single();
  if (error || !u) return err(res, 'Could not verify PIN', 500);

  if (!u.pin_hash) return err(res, 'Please set up a transaction PIN before making purchases.', 403, { code: 'PIN_NOT_SET' });

  if (u.pin_locked_until && new Date(u.pin_locked_until) > new Date()) {
    return err(res, `Too many incorrect PIN attempts. Try again in a few minutes, or contact support.`, 423, { code: 'PIN_LOCKED' });
  }

  const valid = await bcrypt.compare(String(pin), u.pin_hash);
  if (!valid) {
    const attempts = (u.pin_failed_attempts || 0) + 1;
    const update = { pin_failed_attempts: attempts };
    if (attempts >= PIN_MAX_ATTEMPTS) update.pin_locked_until = new Date(Date.now() + PIN_LOCK_MINUTES * 60 * 1000).toISOString();
    await supabase.from('users').update(update).eq('id', req.user.id);
    const attemptsLeft = Math.max(0, PIN_MAX_ATTEMPTS - attempts);
    return err(res, attemptsLeft > 0 ? `Incorrect PIN — ${attemptsLeft} attempt${attemptsLeft === 1 ? '' : 's'} left` : 'Incorrect PIN — PIN locked for 15 minutes', 401, { code: 'PIN_INCORRECT', attemptsLeft });
  }

  if (u.pin_failed_attempts) await supabase.from('users').update({ pin_failed_attempts: 0, pin_locked_until: null }).eq('id', req.user.id);
  next();
};

// ─── Wallet helpers ───────────────────────────────────────────────────────────
const getWallet = async (userId) => { const { data } = await supabase.from('wallets').select('id, balance').eq('user_id', userId).single(); return data; };
// IMPORTANT: this used to read the balance, add to it in app memory, then write it back —
// a classic race condition. If two credits landed for the same user close together (e.g. a
// webhook retry, or an admin credit overlapping a webhook), one could silently overwrite the
// other and money would go missing from the ledger. It now calls a Postgres function
// (see credit_wallet_function.sql) that locks the row and updates it atomically, the same way
// debitWallet already does via the debit_wallet RPC.
const creditWallet = async (userId, amount, category, description, metadata = {}) => {
  const ref = genRef('FUND');
  const { data, error } = await supabase.rpc('credit_wallet', { p_user_id: userId, p_amount: parseFloat(amount), p_category: category, p_description: description, p_reference: ref, p_metadata: metadata });
  if (error) throw new Error(error.message || 'Credit failed');
  return { reference: ref, newBalance: data?.new_balance ?? data?.newBalance };
};
const debitWallet = async (userId, amount, category, phone, description, metadata = {}) => {
  const ref = genRef();
  const { data, error } = await supabase.rpc('debit_wallet', { p_user_id: userId, p_amount: parseFloat(amount), p_fee: 0, p_category: category, p_phone: phone, p_description: description, p_reference: ref, p_metadata: metadata });
  if (error) { const msg = error.message || 'Debit failed'; if (msg.toLowerCase().includes('insufficient')) throw Object.assign(new Error(msg), { status: 402 }); throw new Error(msg); }
  return data;
};

// One-time referral bonus, paid to the referrer the first time their referred user
// completes a successful purchase (not on signup, not on wallet funding — proof of
// real usage). Safe to call after every purchase; it no-ops once already paid for
// that referred user, and no-ops if the buyer wasn't referred by anyone.
const REFERRAL_BONUS_AMOUNT = Number(process.env.REFERRAL_BONUS_AMOUNT || 200);
const payReferralBonusIfFirstPurchase = async (userId) => {
  try {
    const { data: buyer } = await supabase
      .from('users')
      .select('id, referred_by, full_name')
      .eq('id', userId)
      .single();

    if (!buyer?.referred_by) return;

    const { data: alreadyPaid } = await supabase
      .from('transactions')
      .select('id')
      .eq('category', 'referral_bonus')
      .contains('metadata', { referredUserId: buyer.id })
      .maybeSingle();

    if (alreadyPaid) return;

    await creditWallet(
      buyer.referred_by,
      REFERRAL_BONUS_AMOUNT,
      'referral_bonus',
      `Referral bonus: ${buyer.full_name} made their first purchase`,
      { referredUserId: buyer.id }
    );
    await notifyUser(buyer.referred_by, null, 'Referral bonus credited',
      `You earned ₦${REFERRAL_BONUS_AMOUNT} — your referral made their first purchase!`, null, 'wallet_credit')
      .catch(e => console.error('referral notify failed:', e.message));
  } catch (e) {
    console.error('payReferralBonusIfFirstPurchase failed:', e.message);
  }
};

// The provider-calling functions (klubconnectBuyData, parseBigisub, etc.) already tag a thrown
// error with `shouldReverse: true` ONLY when the provider gave back an actual response that
// explicitly says the purchase failed (e.g. "insufficient stock", "invalid number"). Errors from
// a timeout, dropped connection, or no response at all do NOT get that flag — because in those
// cases we genuinely don't know whether the provider processed the purchase before we lost the
// connection. Auto-refunding those anyway means a customer could get refunded AND still receive
// the real data/airtime/etc — a real money leak once volume grows. So: confirmed declines refund
// immediately like before; anything ambiguous is held as 'pending_review' for a human to check
// with the provider (a requery) before deciding whether to refund.
const handlePurchaseFailure = async (transaction, providerErr, user, sellingPrice) => {
  if (providerErr?.shouldReverse === true) {
    await supabase.from('transactions').update({ status: 'failed' }).eq('reference', transaction.reference);
    await creditWallet(user.id, sellingPrice, 'reversal', `Reversal: ${providerErr.message}`);
    await notifyUser(user.id, user.phone, 'Purchase failed — refunded', `Your ${transaction.reference} purchase failed (${providerErr.message}). ₦${sellingPrice} was refunded to your wallet.`, null, 'wallet_credit')
      .catch(e => console.error('handlePurchaseFailure notify (refund) failed:', e.message));
    return { refunded: true };
  }
  await supabase.from('transactions').update({ status: 'pending_review' }).eq('reference', transaction.reference);
  console.error(`Purchase ${transaction.reference} left pending_review (ambiguous failure, not auto-refunded):`, providerErr?.message);
  await notifyUser(user.id, user.phone, 'Purchase under review', `We couldn't confirm your ${transaction.reference} purchase went through. It's under review — you'll be notified once it's resolved, and refunded if it didn't go through.`, null, 'transaction')
    .catch(e => console.error('handlePurchaseFailure notify (pending_review) failed:', e.message));
  return { refunded: false };
};

// ─── Bigisub response parser ──────────────────────────────────────────────────
const parseBigisub = (data) => {
  const inner = data?.data || {};
  const ok2 = data?.success === true || inner?.status === 'successful' || data?.Status === 'successful' || data?.status === 'success' || data?.status === 'successful';
  if (!ok2) throw Object.assign(new Error(data?.message || data?.api_response || 'Provider failed'), { shouldReverse: true });
  return { success: true, providerRef: inner?.transaction_id || inner?.reference || data?.id || data?.transaction_id || null, token: inner?.token || data?.token || data?.pin || null, units: inner?.units || data?.units || null, pins: inner?.pins || data?.pins || null, raw: data };
};

// ─── ANNOUNCEMENTS (admin broadcasts a banner every user sees on Home) ────────
// Requires a table:
//   create table if not exists announcements (
//     id uuid primary key default gen_random_uuid(),
//     message text not null,
//     type text not null default 'info',        -- 'info' | 'warning' | 'issue'
//     active boolean not null default true,
//     created_at timestamptz not null default now(),
//     created_by uuid references users(id)
//   );

// Any logged-in user — returns the single most recent active announcement, or null.
app.get('/api/v1/announcements/active', auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('announcements')
      .select('id, message, type, created_at')
      .eq('active', true)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error) throw new Error(error.message);
    ok(res, data || null);
  } catch (e) { err(res, e.message); }
});

// Admin: list all announcements (active and past), most recent first.
app.get('/api/v1/admin/announcements', auth, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('announcements').select('*').order('created_at', { ascending: false }).limit(50);
    if (error) throw new Error(error.message);
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

// Admin: publish a new announcement. Deactivates any currently-active one first,
// so only one banner is ever shown at a time.
app.post('/api/v1/admin/announcements', auth, requireAdmin, async (req, res) => {
  try {
    const { message, type } = req.body || {};
    if (!message || !message.trim()) return err(res, 'message is required');
    const validTypes = ['info', 'warning', 'issue'];
    const announcementType = validTypes.includes(type) ? type : 'info';

    await supabase.from('announcements').update({ active: false }).eq('active', true);

    const { data, error } = await supabase.from('announcements').insert({
      message: message.trim(), type: announcementType, active: true, created_by: req.user.id,
    }).select().single();
    if (error) throw new Error(error.message);
    logAdminAction(req.user.id, 'publish_announcement', 'announcement', data?.id, { message: message.trim(), type: announcementType });
    ok(res, data, 'Announcement published');
  } catch (e) { err(res, e.message); }
});

// Admin: deactivate (remove) an announcement so it stops showing.
app.post('/api/v1/admin/announcements/:id/deactivate', auth, requireAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('announcements').update({ active: false }).eq('id', req.params.id);
    if (error) throw new Error(error.message);
    logAdminAction(req.user.id, 'deactivate_announcement', 'announcement', req.params.id, {});
    ok(res, null, 'Announcement removed');
  } catch (e) { err(res, e.message); }
});

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', message: 'Gora Data VTU API is running!', timestamp: new Date().toISOString() }));
app.get('/', (req, res) => res.json({ status: 'ok', name: 'Gora Data API', version: '1.0.0' }));

// ─── FORCE UPDATE / VERSION CHECK ──────────────────────────────────────────────
// Without this, pushing a backend change that the old app code can't handle (a
// renamed field, a new required param) breaks every user still on the old build,
// with no way to tell them — this is the gap: users on an old build just silently
// fail with no idea why, until they happen to update manually.
//
// Simple three-part semver compare — good enough for 'x.y.z' version strings,
// no need to pull in a whole semver package for this.
function compareVersions(a, b) {
  const pa = String(a).split('.').map(Number);
  const pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  return 0;
}

const DEFAULT_VERSION_SETTINGS = {
  minVersion: '1.0.0',
  latestVersion: '1.0.0',
  updateUrl: 'https://play.google.com/store/apps/details?id=com.goradata.app',
  message: 'A new version of Gora Data is available. Please update to continue.',
};

async function getVersionSettings() {
  const stored = await kvGet('app_version_settings');
  return { ...DEFAULT_VERSION_SETTINGS, ...(stored || {}) };
}

// Public — called before login even, so a user on a broken old build finds out
// immediately rather than after a confusing failed login/purchase.
app.get('/api/v1/app/version-check', async (req, res) => {
  try {
    const { version } = req.query;
    const settings = await getVersionSettings();
    if (!version) return ok(res, { ...settings, forceUpdate: false, updateAvailable: false });
    const forceUpdate = compareVersions(version, settings.minVersion) < 0;
    const updateAvailable = compareVersions(version, settings.latestVersion) < 0;
    ok(res, { ...settings, forceUpdate, updateAvailable });
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/admin/app-version', auth, requireAdmin, async (req, res) => {
  try { ok(res, await getVersionSettings()); } catch (e) { err(res, e.message); }
});

app.put('/api/v1/admin/app-version', auth, requireAdmin, async (req, res) => {
  try {
    const { minVersion, latestVersion, updateUrl, message } = req.body;
    const current = await getVersionSettings();
    const next = {
      minVersion: minVersion || current.minVersion,
      latestVersion: latestVersion || current.latestVersion,
      updateUrl: updateUrl || current.updateUrl,
      message: message || current.message,
    };
    await kvSet('app_version_settings', next);
    logAdminAction(req.user.id, 'update_app_version_settings', 'settings', 'app_version', next);
    ok(res, next, 'App version settings updated');
  } catch (e) { err(res, e.message); }
});

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post('/api/v1/auth/register', sensitiveLimiter, async (req, res) => {
  try {
    const { phone, email, password, fullName, referralCode, otpChannel } = req.body;
    if (!phone || !password || !fullName) return err(res, 'Phone, password and name required');
    if (!email || !isValidEmail(email)) return err(res, 'A valid email address is required');
    const channel = ['sms', 'email', 'both'].includes(otpChannel) ? otpChannel : 'both';

    const { data: existingPhone } = await supabase.from('users').select('id').eq('phone', phone).single();
    if (existingPhone) return err(res, 'Phone already registered', 409);

    const { data: existingEmail } = await supabase.from('users').select('id').eq('email', email.trim().toLowerCase()).single();
    if (existingEmail) return err(res, 'Email already registered', 409);

    const otp = genOTP();
    const cleanEmail = email.trim().toLowerCase();
    await kvSet(`reg:${phone}`, { phone, email: cleanEmail, password, fullName, referralCode }, 300);
    await kvSet(`otp:${phone}`, otp, 300);

    // Send only to the channel the customer picked at signup (or both, if they didn't pick / picked "both").
    const sendJobs = [];
    if (channel === 'sms' || channel === 'both') sendJobs.push(sendSMS(phone, `Your Gora Data verification code is ${otp}. Expires in 5 minutes.`).then(() => 'sms').catch((e) => { throw Object.assign(e, { channel: 'sms' }); }));
    if (channel === 'email' || channel === 'both') sendJobs.push(sendEmailOTP(cleanEmail, otp).then(() => 'email').catch((e) => { throw Object.assign(e, { channel: 'email' }); }));

    const results = await Promise.allSettled(sendJobs);
    const smsSent = channel !== 'email' ? results.some(r => r.status === 'fulfilled' && r.value === 'sms') : undefined;
    const emailSent = channel !== 'sms' ? results.some(r => r.status === 'fulfilled' && r.value === 'email') : undefined;
    results.filter(r => r.status === 'rejected').forEach(r => console.error(`Register OTP failed (${r.reason?.channel}):`, r.reason?.message));

    // If every channel we tried failed, the user has no way to get the code at all — don't
    // tell them "OTP sent" in that case, since that just leaves them stuck. They can retry
    // once delivery is actually working.
    const anySent = (smsSent === true) || (emailSent === true);
    if (!anySent) {
      await kvDel(`reg:${phone}`); await kvDel(`otp:${phone}`);
      return err(res, 'We could not send a verification code right now. Please try again in a few minutes.', 502);
    }

    const message = channel === 'sms'
      ? (smsSent ? 'OTP sent to your phone' : 'Could not send SMS — please try email instead')
      : channel === 'email'
        ? (emailSent ? 'OTP sent to your email' : 'Could not send email — please try SMS instead')
        : smsSent && emailSent
          ? 'OTP sent to your phone and email'
          : smsSent
            ? 'OTP sent to your phone (email delivery failed — use the SMS code)'
            : 'OTP sent to your email (SMS delivery failed — use the email code)';

    res.json({
      status: 'success',
      message,
      data: {
        smsSent,
        emailSent,
        otp: process.env.NODE_ENV !== 'production' ? otp : undefined,
      },
    });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/auth/verify', sensitiveLimiter, async (req, res) => {
  try {
    const { phone, otp } = req.body;
    const stored = await kvGet(`otp:${phone}`);
    if (!stored) return err(res, 'OTP expired', 400);
    if (stored !== otp) return err(res, 'Invalid OTP', 400);
    const pending = await kvGet(`reg:${phone}`);
    if (!pending) return err(res, 'Session expired', 400);
    const { password, email, fullName, referralCode } = pending;
    const passwordHash = await bcrypt.hash(password, 12);
    const refCode = genCode(fullName);
    let referrerId = null;
    if (referralCode) { const { data: ref } = await supabase.from('users').select('id').eq('referral_code', referralCode).single(); if (ref) referrerId = ref.id; }
    const { data: newUser, error: uErr } = await supabase.from('users').insert({ phone, email, password_hash: passwordHash, full_name: fullName, role: 'user', is_verified: true, referral_code: refCode, referred_by: referrerId }).select('id, phone, email, full_name, role, referral_code').single();
    if (uErr) throw new Error(uErr.message);
    await supabase.from('wallets').insert({ user_id: newUser.id });
    await kvDel(`otp:${phone}`); await kvDel(`reg:${phone}`);
    const accessToken = jwt.sign({ sub: newUser.id, role: newUser.role }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ sub: newUser.id, jti: uuidv4() }, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });
    res.status(201).json({ status: 'success', message: 'Account created', data: { user: newUser, accessToken, refreshToken } });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/auth/login', sensitiveLimiter, async (req, res) => {
  try {
    const { identifier, phone, password } = req.body;
    const loginId = (identifier || phone || '').trim();
    if (!loginId || !password) return err(res, 'Phone/email and password required');

    const { data: user } = await supabase
      .from('users')
      .select('id, phone, email, full_name, role, password_hash, is_verified, is_active')
      .or(`phone.eq.${loginId},email.eq.${loginId.toLowerCase()}`)
      .single();

    if (!user) return err(res, 'Invalid credentials', 401);
    if (!user.is_active) return err(res, 'Account suspended', 403);
    if (!user.is_verified) return err(res, 'Phone not verified', 403);
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return err(res, 'Invalid credentials', 401);
    await supabase.from('users').update({ last_login_at: new Date().toISOString() }).eq('id', user.id);
    const accessToken = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ sub: user.id, jti: uuidv4() }, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });
    const { password_hash, ...safeUser } = user;
    ok(res, { user: safeUser, accessToken, refreshToken }, 'Login successful');
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/auth/me', auth, (req, res) => ok(res, req.user));

app.post('/api/v1/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return err(res, 'Refresh token required');
    const p = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    if (p.jti) {
      const revoked = await kvGet(`revoked_token:${p.jti}`);
      if (revoked) return err(res, 'Session has been logged out', 401);
    }
    const { data: user } = await supabase.from('users').select('id, role, is_active').eq('id', p.sub).single();
    if (!user || !user.is_active) return err(res, 'User not found', 401);
    const accessToken = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
    ok(res, { accessToken });
  } catch (e) { err(res, 'Invalid refresh token', 401); }
});

// Revokes a refresh token server-side (e.g. user taps "log out", or "log out this device"
// from a lost/stolen phone). The access token issued from it keeps working for up to 15
// minutes until it naturally expires — this only blocks getting a *new* access token via
// /auth/refresh with this token going forward. TTL on the blacklist entry matches the
// refresh token's own 30-day lifetime, so the kv_store row expires on its own afterward
// instead of growing forever.
app.post('/api/v1/auth/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return err(res, 'Refresh token required');
    let p;
    try { p = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET); }
    catch { return ok(res, null, 'Logged out'); } // already invalid/expired — nothing to revoke, not an error for the client
    if (p.jti) await kvSet(`revoked_token:${p.jti}`, true, 30 * 24 * 60 * 60);
    ok(res, null, 'Logged out');
  } catch (e) { err(res, e.message); }
});

// ─── CHANGE PHONE ───────────────────────────────────────────────────────────
app.post('/api/v1/auth/change-phone/request', auth, async (req, res) => {
  try {
    const { newPhone } = req.body;
    if (!newPhone) return err(res, 'newPhone is required');
    const { data: existing } = await supabase.from('users').select('id').eq('phone', newPhone).single();
    if (existing) return err(res, 'Phone number already in use', 409);
    const code = genOTP();
    await kvSet(`change_phone:${req.user.id}`, { newPhone, code }, 300);
    await sendSMS(newPhone, `Your Gora Data verification code is ${code}`);
    ok(res, null, 'Verification code sent to new number');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/auth/change-phone/verify', auth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return err(res, 'code is required');
    const pending = await kvGet(`change_phone:${req.user.id}`);
    if (!pending) return err(res, 'No pending request or it expired', 400);
    if (pending.code !== code) return err(res, 'Invalid code', 400);
    const { error } = await supabase.from('users').update({ phone: pending.newPhone }).eq('id', req.user.id);
    if (error) throw new Error(error.message);
    await kvDel(`change_phone:${req.user.id}`);
    ok(res, { phone: pending.newPhone }, 'Phone number updated');
  } catch (e) { err(res, e.message); }
});

// ─── CHANGE EMAIL ───────────────────────────────────────────────────────────
app.post('/api/v1/auth/change-email/request', auth, async (req, res) => {
  try {
    const { newEmail } = req.body;
    if (!newEmail || !isValidEmail(newEmail)) return err(res, 'A valid newEmail is required');
    const { data: existing } = await supabase.from('users').select('id').eq('email', newEmail.trim().toLowerCase()).single();
    if (existing) return err(res, 'Email already in use', 409);
    const code = genOTP();
    await kvSet(`change_email:${req.user.id}`, { newEmail: newEmail.trim().toLowerCase(), code }, 300);
    await sendEmailOTP(newEmail, code);
    ok(res, null, 'Verification code sent to new email');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/auth/change-email/verify', auth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return err(res, 'code is required');
    const pending = await kvGet(`change_email:${req.user.id}`);
    if (!pending) return err(res, 'No pending request or it expired', 400);
    if (pending.code !== code) return err(res, 'Invalid code', 400);
    const { error } = await supabase.from('users').update({ email: pending.newEmail }).eq('id', req.user.id);
    if (error) throw new Error(error.message);
    await kvDel(`change_email:${req.user.id}`);
    ok(res, { email: pending.newEmail }, 'Email updated');
  } catch (e) { err(res, e.message); }
});

// ─── TRANSACTION PIN ──────────────────────────────────────────────────────────
// Separate from the login password. Gates every route that moves money out of
// the wallet (see requireTransactionPin above, applied per-route further down).

app.get('/api/v1/user/pin/status', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('pin_hash, pin_set_at').eq('id', req.user.id).single();
    if (error) throw new Error(error.message);
    ok(res, { hasPin: !!data.pin_hash, setAt: data.pin_set_at || null });
  } catch (e) { err(res, e.message); }
});

// First-time setup only — fails if a PIN already exists (use /pin/change for that).
// No re-auth required since the caller already holds a valid session; this mirrors
// how a physical bank card's first PIN is chosen in-app after login.
app.post('/api/v1/user/pin/set', auth, requireUnfrozen, async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin || !/^\d{4}$/.test(String(pin))) return err(res, 'PIN must be exactly 4 digits');
    if (/^(\d)\1{3}$/.test(String(pin))) return err(res, 'Choose a less predictable PIN (not 4 repeated digits)');

    const { data: existing } = await supabase.from('users').select('pin_hash').eq('id', req.user.id).single();
    if (existing?.pin_hash) return err(res, 'A PIN is already set — use change PIN instead', 400, { code: 'PIN_ALREADY_SET' });

    const pinHash = await bcrypt.hash(String(pin), 12);
    const { error } = await supabase.from('users').update({
      pin_hash: pinHash, pin_set_at: new Date().toISOString(), pin_failed_attempts: 0, pin_locked_until: null,
    }).eq('id', req.user.id);
    if (error) throw new Error(error.message);
    ok(res, null, 'Transaction PIN set');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/user/password/change', auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return err(res, 'oldPassword and newPassword are required');
    if (String(newPassword).length < 8) return err(res, 'New password must be at least 8 characters');

    const { data: u } = await supabase.from('users').select('password_hash').eq('id', req.user.id).single();
    if (!u?.password_hash) return err(res, 'Account has no password set', 400);

    const valid = await bcrypt.compare(oldPassword, u.password_hash);
    if (!valid) return err(res, 'Current password is incorrect', 401, { code: 'PASSWORD_INCORRECT' });

    const passwordHash = await bcrypt.hash(newPassword, 12);
    const { error } = await supabase.from('users').update({ password_hash: passwordHash }).eq('id', req.user.id);
    if (error) throw new Error(error.message);
    ok(res, null, 'Password updated');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/user/pin/change', auth, requireUnfrozen, async (req, res) => {
  try {
    const { oldPin, newPin } = req.body;
    if (!oldPin || !newPin) return err(res, 'oldPin and newPin are required');
    if (!/^\d{4}$/.test(String(newPin))) return err(res, 'New PIN must be exactly 4 digits');
    if (/^(\d)\1{3}$/.test(String(newPin))) return err(res, 'Choose a less predictable PIN (not 4 repeated digits)');

    const { data: u } = await supabase.from('users').select('pin_hash').eq('id', req.user.id).single();
    if (!u?.pin_hash) return err(res, 'No PIN set yet', 403, { code: 'PIN_NOT_SET' });

    const valid = await bcrypt.compare(String(oldPin), u.pin_hash);
    if (!valid) return err(res, 'Current PIN is incorrect', 401, { code: 'PIN_INCORRECT' });

    const pinHash = await bcrypt.hash(String(newPin), 12);
    const { error } = await supabase.from('users').update({
      pin_hash: pinHash, pin_set_at: new Date().toISOString(), pin_failed_attempts: 0, pin_locked_until: null,
    }).eq('id', req.user.id);
    if (error) throw new Error(error.message);
    ok(res, null, 'Transaction PIN updated');
  } catch (e) { err(res, e.message); }
});

// ─── SELF-SERVICE TRANSACTION PIN RESET (forgot PIN, while logged in) ─────────
// Separate from /user/pin/change (which needs the OLD pin). This is for a user who
// can't remember their PIN at all. Requires an active login session (the `auth`
// middleware) PLUS a fresh OTP to their verified phone/email — losing your PIN
// shouldn't be as easy to recover as losing a password, since a PIN gates money
// movement. Mirrors the forgot-password OTP + short-lived-token pattern above.
app.post('/api/v1/user/pin/forgot', sensitiveLimiter, auth, requireUnfrozen, async (req, res) => {
  try {
    const { method } = req.body;
    if (!['sms', 'email'].includes(method)) return err(res, "method must be 'sms' or 'email'");

    const { data: user } = await supabase.from('users').select('id, phone, email').eq('id', req.user.id).single();
    if (!user) return err(res, 'Account not found', 404);
    if (method === 'sms' && !user.phone) return err(res, 'No phone number on this account');
    if (method === 'email' && !user.email) return err(res, 'No email on this account');

    const code = genOTP();
    await kvSet(`pin_reset_otp:${user.id}`, code, 300);

    if (method === 'sms') {
      await sendSMS(user.phone, `Your Gora Data transaction PIN reset code is ${code}. Expires in 5 minutes. If you didn't request this, contact support immediately.`);
    } else {
      await sendEmailOTP(user.email, code);
    }

    ok(res, null, `Reset code sent via ${method}`);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/user/pin/verify-reset-code', sensitiveLimiter, auth, requireUnfrozen, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return err(res, 'code is required');

    const stored = await kvGet(`pin_reset_otp:${req.user.id}`);
    if (!stored) return err(res, 'Code expired, please request a new one', 400);
    if (stored !== code) return err(res, 'Invalid code', 400);

    await kvDel(`pin_reset_otp:${req.user.id}`);

    const resetToken = jwt.sign({ sub: req.user.id, purpose: 'pin_reset' }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
    ok(res, { resetToken }, 'Code verified');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/user/pin/reset', auth, requireUnfrozen, async (req, res) => {
  try {
    const { resetToken, newPin } = req.body;
    if (!resetToken || !newPin) return err(res, 'resetToken and newPin are required');
    if (!/^\d{4}$/.test(String(newPin))) return err(res, 'New PIN must be exactly 4 digits');
    if (/^(\d)\1{3}$/.test(String(newPin))) return err(res, 'Choose a less predictable PIN (not 4 repeated digits)');

    let payload;
    try {
      payload = jwt.verify(resetToken, process.env.JWT_ACCESS_SECRET);
    } catch (e) {
      return err(res, 'Reset code expired, please start over', 401);
    }
    if (payload.purpose !== 'pin_reset' || payload.sub !== req.user.id) return err(res, 'Invalid reset token', 401);

    const pinHash = await bcrypt.hash(String(newPin), 12);
    const { error } = await supabase.from('users').update({
      pin_hash: pinHash, pin_set_at: new Date().toISOString(), pin_failed_attempts: 0, pin_locked_until: null,
      pin_reset_by: req.user.id, pin_reset_at: new Date().toISOString(),
    }).eq('id', req.user.id);
    if (error) throw new Error(error.message);

    // Notify the user immediately in case this wasn't actually them — same safety net
    // as a "your password was changed" alert, so a hijacked session gets noticed fast.
    const notifyMsg = 'Your Gora Data transaction PIN was just reset. If this was not you, contact support immediately.';
    if (req.user.phone) sendSMS(req.user.phone, notifyMsg).catch(e => console.error('PIN reset SMS alert failed:', e.message));
    if (req.user.email) sendAlertEmail(req.user.email, 'Your transaction PIN was reset', notifyMsg).catch(e => console.error('PIN reset email alert failed:', e.message));

    ok(res, null, 'Transaction PIN reset successful');
  } catch (e) { err(res, e.message); }
});

// ─── PASSWORD RESET (forgot password flow, choose SMS or Email) ──────────────

app.post('/api/v1/auth/forgot-password', sensitiveLimiter, async (req, res) => {
  try {
    const { identifier, method } = req.body;
    if (!identifier) return err(res, 'Email or phone number is required');
    if (!['sms', 'email'].includes(method)) return err(res, "method must be 'sms' or 'email'");

    const value = identifier.trim();
    const { data: user } = await supabase.from('users').select('id, phone, email').or(`phone.eq.${value},email.eq.${value.toLowerCase()}`).single();
    if (!user) return ok(res, null, 'If an account exists, a reset code has been sent');

    if (method === 'sms' && !user.phone) return err(res, 'No phone number on this account');
    if (method === 'email' && !user.email) return err(res, 'No email on this account');

    const code = genOTP();
    await kvSet(`reset_otp:${user.id}`, code, 300);

    if (method === 'sms') {
      await sendSMS(user.phone, `Your Gora Data password reset code is ${code}. Expires in 5 minutes.`);
    } else {
      await sendEmailOTP(user.email, code);
    }

    ok(res, { userId: user.id }, `Reset code sent via ${method}`);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/auth/verify-reset-code', sensitiveLimiter, async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !code) return err(res, 'userId and code are required');

    const stored = await kvGet(`reset_otp:${userId}`);
    if (!stored) return err(res, 'Code expired, please request a new one', 400);
    if (stored !== code) return err(res, 'Invalid code', 400);

    const { data: user } = await supabase.from('users').select('id').eq('id', userId).single();
    if (!user) return err(res, 'Account not found', 404);

    await kvDel(`reset_otp:${userId}`);

    const resetToken = jwt.sign({ sub: user.id, purpose: 'password_reset' }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
    ok(res, { resetToken }, 'Code verified');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword) return err(res, 'resetToken and newPassword are required');
    if (newPassword.length < 6) return err(res, 'Password must be at least 6 characters');

    let payload;
    try {
      payload = jwt.verify(resetToken, process.env.JWT_ACCESS_SECRET);
    } catch (e) {
      return err(res, 'Reset link expired, please start over', 401);
    }
    if (payload.purpose !== 'password_reset') return err(res, 'Invalid reset token', 401);

    const passwordHash = await bcrypt.hash(newPassword, 12);
    const { error } = await supabase.from('users').update({ password_hash: passwordHash }).eq('id', payload.sub);
    if (error) throw new Error(error.message);

    ok(res, null, 'Password reset successful');
  } catch (e) { err(res, e.message); }
});

// ─── WALLET ROUTES ────────────────────────────────────────────────────────────

app.get('/api/v1/wallet', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('wallets').select('id, balance, ledger_balance, currency').eq('user_id', req.user.id).single();
    ok(res, data);
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/wallet/transactions', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const offset = (page - 1) * limit;
    let q = supabase.from('transactions').select('id, type, category, amount, fee, balance_before, balance_after, status, reference, phone, description, created_at', { count: 'exact' }).eq('user_id', req.user.id).order('created_at', { ascending: false }).range(offset, offset + limit - 1);
    if (req.query.category) q = q.eq('category', req.query.category);
    if (req.query.status) q = q.eq('status', req.query.status);
    const { data, count } = await q;
    ok(res, { transactions: data || [], pagination: { page, limit, total: count || 0 } });
  } catch (e) { err(res, e.message); }
});

// ─── Wallet-to-Wallet Transfer (send money to another gora-data user) ─────────
// Two-step client flow: lookup resolves who you're about to pay (so the sender can
// confirm the name before typing their PIN), then the actual transfer executes it.
// Money never leaves the ledger — both legs are internal creditWallet/debitWallet
// calls, so there's no Flutterwave transfer fee and no external payout risk.
const WALLET_TRANSFER_MIN = 100;

app.get('/api/v1/wallet/transfer/lookup', auth, async (req, res) => {
  try {
    const { identifier } = req.query;
    if (!identifier) return err(res, 'identifier (phone or email) is required');
    const clean = String(identifier).trim();

    const { data: recipient } = await supabase
      .from('users')
      .select('id, full_name, phone, email, is_active')
      .or(`phone.eq.${clean},email.eq.${clean.toLowerCase()}`)
      .maybeSingle();

    if (!recipient) return err(res, 'No gora-data user found with that phone or email', 404, { code: 'RECIPIENT_NOT_FOUND' });
    if (recipient.id === req.user.id) return err(res, "You can't send money to yourself", 400);
    if (!recipient.is_active) return err(res, 'This account is not able to receive transfers right now', 403, { code: 'RECIPIENT_BLOCKED' });

    ok(res, { id: recipient.id, fullName: recipient.full_name, phone: recipient.phone });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/wallet/transfer', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { identifier, amount, note } = req.body || {};
    if (!identifier) return err(res, 'identifier (recipient phone or email) is required');
    const amt = parseFloat(amount);
    if (!amt || amt < WALLET_TRANSFER_MIN) return err(res, `Minimum transfer is \u20a6${WALLET_TRANSFER_MIN}`);
    const clean = String(identifier).trim();

    const { data: recipient } = await supabase
      .from('users')
      .select('id, full_name, phone, is_active, is_frozen')
      .or(`phone.eq.${clean},email.eq.${clean.toLowerCase()}`)
      .maybeSingle();

    if (!recipient) return err(res, 'No gora-data user found with that phone or email', 404, { code: 'RECIPIENT_NOT_FOUND' });
    if (recipient.id === req.user.id) return err(res, "You can't send money to yourself", 400);
    if (!recipient.is_active) return err(res, 'This account is not able to receive transfers right now', 403, { code: 'RECIPIENT_BLOCKED' });
    if (recipient.is_frozen) return err(res, "This user's wallet is frozen and can't receive transfers right now", 403, { code: 'RECIPIENT_FROZEN' });

    const ref = genRef('XFER');
    const cleanNote = note ? String(note).trim().slice(0, 140) : null;

    // Debit sender first — debitWallet already throws a 402 on insufficient balance,
    // and if it fails, we never touch the recipient's balance at all.
    const debitResult = await debitWallet(
      req.user.id,
      amt,
      'wallet_transfer_out',
      recipient.phone,
      cleanNote ? `Transfer to ${recipient.full_name} — ${cleanNote}` : `Transfer to ${recipient.full_name}`,
      { transferRef: ref, counterpartyId: recipient.id, counterpartyName: recipient.full_name, note: cleanNote }
    );

    // Credit recipient. If this somehow throws after the debit succeeded, the sender's
    // money isn't lost — it shows as a debit with no matching credit, which the existing
    // transaction/reconciliation trail (reference: ref) makes easy for support to spot
    // and refund, the same way ambiguous Flutterwave transfers are already handled.
    let creditResult;
    try {
      creditResult = await creditWallet(
        recipient.id,
        amt,
        'wallet_transfer_in',
        cleanNote ? `Transfer from ${req.user.full_name} — ${cleanNote}` : `Transfer from ${req.user.full_name}`,
        { transferRef: ref, counterpartyId: req.user.id, counterpartyName: req.user.full_name, note: cleanNote }
      );
    } catch (creditErr) {
      console.error(`Transfer ${ref}: debit succeeded but credit failed — needs manual reconciliation:`, creditErr.message);
      return err(res, 'Transfer could not be completed. If you were debited, contact support with this reference.', 500, { code: 'TRANSFER_INCOMPLETE', reference: ref });
    }

    notifyUser(recipient.id, recipient.phone, 'Money received',
      `You received \u20a6${amt} from ${req.user.full_name}${cleanNote ? `: "${cleanNote}"` : ''}`, null, 'wallet_credit')
      .catch(e => console.error('transfer notify failed:', e.message));

    ok(res, {
      reference: ref,
      amount: amt,
      recipient: { fullName: recipient.full_name, phone: recipient.phone },
      newBalance: debitResult?.new_balance ?? debitResult?.newBalance,
    }, `\u20a6${amt} sent to ${recipient.full_name}`);
  } catch (e) {
    err(res, e.message, e.status || 400);
  }
});

// ─── KYC (identity verification, required before funding or withdrawing) ──────
// See kyc_columns.sql for the note on what "verified" means today — it's a format check,
// not yet checked against NIMC/CBN records. Wire in Smile Identity/YouVerify later for that.
app.post('/api/v1/kyc/submit', auth, async (req, res) => {
  try {
    const { bvn, nin } = req.body;
    const cleanBvn = bvn ? String(bvn).trim() : null;
    const cleanNin = nin ? String(nin).trim() : null;
    if (!cleanBvn && !cleanNin) return err(res, 'Provide your BVN or your NIN');
    if (cleanBvn && !/^\d{11}$/.test(cleanBvn)) return err(res, 'BVN must be exactly 11 digits');
    if (cleanNin && !/^\d{11}$/.test(cleanNin)) return err(res, 'NIN must be exactly 11 digits');

    await supabase.from('users').update({
      bvn: cleanBvn || undefined,
      nin: cleanNin || undefined,
      kyc_verified: true,
      kyc_submitted_at: new Date().toISOString(),
    }).eq('id', req.user.id);

    ok(res, { kycVerified: true }, 'Identity verified — you can now fund and withdraw');
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/kyc/status', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('users').select('kyc_verified, kyc_submitted_at').eq('id', req.user.id).single();
    ok(res, data);
  } catch (e) { err(res, e.message); }
});

// ─── Account Deletion (Play Store requirement — see account_deletion_columns.sql) ──
// Flow: user requests -> we check wallet balance is zero -> mark 'pending' -> admin
// reviews (fraud/dispute check) -> approve (anonymize PII, keep transaction history
// for accounting/NDPR purposes) or reject (back to 'none' with a reason).
app.post('/api/v1/account/delete-request', auth, requireTransactionPin, async (req, res) => {
  try {
    const { reason } = req.body || {};
    const { data: user } = await supabase.from('users').select('deletion_status').eq('id', req.user.id).single();
    if (user?.deletion_status === 'pending') return err(res, 'You already have a pending deletion request.', 409);

    const wallet = await getWallet(req.user.id);
    if (wallet && parseFloat(wallet.balance) > 0) {
      return err(res, 'Please withdraw your wallet balance before requesting account deletion.', 400, { code: 'BALANCE_NOT_ZERO', balance: wallet.balance });
    }

    await supabase.from('users').update({
      deletion_status: 'pending',
      deletion_requested_at: new Date().toISOString(),
      deletion_reason: reason || null,
      deletion_rejected_reason: null,
    }).eq('id', req.user.id);

    ok(res, { deletionStatus: 'pending' }, 'Deletion request submitted. This is usually processed within 30 days.');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/account/delete-request/cancel', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('deletion_status').eq('id', req.user.id).single();
    if (user?.deletion_status !== 'pending') return err(res, 'You have no pending deletion request.', 400);

    await supabase.from('users').update({ deletion_status: 'none', deletion_requested_at: null, deletion_reason: null }).eq('id', req.user.id);
    ok(res, { deletionStatus: 'none' }, 'Deletion request cancelled.');
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/account/deletion-status', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('users').select('deletion_status, deletion_requested_at, deletion_rejected_reason').eq('id', req.user.id).single();
    ok(res, data);
  } catch (e) { err(res, e.message); }
});

// ─── WALLET FUNDING: CARD (Flutterwave hosted payment page) ───────────────────
// Deliberately does NOT collect card numbers in this app — that's a PCI-DSS compliance burden
// this app isn't certified for. Instead we create a Flutterwave-hosted checkout link and open
// it in a browser/webview; Flutterwave collects the card details on their own certified page.
app.post('/api/v1/wallet/fund/card', auth, requireKYC, async (req, res) => {
  try {
    const { amount } = req.body;
    const amt = parseFloat(amount);
    if (!amt || amt < 100) return err(res, 'Minimum funding amount is ₦100');

    // Double-underscore delimiter (not hyphen) because the user id itself is a UUID full of
    // hyphens — this keeps the webhook's parsing unambiguous when it splits this back apart.
    const txRef = `CARD__${req.user.id}__${Date.now().toString(36).toUpperCase()}`;
    const email = req.user.email || `${req.user.phone}@goradata.ng`;

    const { data: result } = await flutterwave.post('/payments', {
      tx_ref: txRef,
      amount: amt,
      currency: 'NGN',
      redirect_url: process.env.FLUTTERWAVE_REDIRECT_URL || 'https://goradata.ng/wallet/funded',
      customer: { email, phonenumber: req.user.phone, name: req.user.full_name },
      customizations: { title: 'Gora Data', description: 'Wallet funding' },
      payment_options: 'card',
    });

    if (result?.status !== 'success' || !result?.data?.link) return err(res, result?.message || 'Could not start card payment');
    ok(res, { paymentLink: result.data.link, txRef }, 'Open this link to complete payment');
  } catch (e) { err(res, e.response?.data?.message || e.message); }
});

// ─── WALLET FUNDING: USSD ───────────────────────────────────────────────────────
// This list is hardcoded (not pulled from Flutterwave's general bank list) because not every
// bank Flutterwave lists for transfers actually supports USSD charges through them — showing
// a bank here that fails when dialed would be worse than a shorter, verified list. These are
// the standard NIBSS bank codes, same ones used across Paystack/Flutterwave/Monnify.
app.get('/api/v1/wallet/fund/ussd/banks', auth, (req, res) => {
  ok(res, [
    { code: '058', name: 'GTBank' },
    { code: '044', name: 'Access Bank' },
    { code: '057', name: 'Zenith Bank' },
    { code: '011', name: 'First Bank' },
    { code: '033', name: 'UBA' },
    { code: '232', name: 'Sterling Bank' },
    { code: '070', name: 'Fidelity Bank' },
    { code: '214', name: 'FCMB' },
    { code: '032', name: 'Union Bank' },
    { code: '035', name: 'Wema Bank' },
    { code: '221', name: 'Stanbic IBTC' },
    { code: '050', name: 'Ecobank' },
    { code: '076', name: 'Polaris Bank' },
    { code: '030', name: 'Heritage Bank' },
    { code: '082', name: 'Keystone Bank' },
    { code: '215', name: 'Unity Bank' },
    { code: '101', name: 'Providus Bank' },
  ]);
});

app.post('/api/v1/wallet/fund/ussd', auth, requireKYC, async (req, res) => {
  try {
    const { amount, bankCode } = req.body;
    const amt = parseFloat(amount);
    if (!amt || amt < 100) return err(res, 'Minimum funding amount is ₦100');
    if (!bankCode) return err(res, 'bankCode is required');

    const txRef = `USSD__${req.user.id}__${Date.now().toString(36).toUpperCase()}`;
    const email = req.user.email || `${req.user.phone}@goradata.ng`;

    const { data: result } = await flutterwave.post('/charges?type=ussd', {
      tx_ref: txRef,
      account_bank: bankCode,
      amount: amt,
      currency: 'NGN',
      email,
      phone_number: req.user.phone,
      fullname: req.user.full_name,
    });

    const ussdCode = result?.meta?.authorization?.note;
    if (result?.status !== 'success' || !ussdCode) return err(res, result?.message || 'Could not generate USSD code');
    ok(res, { ussdCode, txRef, expiresInMinutes: 30 }, 'Dial this code on your phone to complete payment');
  } catch (e) { err(res, e.response?.data?.message || e.message); }
});

app.get('/api/v1/wallet/virtual-account', auth, async (req, res) => {
  try {
    const account = await kvGet(`virtual_account:${req.user.id}`);
    ok(res, account || null);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/wallet/virtual-account', auth, async (req, res) => {
  try {
    const existing = await kvGet(`virtual_account:${req.user.id}`);
    if (existing) return ok(res, existing, 'Virtual account already exists');

    const { bvn, nin } = req.body;
    const cleanBvn = bvn ? String(bvn).trim() : null;
    const cleanNin = nin ? String(nin).trim() : null;
    if (!cleanBvn && !cleanNin) return err(res, 'Provide your BVN or your NIN to create your funding account');
    if (cleanBvn && !/^\d{11}$/.test(cleanBvn)) return err(res, 'BVN must be exactly 11 digits');
    if (cleanNin && !/^\d{11}$/.test(cleanNin)) return err(res, 'NIN must be exactly 11 digits');

    const nameParts = (req.user.full_name || 'Gora User').trim().split(/\s+/);
    const firstname = nameParts[0];
    const lastname = nameParts.slice(1).join(' ') || nameParts[0];
    const email = `${req.user.phone}@goradata.ng`;
    const txRef = genRef('VA');

    const { data: result } = await flutterwave.post('/virtual-account-numbers', {
      email,
      tx_ref: txRef,
      phonenumber: req.user.phone,
      is_permanent: true,
      firstname,
      lastname,
      narration: `Gora Data - ${req.user.full_name || req.user.phone}`,
      ...(cleanBvn ? { bvn: cleanBvn } : { nin: cleanNin }),
    });

    if (result?.status !== 'success') return err(res, result?.message || 'Could not create virtual account');

    const account = {
      accountNumber: result.data.account_number,
      bankName: result.data.bank_name,
      flwRef: result.data.flw_ref,
      orderRef: result.data.order_ref,
      createdAt: new Date().toISOString(),
    };

    await kvSet(`virtual_account:${req.user.id}`, account);
    await kvSet(`virtual_account_owner:${account.accountNumber}`, req.user.id);

    // This is the point where BVN/NIN actually gets collected in the real app flow (the
    // separate /kyc/submit endpoint isn't wired to any button in the app), so this is what
    // must flip kyc_verified — otherwise requireKYC on funding/withdrawal routes would lock
    // out every user who goes through the normal "Fund Wallet" flow.
    if (!req.user.kyc_verified) {
      await supabase.from('users').update({
        bvn: cleanBvn || undefined,
        nin: cleanNin || undefined,
        kyc_verified: true,
        kyc_submitted_at: new Date().toISOString(),
      }).eq('id', req.user.id);
    }

    ok(res, account, 'Virtual account created — fund your wallet by transferring to this account');
  } catch (e) { err(res, e.message, e.status || 400); }
});

app.post('/webhooks/flutterwave', async (req, res) => {
  try {
    const signature = req.headers['verif-hash'];
    if (!signature || (signature !== process.env.FLUTTERWAVE_WEBHOOK_SECRET && signature !== process.env.FLUTTERWAVE_WEBHOOK_SECRET_TEST)) {
      return res.status(401).json({ status: 'error', message: 'Invalid signature' });
    }

    const payload = req.body;
    res.status(200).json({ status: 'received' });

    // Wallet withdrawals are initiated synchronously in /api/v1/wallet/withdraw, but Flutterwave
    // settles transfers asynchronously — this event tells us whether the money actually landed.
    // If it failed, the wallet needs a refund since the customer was already debited up front.
    if (payload?.event === 'transfer.completed') {
      const t = payload.data;
      const reference = t?.reference;
      if (!reference) return;

      const { data: txn } = await supabase.from('transactions').select('*').eq('reference', reference).eq('category', 'wallet_withdrawal').single();
      if (!txn || txn.status !== 'pending_review') return; // already resolved, or not a withdrawal we know about

      if (t?.status === 'SUCCESSFUL') {
        await supabase.from('transactions').update({ status: 'success', metadata: { ...txn.metadata, flwTransferStatus: t.status } }).eq('reference', reference);
      } else if (t?.status === 'FAILED' || t?.status === 'REVERSED') {
        // Confirmed failure/reversal — the payout didn't land, refund the customer.
        await supabase.from('transactions').update({ status: 'failed', metadata: { ...txn.metadata, flwTransferStatus: t.status, flwComplaint: t?.complete_message } }).eq('reference', reference);
        await creditWallet(txn.user_id, txn.amount, 'reversal', `Reversal: withdrawal transfer ${t.status?.toLowerCase()}`, { originalReference: reference });
        const { data: wUser } = await supabase.from('users').select('id, phone').eq('id', txn.user_id).single();
        if (wUser) await notifyUser(wUser.id, wUser.phone, 'Withdrawal failed — refunded', `Your withdrawal of ₦${txn.amount} could not be completed and was refunded to your wallet.`, null, 'wallet_credit').catch(e => console.error('notify (withdrawal reversal) failed:', e.message));
      } else {
        // Unrecognized/intermediate status (e.g. PENDING) — not a confirmed outcome either way.
        // Leave it in pending_review so we don't refund a withdrawal that may still land, and
        // record what we saw so an admin can check it via /admin/withdrawals/:reference/resolve.
        await supabase.from('transactions').update({ metadata: { ...txn.metadata, flwTransferStatus: t.status, flwComplaint: t?.complete_message } }).eq('reference', reference);
      }
      return;
    }

    if (payload?.event !== 'charge.completed') return;
    const data = payload.data;
    if (data?.status !== 'successful') return;
    if (!['bank_transfer', 'card', 'ussd'].includes(data?.payment_type)) return;

    // Flutterwave (like most payment providers) retries webhooks that don't get acknowledged
    // fast enough, and duplicates can arrive close together. A "check if processed, then credit,
    // then mark processed" sequence is racy — two near-simultaneous deliveries can both pass the
    // check before either finishes. To close that gap, we atomically CLAIM the event first by
    // inserting it with a unique constraint on flw_charge_id (see webhook_idempotency.sql) —
    // whichever request's insert wins is the only one that proceeds to credit the wallet.
    let userId = null;
    if (data?.payment_type === 'card' || data?.payment_type === 'ussd') {
      // Card/USSD payments carry the user id we embedded in tx_ref at initiation
      // (see /wallet/fund/card and /wallet/fund/ussd) — far more reliable than phone lookup.
      const parts = String(data.tx_ref || '').split('__');
      if (parts.length === 3) {
        const { data: userRow } = await supabase.from('users').select('id').eq('id', parts[1]).single();
        if (userRow) userId = userRow.id;
      }
    } else if (data?.customer?.phone_number) {
      const { data: userRow } = await supabase.from('users').select('id').eq('phone', data.customer.phone_number).single();
      if (userRow) userId = userRow.id;
    }

    const logRow = {
      provider: 'flutterwave',
      event_type: payload.event,
      flw_charge_id: String(data.id),
      tx_ref: data.tx_ref,
      amount: data.amount,
      customer_phone: data?.customer?.phone_number || null,
      matched_user_id: userId,
      wallet_credited: false,
      raw_payload: payload,
    };

    // Atomic claim: this INSERT will fail with a unique-violation if another request (a retry
    // delivered concurrently) already claimed this flw_charge_id — that's our idempotency guard.
    const { error: claimErr } = await supabase.from('gateway_webhook_log').insert(logRow);
    if (claimErr) {
      if (claimErr.code === '23505') { // unique_violation — already being/been processed
        console.log('Flutterwave webhook: duplicate delivery ignored for charge', data.id);
        return;
      }
      throw new Error(claimErr.message);
    }

    if (!userId) {
      // Logged above with wallet_credited: false — shows up in the admin reconciliation queue
      // so a "paid but not credited" complaint can be resolved manually.
      console.log('Flutterwave webhook: could not resolve user for charge', data.id);
      return;
    }

    // SECURITY: never trust amount/status straight off the webhook body — verify the charge
    // server-to-server with Flutterwave first, using our secret key, and credit only what
    // Flutterwave's own record confirms. This protects against a tampered or replayed webhook
    // payload (e.g. an inflated `amount`) even though the signature header already checked out.
    let verified;
    try {
      const { data: verifyResp } = await flutterwave.get(`/transactions/${data.id}/verify`);
      verified = verifyResp?.data;
    } catch (verifyErr) {
      console.error('Flutterwave webhook: verify call failed for charge', data.id, verifyErr.message);
      await supabase.from('gateway_webhook_log').update({ wallet_credited: false, verify_error: verifyErr.message }).eq('flw_charge_id', String(data.id));
      return; // do not credit if we can't independently confirm the charge
    }

    if (!verified || verified.status !== 'successful' || String(verified.tx_ref) !== String(data.tx_ref)) {
      console.log('Flutterwave webhook: verify mismatch/not successful for charge', data.id);
      await supabase.from('gateway_webhook_log').update({ wallet_credited: false, verify_error: 'verify_mismatch' }).eq('flw_charge_id', String(data.id));
      return;
    }

    // Credit the NET settled amount, not the gross charged amount. Once "Charge my
    // customers" is enabled in the Flutterwave dashboard (Settings > Business Preference >
    // Fee Settings), card/USSD checkouts mark the fee up on top of the base price the
    // customer sees before paying, so amount_settled ends up equal to what they intended to
    // fund and this is a no-op for those methods. For bank transfer (permanent virtual
    // account), there's no checkout step to show a markup on — Flutterwave can't add a fee
    // on top of an amount the customer typed into their own banking app — so the fee still
    // just comes off amount_settled the same as before. Per the merchant's decision, that
    // means a bank-transfer funder who sends ₦100 gets slightly less than ₦100 credited,
    // consistently with every other funding method now passing the fee to the customer
    // rather than the merchant absorbing it.
    const verifiedAmount = verified.amount_settled;
    const verifiedCurrency = verified.currency;
    if (verifiedCurrency !== 'NGN') {
      console.log('Flutterwave webhook: unexpected currency for charge', data.id, verifiedCurrency);
      await supabase.from('gateway_webhook_log').update({ wallet_credited: false, verify_error: 'unexpected_currency' }).eq('flw_charge_id', String(data.id));
      return;
    }
    if (!verifiedAmount || verifiedAmount <= 0) {
      console.error('Flutterwave webhook: missing/invalid amount_settled for charge', data.id, verified.amount_settled);
      await supabase.from('gateway_webhook_log').update({ wallet_credited: false, verify_error: 'missing_amount_settled' }).eq('flw_charge_id', String(data.id));
      return;
    }

    const methodLabel = { bank_transfer: 'bank transfer', card: 'card', ussd: 'USSD' }[data.payment_type] || data.payment_type;
    await creditWallet(userId, verifiedAmount, 'wallet_funding', `Wallet funded via ${methodLabel} (₦${verifiedAmount})`, { flwChargeId: data.id, txRef: data.tx_ref, flwRef: data.flw_ref, paymentType: data.payment_type, verifiedAmount, grossAmount: verified.amount });
    await supabase.from('gateway_webhook_log').update({ wallet_credited: true, verified_amount: verifiedAmount }).eq('flw_charge_id', String(data.id));
  } catch (e) {
    console.error('Flutterwave webhook error:', e.message);
  }
});

// ─── ADMIN: PRICING / MARGINS ──────────────────────────────────────────────────

app.get('/api/v1/admin/pricing', auth, requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('service_margins').select('*').order('service');
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

app.put('/api/v1/admin/pricing/:service', auth, requireAdmin, async (req, res) => {
  try {
    const { service } = req.params;
    const { markupPercent } = req.body;
    if (markupPercent === undefined || markupPercent === null || isNaN(markupPercent)) return err(res, 'markupPercent is required and must be a number');
    // upsert (not update) — a brand-new service like 'isp' has no pre-existing row, and .update()
    // silently affects 0 rows in that case instead of erroring, which made this a no-op for it.
    const { error } = await supabase.from('service_margins').upsert(
      { service, markup_percent: markupPercent, updated_at: new Date().toISOString() },
      { onConflict: 'service' }
    );
    if (error) throw new Error(error.message);
    marginCache = { data: null, ts: 0 };
    logAdminAction(req.user.id, 'update_pricing', 'service', service, { markupPercent });
    ok(res, { service, markupPercent }, 'Pricing updated');
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: ACTIVE VTU PROVIDER SWITCH ─────────────────────────────────────────

app.get('/api/v1/admin/provider', auth, requireAdmin, async (req, res) => {
  try {
    const active = await getActiveProvider();
    ok(res, { active, options: VALID_PROVIDERS });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/admin/provider', auth, requireAdmin, async (req, res) => {
  try {
    const { provider } = req.body;
    if (!VALID_PROVIDERS.includes(provider)) return err(res, `provider must be one of: ${VALID_PROVIDERS.join(', ')}`);
    await setActiveProvider(provider);
    logAdminAction(req.user.id, 'switch_active_provider', 'provider', provider, {});
    ok(res, { active: provider }, `Active provider switched to ${provider}`);
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: GRANULAR PROVIDER ROUTING (per network+service) ───────────────────

app.get('/api/v1/admin/provider-routes', auth, requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('provider_routes').select('*').order('network');
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/admin/provider-routes', auth, requireAdmin, async (req, res) => {
  try {
    const { network, service, provider } = req.body;
    if (!network || !service || !VALID_PROVIDERS.includes(provider)) {
      return err(res, `network, service and provider (${VALID_PROVIDERS.join('/')}) are required`);
    }
    const { error } = await supabase.from('provider_routes').upsert(
      { network, service, provider, updated_at: new Date().toISOString(), updated_by: req.user.id },
      { onConflict: 'network,service' }
    );
    if (error) throw new Error(error.message);
    invalidateRouteCache();
    logAdminAction(req.user.id, 'set_provider_route', 'provider_route', `${network}/${service}`, { provider });
    ok(res, { network, service, provider }, 'Route updated');
  } catch (e) { err(res, e.message); }
});

app.delete('/api/v1/admin/provider-routes/:network/:service', auth, requireAdmin, async (req, res) => {
  try {
    const { network, service } = req.params;
    await supabase.from('provider_routes').delete().eq('network', network).eq('service', service);
    invalidateRouteCache();
    logAdminAction(req.user.id, 'delete_provider_route', 'provider_route', `${network}/${service}`, {});
    ok(res, null, 'Reverted to default provider');
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: SERVICE CONTROL (KILL-SWITCH) ──────────────────────────────────────

app.get('/api/v1/admin/service-controls', auth, requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('service_controls').select('*').order('network');
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/admin/service-controls/toggle', auth, requireAdmin, async (req, res) => {
  try {
    const { network, service, enabled } = req.body;
    if (!network || !service || typeof enabled !== 'boolean') return err(res, 'network, service and enabled (boolean) are required');
    const { error } = await supabase.from('service_controls').update({ enabled, updated_at: new Date().toISOString(), updated_by: req.user.id }).eq('network', network).eq('service', service);
    if (error) throw new Error(error.message);
    invalidateServiceControlCache();
    logAdminAction(req.user.id, 'toggle_service', 'service_control', `${network}/${service}`, { enabled });
    ok(res, { network, service, enabled }, `${network} ${service} ${enabled ? 'enabled' : 'disabled'}`);
  } catch (e) { err(res, e.message); }
});

// ─── SERVICE CAPABILITY MAP (which provider actually implements which service) ─
// Keep this in sync with what's coded below, not with what a provider's docs merely
// advertise — e.g. klubconnect now has an official EPIN spec but there's no
// klubconnectBuyRechargePin() call wired up yet, so it stays false here until that lands.
const SERVICE_SUPPORT = {
  bigisub:     { airtime: true, data: true, cable: true, electricity: true, exam: true, recharge_pin: true, betting: true },
  klubconnect: { airtime: true, data: true, cable: true, electricity: true, exam: true, recharge_pin: true, betting: true },
};

// ─── SERVICES: what's available right now, for the frontend to render around ──
// Returns one entry per service. If `provider` is passed, previews that provider's
// support ignoring routing (e.g. for a "switch to X" confirmation screen). Otherwise
// reflects the live effective provider per service (global switch + any per-service
// override + kill-switch), which is what should drive normal UI filtering.
app.get('/api/v1/services', auth, async (req, res) => {
  try {
    const requestedProvider = req.query.provider;
    if (requestedProvider && !VALID_PROVIDERS.includes(requestedProvider)) {
      return err(res, `provider must be one of: ${VALID_PROVIDERS.join(', ')}`);
    }

    const services = Object.keys(SERVICE_SUPPORT.bigisub);
    const activeProvider = await getActiveProvider();

    const result = await Promise.all(services.map(async (service) => {
      if (requestedProvider) {
        const supported = SERVICE_SUPPORT[requestedProvider][service];
        return { service, provider: requestedProvider, supported, enabled: supported };
      }
      const effectiveProvider = await getProviderForRoute('ALL', service);
      const supported = SERVICE_SUPPORT[effectiveProvider][service];
      const killSwitchEnabled = await isServiceEnabled('ALL', service);
      return { service, provider: effectiveProvider, supported, enabled: supported && killSwitchEnabled };
    }));

    ok(res, { activeProvider, services: result });
  } catch (e) { err(res, e.message); }
});

// ─── VTU ROUTES ───────────────────────────────────────────────────────────────

// For services where the customer types/picks a face-value amount (airtime, electricity,
// recharge pin) rather than choosing from a pre-priced catalog: this returns the EXACT
// price they'll be charged (sellingPrice, after margin) for a given cost amount, computed
// with the same getEffectiveMargin/applyMargin used at actual purchase time — so what the
// customer sees here is guaranteed to match what debitWallet charges, never the raw cost.
app.get('/api/v1/pricing/quote', auth, async (req, res) => {
  try {
    const { service, amount } = req.query;
    if (!service) return err(res, 'service is required');
    const costPrice = parseFloat(amount);
    if (!costPrice || costPrice <= 0) return err(res, 'amount must be a positive number');
    const margin = await getEffectiveMargin(req.user.tier, service);
    const sellingPrice = applyMargin(costPrice, margin);
    ok(res, { service, costPrice, marginPercent: margin, sellingPrice });
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/vtu/data/plans', auth, async (req, res) => {
  try {
    const { network } = req.query;
    if (!network) return err(res, 'network is required');
    const provider = await getProviderForRoute(network, 'data');
    const markup = await getEffectiveMargin(req.user.tier, 'data');
    let plans = [];

    if (provider === 'klubconnect') {
      const kcPlans = await klubconnectDataPlansFor(network);
      plans = kcPlans.map(p => ({
        id: p.code,
        code: p.code,
        name: `${p.size} - ${p.validity}`,
        size: p.size,
        validity: p.validity,
        costPrice: p.costPrice,
        sellingPrice: applyMargin(p.costPrice, markup),
      }));
    } else {
      const rawPlans = await fetchAllBigisubPages('/api/v2/vtu/data/plans/', { network: NETWORKS[network] || network });
      plans = (Array.isArray(rawPlans) ? rawPlans : []).map(p => {
        const costPrice = parseFloat(p.price ?? p.amount ?? p.cost_price ?? p.regular_price ?? 0);
        return { ...p, costPrice, sellingPrice: applyMargin(costPrice, markup) };
      });
    }

    ok(res, plans);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/vtu/data', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { phone, network, planCode } = req.body;
    if (!phone || !network || !planCode) return err(res, 'Phone, network and planCode required');

    const detectedNetwork = detectNetworkFromPhone(phone);
    if (!detectedNetwork) return err(res, 'That does not look like a valid Nigerian phone number. Please check and try again.');
    if (detectedNetwork !== network) {
      return err(res, `This number looks like it's on ${detectedNetwork}, not ${network}. Please select ${detectedNetwork} or double-check the number.`);
    }

    const enabled = await isServiceEnabled(network, 'data');
    if (!enabled) return err(res, `${network} data is temporarily unavailable. Please try again later.`, 503);

    const provider = await getProviderForRoute(network, 'data');
    const costPrice = await getDataPlanCostPrice(provider, network, planCode);
    const margin = await getEffectiveMargin(req.user.tier, 'data');
    const sellingPrice = applyMargin(costPrice, margin);
    const transaction = await debitWallet(req.user.id, sellingPrice, 'data', phone, `${network} data → ${phone}`, { network, planCode, costPrice, sellingPrice, profit: sellingPrice - costPrice, provider, tier: req.user.tier || 'standard' });
    try {
      const attempt = async (useProvider) => {
        if (useProvider === 'klubconnect') {
          const requestPayload = { network, planCode, phone, requestId: transaction.reference };
          return withProviderLog('klubconnect', 'data', transaction.reference, requestPayload, async () => {
            const parsed = await klubconnectBuyData({ network, planCode, phone, requestId: transaction.reference });
            return { result: parsed, raw: parsed.raw };
          });
        }
        const requestPayload = { network: Number(NETWORKS[network] || network), plan: Number(planCode), phone_number: phone, ported_number: true };
        return withProviderLog('bigisub', 'data', transaction.reference, requestPayload, async () => {
          const { data: result } = await bigisub.post('/api/v2/vtu/data/purchase/', { ...requestPayload, pin: process.env.BIGISUB_PIN });
          return { result: parseBigisub(result), raw: result };
        });
      };
      const { result: parsed, providerUsed, failedOver } = await executeWithFailover({ network, service: 'data', primaryProvider: provider, reference: transaction.reference, attempt });
      await supabase.from('transactions').update({ status: 'success', provider_ref: parsed.providerRef }).eq('reference', transaction.reference);
      await payReferralBonusIfFirstPurchase(transaction.user_id);
      ok(res, { transaction, result: parsed, providerUsed, failedOver }, 'Data purchase successful');
    } catch (providerErr) {
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

app.post('/api/v1/vtu/airtime', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { phone, network, amount } = req.body;
    if (!phone || !network || !amount) return err(res, 'Phone, network and amount required');
    if (amount < 50) return err(res, 'Minimum airtime is ₦50');

    const detectedNetwork = detectNetworkFromPhone(phone);
    if (!detectedNetwork) return err(res, 'That does not look like a valid Nigerian phone number. Please check and try again.');
    if (detectedNetwork !== network) {
      return err(res, `This number looks like it's on ${detectedNetwork}, not ${network}. Please select ${detectedNetwork} or double-check the number.`);
    }

    const enabled = await isServiceEnabled(network, 'airtime');
    if (!enabled) return err(res, `${network} airtime is temporarily unavailable. Please try again later.`, 503);

    const provider = await getProviderForRoute(network, 'airtime');
    const costPrice = parseFloat(amount);
    const margin = await getEffectiveMargin(req.user.tier, 'airtime');
    const sellingPrice = applyMargin(costPrice, margin);
    const transaction = await debitWallet(req.user.id, sellingPrice, 'airtime', phone, `₦${amount} ${network} airtime → ${phone}`, { network, amount, costPrice, sellingPrice, profit: sellingPrice - costPrice, provider, tier: req.user.tier || 'standard' });
    try {
      const attempt = async (useProvider) => {
        if (useProvider === 'klubconnect') {
          const requestPayload = { network, amount, phone, requestId: transaction.reference };
          return withProviderLog('klubconnect', 'airtime', transaction.reference, requestPayload, async () => {
            const parsed = await klubconnectBuyAirtime({ network, amount, phone, requestId: transaction.reference });
            return { result: parsed, raw: parsed.raw };
          });
        }
        const requestPayload = { network: Number(NETWORKS[network] || network), phone_number: phone, amount: String(amount), airtime_type: 'vtu' };
        return withProviderLog('bigisub', 'airtime', transaction.reference, requestPayload, async () => {
          const { data: result } = await bigisub.post('/api/v2/vtu/airtime/purchase/', { ...requestPayload, pin: process.env.BIGISUB_PIN });
          return { result: parseBigisub(result), raw: result };
        });
      };
      const { result: parsed, providerUsed, failedOver } = await executeWithFailover({ network, service: 'airtime', primaryProvider: provider, reference: transaction.reference, attempt });
      await supabase.from('transactions').update({ status: 'success', provider_ref: parsed.providerRef }).eq('reference', transaction.reference);
      await payReferralBonusIfFirstPurchase(transaction.user_id);
      ok(res, { transaction, result: parsed, providerUsed, failedOver }, 'Airtime purchase successful');
    } catch (providerErr) {
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

// KlubConnect electric-company codes — all 12 Nigerian DISCOs confirmed against
// KlubConnect's live "Available Electricity Companies" docs table (clubkonnect.com).
const KC_ELECTRIC_COMPANIES = {
  EKEDC: '01',   // Eko Electric
  IKEDC: '02',   // Ikeja Electric
  AEDC: '03',    // Abuja Electric
  KEDC: '04',    // Kano Electric (KEDCO)
  PHEDC: '05',   // Port Harcourt Electric (PHED)
  JED: '06',     // Jos Electric
  IBEDC: '07',   // Ibadan Electric
  KAEDC: '08',   // Kaduna Electric (KAEDCO)
  EEDC: '09',    // Enugu Electric
  BEDC: '10',    // Benin Electric
  YEDC: '11',    // Yola Electric
  APLE: '12',    // Aba Electric
};

// Full KlubConnect DISCO list (from clubkonnect.com's own provider selector), all codes confirmed.
const KC_ELECTRIC_DISCO_LIST = [
  { code: 'EKEDC', name: 'Eko Electric (EKEDC)' },
  { code: 'IKEDC', name: 'Ikeja Electric (IKEDC)' },
  { code: 'AEDC', name: 'Abuja Electric (AEDC)' },
  { code: 'KEDC', name: 'Kano Electric (KEDCO)' },
  { code: 'PHEDC', name: 'Port Harcourt Electric (PHED)' },
  { code: 'JED', name: 'Jos Electric (JED)' },
  { code: 'IBEDC', name: 'Ibadan Electric (IBEDC)' },
  { code: 'KAEDC', name: 'Kaduna Electric (KAEDCO)' },
  { code: 'EEDC', name: 'Enugu Electric (EEDC)' },
  { code: 'BEDC', name: 'Benin Electric (BEDC)' },
  { code: 'YEDC', name: 'Yola Electric (YEDC)' },
  { code: 'APLE', name: 'Aba Electric (APLE)' },
];

// Discos Bigisub's reseller API does not currently support at all, even though KlubConnect does.
// This list is only used as a starting guess — the actual decision at verify/purchase time checks
// Bigisub's LIVE provider list (cached below) so that if Bigisub later adds one of these discos,
// this code auto-detects it and stops forcing KlubConnect, with no code change needed.
const KC_ONLY_ELECTRIC_DISCOS = {
  BEDC: { code: 'BEDC', name: 'Benin Electric (BEDC)' },
  YEDC: { code: 'YEDC', name: 'Yola Electric (YEDC)' },
  APLE: { code: 'APLE', name: 'Aba Electric (APLE)' },
};

// Cached set of disco codes Bigisub currently supports, refreshed at most every 10 minutes so
// verify/purchase don't hit Bigisub's provider-list endpoint on every single request.
let bigisubElectricDiscoCache = { codes: null, ts: 0 };
const getBigisubElectricDiscoCodes = async () => {
  const now = Date.now();
  if (bigisubElectricDiscoCache.codes && now - bigisubElectricDiscoCache.ts < 600000) return bigisubElectricDiscoCache.codes;
  try {
    const providers = await fetchAllBigisubPages('/api/v2/bills/electricity/providers/');
    const codes = new Set((providers || []).map(p => String(p?.code ?? p?.company ?? p?.id ?? p?.name ?? '').toUpperCase()));
    bigisubElectricDiscoCache = { codes, ts: now };
    return codes;
  } catch (e) {
    // Live check failed — use the last known good list if we have one, otherwise assume
    // unsupported (the safe default: fall back to KlubConnect rather than fail the request).
    return bigisubElectricDiscoCache.codes || new Set();
  }
};
// Returns true if this disco should be force-routed to KlubConnect (Bigisub genuinely doesn't
// support it right now, based on the live list, not just the starting guess above).
const shouldForceKlubconnectForDisco = async (disco) => {
  const code = String(disco).toUpperCase();
  if (!KC_ONLY_ELECTRIC_DISCOS[code]) return false;
  const bigisubCodes = await getBigisubElectricDiscoCodes();
  return !bigisubCodes.has(code);
};

app.get('/api/v1/vtu/electric/providers', auth, async (req, res) => {
  try {
    const provider = await getProviderForRoute('ALL', 'electric');
    if (provider === 'klubconnect') {
      return ok(res, KC_ELECTRIC_DISCO_LIST);
    }
    const providers = await fetchAllBigisubPages('/api/v2/bills/electricity/providers/');
    // Keep the shared cache fresh with what we just fetched, so verify/purchase benefit too.
    const existingCodes = new Set((providers || []).map(p => String(p?.code ?? p?.company ?? p?.id ?? p?.name ?? '').toUpperCase()));
    bigisubElectricDiscoCache = { codes: existingCodes, ts: Date.now() };
    // Bigisub's own list won't include Benin/Yola/Aba (unless they've since added them) —
    // add whichever ones are still missing so customers can pick them; verify/purchase force
    // those specific ones to KlubConnect automatically.
    const extras = Object.values(KC_ONLY_ELECTRIC_DISCOS).filter(d => !existingCodes.has(d.code));
    ok(res, [...(providers || []), ...extras]);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/vtu/electric/verify', auth, async (req, res) => {
  try {
    const { disco, meterNumber, meterType } = req.body;
    if (!disco || !meterNumber || !meterType) return err(res, 'disco, meterNumber and meterType are required');

    let provider = await getProviderForRoute('ALL', 'electric');
    if (await shouldForceKlubconnectForDisco(disco)) provider = 'klubconnect';
    if (provider === 'klubconnect') {
      if (!KC_ELECTRIC_COMPANIES[disco]) return err(res, `${disco} is not yet supported on KlubConnect. Switch provider to Bigisub for this DISCO.`);
      const result = await klubconnectVerifyMeter({ electricCompany: KC_ELECTRIC_COMPANIES[disco], meterNo: meterNumber, meterType: meterType === 'prepaid' ? '01' : '02' });
      if (!result?.customer_name) return err(res, result?.remark || 'Unable to verify meter number. Please check and try again.');
      return ok(res, { name: result.customer_name, address: result.customer_address || '' });
    }

    const { data: result } = await bigisub.post('/api/v2/bills/electricity/verify/', { company: disco, meter_no: meterNumber, meter_type: meterType });
    const inner = result?.data || result;
    const success = result?.success === true || result?.status === 'successful' || inner?.status === 'successful';
    if (!success) return err(res, result?.message || 'Unable to verify meter number. Please check and try again.');
    ok(res, { name: inner?.customer_name || 'Verified', address: inner?.customer_address || inner?.address || '' });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/vtu/electric', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { disco, meterNumber, meterType, amount, phone } = req.body;
    if (!disco || !meterNumber || !meterType || !amount || amount < 1000) return err(res, 'Missing fields or minimum ₦1,000');
    if (!phone) return err(res, 'phone is required');

    const enabled = await isServiceEnabled('ALL', 'electric');
    if (!enabled) return err(res, 'Electricity payments are temporarily unavailable. Please try again later.', 503);

    let provider = await getProviderForRoute('ALL', 'electric');
    if (await shouldForceKlubconnectForDisco(disco)) provider = 'klubconnect';
    if (provider === 'klubconnect' && !KC_ELECTRIC_COMPANIES[disco]) {
      return err(res, `${disco} is not yet supported on KlubConnect. Switch provider to Bigisub for this DISCO.`);
    }

    const costPrice = parseFloat(amount);
    const margin = await getEffectiveMargin(req.user.tier, 'electricity');
    const sellingPrice = applyMargin(costPrice, margin);
    const transaction = await debitWallet(req.user.id, sellingPrice, 'electric', phone, `₦${amount} ${disco} electricity`, { disco, meterNumber, meterType, costPrice, sellingPrice, profit: sellingPrice - costPrice, tier: req.user.tier || 'standard' });

    if (provider === 'klubconnect') {
      try {
        const result = await withProviderLog('klubconnect', 'electric', transaction.reference, { disco, meterNumber, meterType, amount }, async () => {
          const parsed = await klubconnectBuyElectricity({
            electricCompany: KC_ELECTRIC_COMPANIES[disco], meterType: meterType === 'prepaid' ? '01' : '02',
            meterNo: meterNumber, amount: Number(amount), phone, requestId: transaction.reference,
          });
          return { result: parsed, raw: parsed.raw };
        });
        await supabase.from('transactions').update({ status: 'success', provider_ref: result.providerRef, metadata: { token: result.token } }).eq('reference', transaction.reference);
        await payReferralBonusIfFirstPurchase(transaction.user_id);
        return ok(res, { transaction, token: result.token }, 'Electricity payment successful');
      } catch (providerErr) {
        const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
        return err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
      }
    }

    try {
      const { data: verifyResult } = await bigisub.post('/api/v2/bills/electricity/verify/', { company: disco, meter_no: meterNumber, meter_type: meterType });
      const verifyInner = verifyResult?.data || verifyResult;
      const verifySuccess = verifyResult?.success === true || verifyResult?.status === 'successful' || verifyInner?.status === 'successful';
      if (!verifySuccess) throw new Error(verifyResult?.message || 'Meter verification failed');
      const customerName = verifyInner?.customer_name;

      const payBody = { company: disco, meter_no: meterNumber, meter_type: meterType, phone_number: phone, amount: Number(amount), Customer_name: customerName };
      const { data: result } = await bigisub.post('/api/v2/bills/electricity/pay/', { ...payBody, pin: process.env.BIGISUB_PIN });
      const parsed = parseBigisub(result);
      await logProviderCall('bigisub', 'electric', transaction.reference, payBody, result, true);
      await supabase.from('transactions').update({ status: 'success', provider_ref: parsed.providerRef, metadata: { token: parsed.token, units: parsed.units, customerName } }).eq('reference', transaction.reference);
      await payReferralBonusIfFirstPurchase(transaction.user_id);
      ok(res, { transaction, token: parsed.token, units: parsed.units, customerName }, 'Electricity payment successful');
    } catch (providerErr) {
      await logProviderCall('bigisub', 'electric', transaction.reference, { disco, meterNumber, meterType, amount }, providerErr.response?.data || { message: providerErr.message }, false, providerErr.message);
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

// cable `provider` field disambiguation: this is the CableTV BILLER (dstv/gotv/startimes/showmax),
// NOT the VTU provider (klubconnect/bigisub) — kept as-is from the original request shape.
app.get('/api/v1/vtu/cable/plans', auth, async (req, res) => {
  try {
    const activeProvider = await getProviderForRoute('ALL', 'cable');
    const margin = await getEffectiveMargin(req.user.tier, 'cable');

    if (activeProvider === 'klubconnect') {
      const result = await klubconnectCableTVPlans();
      // Real shape: { TV_ID: { DStv: [ { ID: "dstv", PRODUCT: [ { PACKAGE_ID, PACKAGE_NAME, PACKAGE_AMOUNT, ... } ] } ], GOtv: [...], ... } }
      // PACKAGE_NAME comes with the cost price baked in, e.g. "DStv Padi N4,400" — strip that off since we show our own sellingPrice.
      const tvGroups = result?.TV_ID || {};
      const plans = [];
      for (const entries of Object.values(tvGroups)) {
        if (!Array.isArray(entries)) continue;
        for (const entry of entries) {
          const cableTV = (entry?.ID || '').toLowerCase();
          const products = Array.isArray(entry?.PRODUCT) ? entry.PRODUCT : [];
          for (const p of products) {
            const costPrice = parseFloat(p.PACKAGE_AMOUNT ?? 0);
            const name = String(p.PACKAGE_NAME || '').replace(/\s*N[\d,]+(\.\d+)?\s*$/i, '').trim();
            plans.push({ id: p.PACKAGE_ID, code: p.PACKAGE_ID, name, cableTV, costPrice, sellingPrice: applyMargin(costPrice, margin) });
          }
        }
      }
      return ok(res, plans);
    }

    const rawPlans = await fetchAllBigisubPages('/api/v2/vtu/cable/plans/');
    // Real shape: flat array of { id, cable_name, product_name, variation_code, amount }.
    // cable_name is the biller (DSTV/GOTV/SHOWMAX/STARTIMES) — lowercased here to match the
    // provider values the app already sends (dstv/gotv/startimes/showmax).
    const plans = (Array.isArray(rawPlans) ? rawPlans : []).map(p => {
      const costPrice = parseFloat(p.amount ?? p.price ?? p.cost_price ?? 0);
      return {
        id: p.variation_code ?? p.id,
        code: p.variation_code ?? p.id,
        name: p.product_name ?? p.name ?? '',
        cableTV: String(p.cable_name || '').toLowerCase(),
        costPrice,
        sellingPrice: applyMargin(costPrice, margin),
      };
    });
    ok(res, plans);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/vtu/cable/verify', auth, async (req, res) => {
  try {
    const { provider, smartCardNumber } = req.body;
    if (!provider || !smartCardNumber) return err(res, 'provider and smartCardNumber are required');

    const activeProvider = await getProviderForRoute('ALL', 'cable');
    if (activeProvider === 'klubconnect') {
      const result = await klubconnectVerifyCableSmartcard({ cableTV: provider.toLowerCase(), smartCardNo: smartCardNumber });
      if (!result?.customer_name) return err(res, result?.remark || result?.status || 'Verification failed');
      return ok(res, { name: result.customer_name, currentPlan: result.current_bouquet || result.package || '' });
    }

    const { data: result } = await bigisub.post('/api/v2/vtu/cable/verify/', { cable_name: provider, card_no: smartCardNumber });
    if (!result?.success) return err(res, result?.message || 'Verification failed');
    ok(res, { name: result.data?.customer_name || 'Verified', currentPlan: result.data?.current_bouquet || '' });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/vtu/cable', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { provider, smartCardNumber, planCode, phone } = req.body;
    if (!provider || !smartCardNumber || !planCode) return err(res, 'Missing required fields');

    const enabled = await isServiceEnabled('ALL', 'cable');
    if (!enabled) return err(res, 'Cable TV subscriptions are temporarily unavailable. Please try again later.', 503);

    const activeProvider = await getProviderForRoute('ALL', 'cable');
    const rawCostPrice = await getCablePlanCostPrice(activeProvider, provider, planCode);

    // bigisub adds its own service charge per cable purchase on top of the plan price — confirmed
    // from a real purchase response: amount 5100 + service_charge 100 = total_amount 5200. We fold
    // that into costPrice BEFORE margin so the customer covers it, not JIBIR's profit. Configurable
    // via BIGISUB_CABLE_SERVICE_CHARGE in case it's not a flat ₦100 for every package — check the
    // '[bigisub cable purchase RAW]' log after a real purchase to confirm and adjust if needed.
    const BIGISUB_CABLE_SERVICE_CHARGE = Number(process.env.BIGISUB_CABLE_SERVICE_CHARGE || 100);
    const costPrice = rawCostPrice + (activeProvider === 'bigisub' ? BIGISUB_CABLE_SERVICE_CHARGE : 0);

    const margin = await getEffectiveMargin(req.user.tier, 'cable');
    const sellingPrice = applyMargin(costPrice, margin);
    const transaction = await debitWallet(req.user.id, sellingPrice, 'cable', phone, `${provider} cable subscription`, { provider, smartCardNumber, planCode, costPrice, sellingPrice, profit: sellingPrice - costPrice, tvProvider: activeProvider, tier: req.user.tier || 'standard' });

    if (activeProvider === 'klubconnect') {
      try {
        const result = await withProviderLog('klubconnect', 'cable', transaction.reference, { provider, planCode, smartCardNumber, phone }, async () => {
          const parsed = await klubconnectBuyCableTV({ cableTV: provider.toLowerCase(), packageCode: planCode, smartCardNo: smartCardNumber, phone, requestId: transaction.reference });
          return { result: parsed, raw: parsed.raw };
        });
        await supabase.from('transactions').update({ status: 'success', provider_ref: result.providerRef }).eq('reference', transaction.reference);
        await payReferralBonusIfFirstPurchase(transaction.user_id);
        return ok(res, { transaction, result }, 'Cable subscription successful');
      } catch (providerErr) {
        const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
        return err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
      }
    }

    try {
      const { data: verifyResult } = await bigisub.post('/api/v2/vtu/cable/verify/', { cable_name: provider, card_no: smartCardNumber });
      if (!verifyResult?.success) throw new Error(verifyResult?.message || 'Customer verification failed');
      // Bigisub expects the smartcard/IUC number under `card_no` on both verify and purchase
      // (confirmed by live "card_no is required" error) — NOT `smart_card_number` as previously assumed.
      const payBody = { cable_name: provider, card_no: smartCardNumber, variation_code: planCode, phone, pin: process.env.BIGISUB_PIN };
      const { data: result } = await bigisub.post('/api/v2/vtu/cable/purchase/', payBody);
      const parsed = parseBigisub(result);
      await logProviderCall('bigisub', 'cable', transaction.reference, payBody, result, true);
      await supabase.from('transactions').update({ status: 'success', provider_ref: parsed.providerRef }).eq('reference', transaction.reference);
      await payReferralBonusIfFirstPurchase(transaction.user_id);
      ok(res, { transaction, result: parsed }, 'Cable subscription successful');
    } catch (providerErr) {
      await logProviderCall('bigisub', 'cable', transaction.reference, { provider, smartCardNumber, planCode }, providerErr.response?.data || { message: providerErr.message }, false, providerErr.message);
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

// Bigisub's own exam-pin codes are inconsistent and sometimes misspelled (e.g. "WAEC-REGISTRAION"),
// so instead of trusting whatever text they send, we build a clean display name ourselves from the
// exam board + whether it's a registration or result-checker pin.
const friendlyExamName = (code) => {
  const c = String(code || '').toLowerCase();
  const board = c.includes('waec') ? 'WAEC' : c.includes('neco') ? 'NECO' : c.includes('nabteb') ? 'NABTEB' : String(code || 'Exam').toUpperCase();
  const isReg = c.includes('reg');
  return `${board} ${isReg ? 'Registration PIN' : 'Result Checker PIN'}`;
};

app.get('/api/v1/vtu/exam/prices', auth, async (req, res) => {
  try {
    const activeProvider = await getProviderForRoute('ALL', 'exam');
    const markup = await getEffectiveMargin(req.user.tier, 'exam');
    if (activeProvider === 'klubconnect') {
      // KlubConnect's exam API (APIWAECV1.asp) is WAEC-only — no confirmed NECO/NABTEB support,
      // so only WAEC packages are surfaced here rather than guessing at unconfirmed exam types.
      const result = await klubconnectExamPackages();
      // Confirmed shape from live response: { EXAM_TYPE: [{ PRODUCT_CODE, PRODUCT_DESCRIPTION, PRODUCT_AMOUNT }] }
      const rawPackages = Array.isArray(result?.EXAM_TYPE) ? result.EXAM_TYPE : [];
      const prices = rawPackages.map(p => {
        const costPrice = parseFloat(p.PRODUCT_AMOUNT || 0);
        return {
          code: p.PRODUCT_CODE,
          name: p.PRODUCT_DESCRIPTION || friendlyExamName(p.PRODUCT_CODE),
          costPrice,
          amount: applyMargin(costPrice, markup), // kept as `amount` too since the frontend currently reads this field
          sellingPrice: applyMargin(costPrice, markup),
        };
      }).filter(p => p.code && p.costPrice > 0);
      return ok(res, prices);
    }
    const { data } = await bigisub.get('/api/v2/bills/result-checker/prices/');
    const rawPrices = data?.data?.prices || [];
    const prices = (Array.isArray(rawPrices) ? rawPrices : []).map(p => {
      const costPrice = parseFloat(p.amount ?? p.price ?? 0);
      return { ...p, name: friendlyExamName(p.code), costPrice, amount: applyMargin(costPrice, markup), sellingPrice: applyMargin(costPrice, markup) };
    });
    ok(res, prices);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/vtu/exam', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { examType, quantity, phone } = req.body;
    if (!examType) return err(res, 'examType is required');

    const enabled = await isServiceEnabled('ALL', 'exam');
    if (!enabled) return err(res, 'Exam pin purchase is temporarily unavailable. Please try again later.', 503);

    const activeProvider = await getProviderForRoute('ALL', 'exam');
    const code = examType.toLowerCase();
    const qty = quantity || 1;

    if (activeProvider === 'klubconnect') {
      const result = await klubconnectExamPackages();
      const rawPackages = Array.isArray(result?.EXAM_TYPE) ? result.EXAM_TYPE : [];
      const packageInfo = rawPackages.find(p => String(p.PRODUCT_CODE).toLowerCase() === code);
      if (!packageInfo) return err(res, `${examType.toUpperCase()} is not available on KlubConnect. Switch provider to Bigisub for this exam type.`);

      const costPrice = parseFloat(packageInfo.PRODUCT_AMOUNT || 0) * qty;
      const margin = await getEffectiveMargin(req.user.tier, 'exam');
      const sellingPrice = applyMargin(costPrice, margin);
      const transaction = await debitWallet(req.user.id, sellingPrice, 'exam', phone, `${packageInfo.PRODUCT_DESCRIPTION} x${qty}`, { examType, quantity: qty, costPrice, sellingPrice, profit: sellingPrice - costPrice, provider: activeProvider, tier: req.user.tier || 'standard' });
      try {
        const result = await withProviderLog('klubconnect', 'exam', transaction.reference, { examType, quantity: qty, phone }, async () => {
          const parsed = await klubconnectBuyExamPin({ examType: packageInfo.PRODUCT_CODE, phone, requestId: transaction.reference });
          return { result: parsed, raw: parsed.raw };
        });
        await supabase.from('transactions').update({ status: 'success', provider_ref: result.providerRef, metadata: { pins: result.pins } }).eq('reference', transaction.reference);
        await payReferralBonusIfFirstPurchase(transaction.user_id);
        return ok(res, { transaction, pins: result.pins }, 'Exam pin purchased');
      } catch (providerErr) {
        const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
        return err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
      }
    }

    const { data: pricesResult } = await bigisub.get('/api/v2/bills/result-checker/prices/');
    const prices = pricesResult?.data?.prices || [];
    
    // SMART MATCH: Safely checks if it is a Registration PIN or a Result Checker PIN
    const examInfo = prices.find(p => {
      const providerCode = p.code?.toLowerCase(); // e.g., 'waec', 'waec-reg', 'neco'
      const firstWord = code.split(/[\s-]/)[0]; // Extracts just 'waec', 'neco', or 'nabteb'
      
      if (code.includes('registration') || code.includes('reg')) {
        return providerCode.includes(firstWord) && providerCode.includes('reg');
      } else {
        return providerCode === firstWord || (providerCode.includes(firstWord) && !providerCode.includes('reg'));
      }
    });

    if (!examInfo) return err(res, 'Unknown exam type or plan mismatch');

    const costPrice = Number(examInfo.amount) * qty;
    const margin = await getEffectiveMargin(req.user.tier, 'exam');
    const sellingPrice = applyMargin(costPrice, margin);
    const transaction = await debitWallet(req.user.id, sellingPrice, 'exam', phone, `${examType.toUpperCase()} pin x${qty}`, { examType, quantity: qty, costPrice, sellingPrice, profit: sellingPrice - costPrice, tier: req.user.tier || 'standard' });
    
    try {
      const payBody = { exam: examInfo.code, quantity: qty }; // Uses the exact provider code we matched
      
      // FIXED: Fully closed object passing the BIGISUB_PIN variable securely
      const { data: result } = await bigisub.post('/api/v2/bills/result-checker/purchase/', { 
        ...payBody, 
        pin: process.env.BIGISUB_PIN 
      });
      
      const parsed = parseBigisub(result);
      await logProviderCall('bigisub', 'exam', transaction.reference, payBody, result, true);
      await supabase.from('transactions').update({ status: 'success', provider_ref: parsed.providerRef, metadata: { pins: parsed.pins } }).eq('reference', transaction.reference);
      await payReferralBonusIfFirstPurchase(transaction.user_id);
      ok(res, { transaction, pins: parsed.pins }, 'Exam pin purchased');
    } catch (providerErr) {
      await logProviderCall('bigisub', 'exam', transaction.reference, { examType, quantity: qty }, providerErr.response?.data || { message: providerErr.message }, false, providerErr.message);
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

// ─── JAMB e-PIN (KlubConnect only — Bigisub has no confirmed JAMB support) ──
// ExamType list and both response shapes below are confirmed against KlubConnect's
// live docs (see comment above klubconnectVerifyJambProfile) — nothing here is guessed.
// Live pricing still comes from APIJAMBPackagesV2.asp, whose exact field names are
// NOT confirmed yet, so that part stays defensive and logs the raw response — but
// it's only used to look up a price for a known code, never to invent one.
app.get('/api/v1/vtu/jamb/packages', auth, async (req, res) => {
  try {
    // JAMB has no Bigisub support at all, so it never follows the global/route
    // provider switch — it's always KlubConnect, regardless of admin routing config.
    const margin = await getEffectiveMargin(req.user.tier, 'jamb');
    let rawPackages = [];
    try {
      const result = await klubconnectJambPackages();
      console.error('DEBUG klubconnectJambPackages raw result:', JSON.stringify(result));
      rawPackages = Array.isArray(result) ? result : (result?.JAMB_TYPE || result?.EXAM_TYPE || result?.data || result?.PACKAGES || []);
      if (!Array.isArray(rawPackages)) rawPackages = [];
      console.error('DEBUG rawPackages after extraction:', JSON.stringify(rawPackages));
    } catch (e) {
      console.error('klubconnectJambPackages failed, falling back to no live pricing:', e.message);
    }

    // Match live prices to the 3 confirmed ExamType codes by code (case-insensitive).
    // If the live call didn't return a match for a code, we omit its price rather
    // than fabricate one — the frontend shows "price unavailable" for that option.
    const packages = JAMB_EXAM_TYPES.map(known => {
      const match = rawPackages.find(p => {
        const rawCode = String(p.PRODUCT_CODE ?? p.code ?? p.ExamType ?? p.exam_type ?? '').toLowerCase();
        return rawCode === known.code;
      });
      const costPrice = match ? parseFloat(match.PRODUCT_AMOUNT ?? match.amount ?? match.price ?? 0) : 0;
      return {
        code: known.code,
        name: known.name,
        costPrice: costPrice || null,
        sellingPrice: costPrice ? applyMargin(costPrice, margin) : null,
      };
    });
    ok(res, packages);
  } catch (e) { err(res, e.message); }
});

// Verify requires ExamType=jamb (fixed literal, confirmed) — only relevant for
// Direct Entry / reprinting flows where a Profile ID needs to be checked first.
app.post('/api/v1/vtu/jamb/verify', auth, async (req, res) => {
  try {
    const { profileId } = req.body;
    if (!profileId) return err(res, 'profileId is required');
    const result = await klubconnectVerifyJambProfile({ profileId });
    const name = result?.customer_name;
    // Confirmed: failure comes back in the SAME field as "INVALID_ACCOUNTNO", not a separate error field.
    if (!name || name.toUpperCase().includes('INVALID')) {
      return err(res, 'Unable to verify JAMB profile ID. Please check and try again.');
    }
    ok(res, { name });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/vtu/jamb', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { examType, profileId, phone } = req.body;
    if (!examType) return err(res, 'examType is required');
    if (!phone) return err(res, 'phone is required');
    const known = JAMB_EXAM_TYPES.find(t => t.code === examType);
    if (!known) return err(res, `examType must be one of: ${JAMB_EXAM_TYPES.map(t => t.code).join(', ')}`);

    const enabled = await isServiceEnabled('ALL', 'jamb');
    if (!enabled) return err(res, 'JAMB e-PIN purchase is temporarily unavailable. Please try again later.', 503);

    // JAMB has no Bigisub support at all, so it never follows the global/route
    // provider switch — it's always KlubConnect, regardless of admin routing config.

    // Look up the current live price the same way the /packages endpoint does — never
    // trust a client-supplied amount for what the wallet gets debited.
    let rawPackages = [];
    try {
      const result = await klubconnectJambPackages();
      rawPackages = Array.isArray(result) ? result : (result?.JAMB_TYPE || result?.EXAM_TYPE || result?.data || result?.PACKAGES || []);
      if (!Array.isArray(rawPackages)) rawPackages = [];
    } catch (e) {
      console.error('klubconnectJambPackages failed during purchase:', e.message);
    }
    const match = rawPackages.find(p => String(p.PRODUCT_CODE ?? p.code ?? p.ExamType ?? p.exam_type ?? '').toLowerCase() === examType);
    const costPrice = match ? parseFloat(match.PRODUCT_AMOUNT ?? match.amount ?? match.price ?? 0) : 0;
    if (!costPrice) {
      return err(res, 'Unable to determine current JAMB pricing right now. Please try again shortly.', 503);
    }

    const margin = await getEffectiveMargin(req.user.tier, 'jamb');
    const sellingPrice = applyMargin(costPrice, margin);
    const label = `JAMB e-PIN (${known.name})`;
    const transaction = await debitWallet(req.user.id, sellingPrice, 'jamb', phone, label, { examType, profileId, costPrice, sellingPrice, profit: sellingPrice - costPrice, provider: 'klubconnect', tier: req.user.tier || 'standard' });

    try {
      const purchaseResult = await withProviderLog('klubconnect', 'jamb', transaction.reference, { examType, profileId, phone }, async () => {
        const parsed = await klubconnectBuyJambPin({ examType, phone, requestId: transaction.reference });
        return { result: parsed, raw: parsed.raw };
      });
      // Confirmed shape: pin/serial arrive as one string in carddetails, not an array.
      const card = parseJambCardDetails(purchaseResult.raw?.carddetails);
      await supabase.from('transactions').update({ status: 'success', provider_ref: purchaseResult.providerRef, metadata: { serial: card?.serial || null, pin: card?.pin || null } }).eq('reference', transaction.reference);
      await payReferralBonusIfFirstPurchase(transaction.user_id);
      return ok(res, { transaction, serial: card?.serial || null, pin: card?.pin || null }, 'JAMB e-PIN purchased');
    } catch (providerErr) {
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      return err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});


// ─── ISP (Smile + Spectranet data) ─────────────────────────────────────────
// bigisub fields below are confirmed against RIF Africa's official bigisub API docs
// (rif.africa/technotronics/api/bigisub → ISP tab):
//   GET  /api/v2/isp/smile/plans/        → [{ id, name, plan_volume, plan_price, validity, variation_code, plan_corporate_price }]
//   POST /api/v2/isp/smile/verify/       → body { account_id } → data.customer_name
//   POST /api/v2/isp/smile/topup/        → body { plan (=id), phone_number, email, account_id, pin }
//   GET  /api/v2/isp/spectranet/plans/   → [{ id, name, price, variation_code, corporate_price, charges }]
//   POST /api/v2/isp/spectranet/topup/   → body { plan (=id), phone_number, spectranet_number, quantity, pin }
// Spectranet has no verify step — confirmed only 2 Spectranet endpoints exist (plans + topup).
// Spectranet's per-plan `charges` field is a real extra cost (confirmed: price 3500 + charges 50
// = amount 3550 in the actual purchase response), folded into costPrice before margin so the
// customer covers it — same principle as bigisub's Cable TV service_charge.
//
// KlubConnect endpoints (Smile only) are real paths but their response shape is still unconfirmed —
// raw responses are logged below so the mapping can be corrected once real data comes back, same
// process used to fix Cable TV.
const ISP_PROVIDERS = ['smile', 'spectranet'];

app.get('/api/v1/isp/plans', auth, async (req, res) => {
  try {
    const ispProvider = String(req.query.ispProvider || 'smile');
    if (!ISP_PROVIDERS.includes(ispProvider)) return err(res, 'ispProvider must be smile or spectranet');
    const activeProvider = await getProviderForRoute('ALL', 'isp');
    const margin = await getEffectiveMargin(req.user.tier, 'isp');

    if (activeProvider === 'klubconnect') {
      if (ispProvider !== 'smile') return err(res, 'Only Smile is available on this provider for ISP right now.', 501);
      const result = await klubconnectSmilePlans();
      const rawPlans = Array.isArray(result) ? result : (result?.data || result?.PLAN || result?.plans || []);
      const plans = (Array.isArray(rawPlans) ? rawPlans : []).map(p => {
        const costPrice = parseFloat(p.amount ?? p.price ?? p.plan_amount ?? p.PLAN_AMOUNT ?? 0);
        return {
          id: p.plan_id ?? p.code ?? p.PLAN_ID ?? p.PACKAGE_ID,
          code: p.plan_id ?? p.code ?? p.PLAN_ID ?? p.PACKAGE_ID,
          name: p.plan_name ?? p.name ?? p.PLAN_NAME ?? p.PACKAGE_NAME ?? '',
          costPrice,
          sellingPrice: applyMargin(costPrice, margin),
        };
      }).filter(p => p.code && p.costPrice > 0);
      return ok(res, plans);
    }

    if (ispProvider === 'smile') {
      const rawPlans = await fetchAllBigisubPages('/api/v2/isp/smile/plans/');
      const plans = (Array.isArray(rawPlans) ? rawPlans : []).map(p => {
        const costPrice = parseFloat(p.plan_price ?? 0);
        return { id: p.id, code: p.id, name: p.name || p.plan_volume || '', costPrice, sellingPrice: applyMargin(costPrice, margin) };
      });
      return ok(res, plans);
    }

    const rawPlans = await fetchAllBigisubPages('/api/v2/isp/spectranet/plans/');
    const plans = (Array.isArray(rawPlans) ? rawPlans : []).map(p => {
      const costPrice = parseFloat(p.price ?? 0) + parseFloat(p.charges ?? 0);
      return { id: p.id, code: p.id, name: p.name || '', costPrice, sellingPrice: applyMargin(costPrice, margin) };
    });
    ok(res, plans);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/isp/verify', auth, async (req, res) => {
  try {
    const { accountId } = req.body;
    if (!accountId) return err(res, 'accountId is required');
    const activeProvider = await getProviderForRoute('ALL', 'isp');

    if (activeProvider === 'klubconnect') {
      const result = await klubconnectVerifySmileAccount({ mobileNumber: accountId });
      if (!result?.customer_name) return err(res, result?.remark || result?.status || 'Unable to verify Smile account. Please check the number and try again.');
      return ok(res, { name: result.customer_name });
    }

    const { data: result } = await bigisub.post('/api/v2/isp/smile/verify/', { account_id: accountId });
    if (!result?.success) return err(res, result?.message || 'Unable to verify Smile account. Please check the number and try again.');
    ok(res, { name: result.data?.customer_name });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/isp', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { ispProvider, planCode, accountId, email, spectranetNumber, quantity, phone } = req.body;
    if (!ISP_PROVIDERS.includes(ispProvider)) return err(res, 'ispProvider must be smile or spectranet');
    if (!planCode) return err(res, 'planCode is required');
    if (ispProvider === 'smile' && !accountId) return err(res, 'accountId is required for Smile');
    if (ispProvider === 'spectranet' && !spectranetNumber) return err(res, 'spectranetNumber is required for Spectranet');

    const enabled = await isServiceEnabled('ALL', 'isp');
    if (!enabled) return err(res, 'ISP data purchase is temporarily unavailable. Please try again later.', 503);

    const activeProvider = await getProviderForRoute('ALL', 'isp');
    if (activeProvider === 'klubconnect' && ispProvider !== 'smile') {
      return err(res, 'Only Smile is available on this provider for ISP right now.', 501);
    }

    // Look up the true cost server-side by planCode — same anti-double-margin pattern as Cable/Data.
    let costPrice;
    if (activeProvider === 'klubconnect') {
      const plansResult = await klubconnectSmilePlans();
      const rawPlans = Array.isArray(plansResult) ? plansResult : (plansResult?.data || plansResult?.PLAN || plansResult?.plans || []);
      const plan = (Array.isArray(rawPlans) ? rawPlans : []).find(p => String(p.plan_id ?? p.code ?? p.PLAN_ID ?? p.PACKAGE_ID) === String(planCode));
      if (!plan) return err(res, 'Selected plan is no longer available');
      costPrice = parseFloat(plan.amount ?? plan.price ?? plan.plan_amount ?? plan.PLAN_AMOUNT ?? 0);
    } else if (ispProvider === 'smile') {
      const rawPlans = await fetchAllBigisubPages('/api/v2/isp/smile/plans/');
      const plan = (Array.isArray(rawPlans) ? rawPlans : []).find(p => String(p.id) === String(planCode));
      if (!plan) return err(res, 'Selected plan is no longer available');
      costPrice = parseFloat(plan.plan_price ?? 0);
    } else {
      const rawPlans = await fetchAllBigisubPages('/api/v2/isp/spectranet/plans/');
      const plan = (Array.isArray(rawPlans) ? rawPlans : []).find(p => String(p.id) === String(planCode));
      if (!plan) return err(res, 'Selected plan is no longer available');
      costPrice = parseFloat(plan.price ?? 0) + parseFloat(plan.charges ?? 0);
    }

    const margin = await getEffectiveMargin(req.user.tier, 'isp');
    const sellingPrice = applyMargin(costPrice, margin);
    const label = ispProvider === 'smile' ? `Smile ISP data → ${accountId}` : `Spectranet ISP data → ${spectranetNumber}`;
    const transaction = await debitWallet(req.user.id, sellingPrice, 'isp', phone || accountId || spectranetNumber, label, { ispProvider, planCode, costPrice, sellingPrice, profit: sellingPrice - costPrice, provider: activeProvider, tier: req.user.tier || 'standard' });

    try {
      let providerRef;
      if (activeProvider === 'klubconnect') {
        const purchaseResult = await withProviderLog('klubconnect', 'isp', transaction.reference, { accountId, planCode }, async () => {
          const parsed = await klubconnectBuySmileData({ dataPlan: planCode, mobileNumber: accountId, requestId: transaction.reference });
          return { result: parsed, raw: parsed.raw };
        });
        providerRef = purchaseResult.providerRef;
      } else if (ispProvider === 'smile') {
        const payBody = { plan: Number(planCode), phone_number: phone || accountId, email: email || req.user.email, account_id: accountId, pin: process.env.BIGISUB_PIN };
        const { data: result } = await bigisub.post('/api/v2/isp/smile/topup/', payBody);
        await logProviderCall('bigisub', 'isp', transaction.reference, payBody, result, true);
        if (!result?.success) throw new Error(result?.message || 'Smile topup failed');
        providerRef = result.data?.reference || result.data?.transaction_id;
      } else {
        const payBody = { plan: Number(planCode), phone_number: phone || spectranetNumber, spectranet_number: spectranetNumber, quantity: quantity || 1, pin: process.env.BIGISUB_PIN };
        const { data: result } = await bigisub.post('/api/v2/isp/spectranet/topup/', payBody);
        await logProviderCall('bigisub', 'isp', transaction.reference, payBody, result, true);
        if (!result?.success) throw new Error(result?.message || 'Spectranet topup failed');
        providerRef = result.data?.reference || result.data?.transaction_id;
      }

      await supabase.from('transactions').update({ status: 'success', provider_ref: providerRef }).eq('reference', transaction.reference);
      await payReferralBonusIfFirstPurchase(transaction.user_id);
      ok(res, { transaction, providerRef }, 'ISP data purchase successful');
    } catch (providerErr) {
      await logProviderCall(activeProvider, 'isp', transaction.reference, { ispProvider, planCode }, providerErr.response?.data || { message: providerErr.message }, false, providerErr.message);
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

// ─── Social Boost (Bigisub Marketing Hub) ─────────────────────────────────
// Confirmed against rif.africa/technotronics Bigisub API docs (Marketing Hub, 22 endpoints):
//   GET  /api/v2/marketinghub/platforms/           → list platforms (Instagram, TikTok, etc)
//   GET  /api/v2/marketinghub/countries/           → list countries
//   GET  /api/v2/marketinghub/services/?platform=&category=&country= → browse services
//   POST /api/v2/marketinghub/order/create/        → place order (link optional; extra fields:
//                                                     comments, media, groups, answer_number,
//                                                     old_posts, type_of_traffic, google_keyword,
//                                                     referring_url)
//   GET  /api/v2/marketinghub/order/status/?order_id=X → check status
//   Also available (not yet wired here): order/receipt, order/history, order/cancel,
//   order/refill, order/refresh
//   GET  /api/v2/marketinghub/pricing-summary/     → { platforms: [{ name, display_name,
//                                                     min_price, max_price, service_count,
//                                                     sample_categories, price_range }] }

app.get('/api/v1/social/platforms', auth, async (req, res) => {
  try {
    const { data } = await bigisub.get('/api/v2/marketinghub/platforms/');
    const platforms = Array.isArray(data) ? data
      : Array.isArray(data?.data) ? data.data
      : Array.isArray(data?.data?.platforms) ? data.data.platforms
      : Array.isArray(data?.platforms) ? data.platforms
      : Array.isArray(data?.results) ? data.results
      : [];
    ok(res, platforms);
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/social/countries', auth, async (req, res) => {
  try {
    const { data } = await bigisub.get('/api/v2/marketinghub/countries/');
    const countries = Array.isArray(data) ? data
      : Array.isArray(data?.data) ? data.data
      : Array.isArray(data?.data?.countries) ? data.data.countries
      : Array.isArray(data?.countries) ? data.countries
      : Array.isArray(data?.results) ? data.results
      : [];
    ok(res, countries);
  } catch (e) { err(res, e.message); }
});

// The marketinghub/services endpoint is paginated (count/next/previous/results).
// Both the browse route and the order-time lookup need the FULL catalog, not just
// page 1 — otherwise a real, active service can look "not found" simply because
// it's on page 2+. This follows `next` until exhausted and concatenates results.
async function fetchAllBigisubServices(params) {
  let url = `/api/v2/marketinghub/services/?${params.toString()}`;
  let all = [];
  let guard = 0;
  while (url && guard < 50) {
    const { data } = await bigisub.get(url);
    const pageResults = Array.isArray(data) ? data
      : Array.isArray(data?.data) ? data.data
      : Array.isArray(data?.data?.services) ? data.data.services
      : Array.isArray(data?.data?.results) ? data.data.results
      : Array.isArray(data?.services) ? data.services
      : Array.isArray(data?.results) ? data.results
      : [];
    all = all.concat(pageResults);
    const next = data?.next ?? data?.data?.next ?? null;
    url = next ? next.replace(bigisub.defaults.baseURL, '') : null;
    guard++;
  }
  return all;
}

app.get('/api/v1/social/services', auth, async (req, res) => {
  try {
    const { platform, category, country } = req.query;
    if (!platform) return err(res, 'platform is required');
    const margin = await getEffectiveMargin(req.user.tier, 'social');
    const params = new URLSearchParams();
    params.set('platform', platform);
    if (category) params.set('category', category);
    if (country) params.set('country', country);
    const rawServices = await fetchAllBigisubServices(params);
    const services = (Array.isArray(rawServices) ? rawServices : []).map(sv => {
      const costPrice = parseFloat(sv.price ?? sv.rate ?? 0);
      return { ...sv, id: sv.service_id ?? sv.id, costPrice, sellingPrice: applyMargin(costPrice, margin) };
    });
    ok(res, services);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/social/order', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { platform, category, country, serviceId, link, quantity, comments, media, groups, answerNumber, oldPosts, typeOfTraffic, googleKeyword, referringUrl } = req.body;
    if (!platform) return err(res, 'platform is required');
    if (!serviceId) return err(res, 'serviceId is required');
    if (!quantity || quantity < 1) return err(res, 'quantity is required');

    const enabled = await isServiceEnabled('ALL', 'social');
    if (!enabled) return err(res, 'Social Boost is temporarily unavailable. Please try again later.', 503);

    // Look up true cost server-side by serviceId — same anti-double-margin pattern as ISP/Cable.
    const params = new URLSearchParams();
    params.set('platform', platform);
    if (category) params.set('category', category);
    if (country) params.set('country', country);
    const rawServices = await fetchAllBigisubServices(params);
    const service = rawServices.find(sv => String(sv.service_id ?? sv.id) === String(serviceId));
    if (!service) return err(res, 'Selected service is no longer available');
    const costPricePerUnit = parseFloat(service.price ?? service.rate ?? 0);

    const margin = await getEffectiveMargin(req.user.tier, 'social');
    const costPrice = costPricePerUnit * Number(quantity);
    const sellingPrice = applyMargin(costPrice, margin);
    const label = `Social Boost → ${platform} ${service.name || service.category || ''} x${quantity}`;
    const transaction = await debitWallet(req.user.id, sellingPrice, 'social', link || platform, label, { platform, category, country, serviceId, quantity, costPrice, sellingPrice, profit: sellingPrice - costPrice, provider: 'bigisub', tier: req.user.tier || 'standard' });

    try {
      const payBody = {
        service_id: serviceId,
        quantity: Number(quantity),
        ...(link ? { link } : {}),
        ...(comments ? { comments } : {}),
        ...(media ? { media } : {}),
        ...(groups ? { groups } : {}),
        ...(answerNumber ? { answer_number: answerNumber } : {}),
        ...(oldPosts ? { old_posts: oldPosts } : {}),
        ...(typeOfTraffic ? { type_of_traffic: typeOfTraffic } : {}),
        ...(googleKeyword ? { google_keyword: googleKeyword } : {}),
        ...(referringUrl ? { referring_url: referringUrl } : {}),
      };
      const { data: result } = await bigisub.post('/api/v2/marketinghub/order/create/', payBody);
      await logProviderCall('bigisub', 'social', transaction.reference, payBody, result, true);
      if (!result?.success) throw new Error(result?.message || 'Social Boost order failed');
      const providerRef = result.data?.order_id;

      await supabase.from('transactions').update({ status: 'success', provider_ref: providerRef }).eq('reference', transaction.reference);
      await payReferralBonusIfFirstPurchase(transaction.user_id);
      ok(res, { transaction, providerRef }, 'Social Boost order placed successfully');
    } catch (providerErr) {
      await logProviderCall('bigisub', 'social', transaction.reference, { platform, serviceId, quantity }, providerErr.response?.data || { message: providerErr.message }, false, providerErr.message);
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

app.get('/api/v1/social/order/status', auth, async (req, res) => {
  try {
    const { orderId } = req.query;
    if (!orderId) return err(res, 'orderId is required');
    const { data: result } = await bigisub.get(`/api/v2/marketinghub/order/status/?order_id=${encodeURIComponent(orderId)}`);
    if (!result?.success) return err(res, result?.message || 'Unable to fetch order status');
    ok(res, result.data);
  } catch (e) { err(res, e.message); }
});

// ─── Bulk SMS (Bigisub Communications API) ─────────────────────────────────
// Confirmed against rif.africa/technotronics Bigisub API docs (Communications, 4 endpoints):
//   GET  /api/v2/communications/sms/pricing/            → { cost_per_page, normal_chars_per_page: 160, unicode_chars_per_page: 70 }
//   POST /api/v2/communications/sms/send/                → body { recipients: [...], message, sender_name } (max 500 recipients)
//                                                           → { job_id, transaction_id, total_recipients, total_cost, pages_per_sms, message_type, status }
//   GET  /api/v2/communications/sms/job/{job_id}/status/ → per-recipient delivery status
//   GET  /api/v2/communications/sms/jobs/                → list all jobs
// Cost = cost_per_page × pages × recipients. Pages: normal SMS 160 chars/page, unicode 70 chars/page.

let smsPricingCache = { data: null, ts: 0 };
async function getBigisubSmsPricing() {
  const now = Date.now();
  if (smsPricingCache.data && now - smsPricingCache.ts < 60000) return smsPricingCache.data;
  const { data } = await bigisub.get('/api/v2/communications/sms/pricing/');
  if (!data?.success) throw new Error(data?.message || 'Unable to fetch SMS pricing');
  smsPricingCache = { data: data.data, ts: now };
  return data.data;
}

// Basic unicode check: if the message contains any character outside the GSM-7 printable
// range, Bigisub bills it as unicode (70 chars/page) instead of normal (160 chars/page).
function isUnicodeSms(message) {
  return /[^\x00-\x7F]/.test(message);
}
function calcSmsPages(message, normalCharsPerPage, unicodeCharsPerPage) {
  const unicode = isUnicodeSms(message);
  const perPage = unicode ? unicodeCharsPerPage : normalCharsPerPage;
  return { pages: Math.max(1, Math.ceil(message.length / perPage)), unicode };
}

app.get('/api/v1/sms/pricing', auth, async (req, res) => {
  try {
    const pricing = await getBigisubSmsPricing();
    const margin = await getEffectiveMargin(req.user.tier, 'sms');
    ok(res, { ...pricing, sellingCostPerPage: applyMargin(pricing.cost_per_page, margin) });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/sms/send', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { senderId, message, recipients } = req.body;
    if (!senderId || senderId.length > 11) return err(res, 'senderId is required (max 11 characters)');
    if (!message) return err(res, 'message is required');
    if (!Array.isArray(recipients) || recipients.length === 0) return err(res, 'recipients is required');
    if (recipients.length > 500) return err(res, 'Maximum 500 recipients per send');

    const enabled = await isServiceEnabled('ALL', 'sms');
    if (!enabled) return err(res, 'Bulk SMS is temporarily unavailable. Please try again later.', 503);

    const pricing = await getBigisubSmsPricing();
    const { pages, unicode } = calcSmsPages(message, pricing.normal_chars_per_page, pricing.unicode_chars_per_page);
    const costPrice = pricing.cost_per_page * pages * recipients.length;
    const margin = await getEffectiveMargin(req.user.tier, 'sms');
    const sellingPrice = applyMargin(costPrice, margin);

    const label = `Bulk SMS → ${senderId} x${recipients.length} (${pages} page${pages > 1 ? 's' : ''})`;
    const transaction = await debitWallet(req.user.id, sellingPrice, 'sms', senderId, label, {
      senderId, recipientCount: recipients.length, pages, messageType: unicode ? 'unicode' : 'normal',
      costPrice, sellingPrice, profit: sellingPrice - costPrice, provider: 'bigisub', tier: req.user.tier || 'standard', message,
    });

    try {
      const payBody = { recipients, message, sender_name: senderId };
      const { data: result } = await bigisub.post('/api/v2/communications/sms/send/', payBody);
      await logProviderCall('bigisub', 'sms', transaction.reference, payBody, result, true);
      if (!result?.success) throw new Error(result?.message || 'Bulk SMS send failed');

      const jobId = result.data?.job_id;
      await supabase
        .from('transactions')
        .update({
          status: 'success',
          provider_ref: jobId,
          metadata: {
            senderId, recipientCount: recipients.length, pages, messageType: unicode ? 'unicode' : 'normal',
            costPrice, sellingPrice, profit: sellingPrice - costPrice, provider: 'bigisub', tier: req.user.tier || 'standard',
            message, jobId,
          },
        })
        .eq('reference', transaction.reference);
      ok(res, { transaction, jobId, totalCost: result.data?.total_cost, pagesPerSms: result.data?.pages_per_sms, status: result.data?.status }, 'Bulk SMS job created successfully');
    } catch (providerErr) {
      await logProviderCall('bigisub', 'sms', transaction.reference, { senderId, recipientCount: recipients.length }, providerErr.response?.data || { message: providerErr.message }, false, providerErr.message);
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

app.get('/api/v1/sms/job/:jobId/status', auth, async (req, res) => {
  try {
    const { jobId } = req.params;
    const { data: result } = await bigisub.get(`/api/v2/communications/sms/job/${encodeURIComponent(jobId)}/status/`);
    if (!result?.success) return err(res, result?.message || 'Unable to fetch SMS job status');
    ok(res, result.data);
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/sms/jobs', auth, async (req, res) => {
  try {
    const { data: jobs, error } = await supabase
      .from('transactions')
      .select('reference, status, amount, description, metadata, created_at')
      .eq('user_id', req.user.id)
      .eq('category', 'sms')
      .order('created_at', { ascending: false });
    if (error) throw error;

    const formatted = (jobs || []).map(j => ({
      job_id: j.metadata?.jobId || j.reference,
      message: j.metadata?.message || j.description || '',
      status: j.status,
      sent_count: j.metadata?.recipientCount ?? 0,
      total_recipients: j.metadata?.recipientCount ?? 0,
      failed_count: 0,
      total_amount: j.amount,
      date_created: j.created_at,
    }));

    ok(res, formatted);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/vtu/recharge-pin', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { network, denomination, quantity, nameOnCard } = req.body;
    if (!network || !denomination) return err(res, 'network and denomination required');

    const enabled = await isServiceEnabled(network, 'recharge_pin');
    if (!enabled) return err(res, `${network} recharge pin is temporarily unavailable. Please try again later.`, 503);

    const activeProvider = await getProviderForRoute(network, 'recharge_pin');
    const qty = quantity || 1;

    if (activeProvider === 'klubconnect') {
      const wantedValue = String(denomination).replace(/[^\d]/g, '');
      const costPrice = Number(wantedValue) * qty; // KlubConnect EPIN sells at face value; adjust here if your account has a discount rate
      const margin = await getEffectiveMargin(req.user.tier, 'recharge_pin');
      const sellingPrice = applyMargin(costPrice, margin);
      const transaction = await debitWallet(req.user.id, sellingPrice, 'recharge_pin', null, `${network} ₦${denomination} pin x${qty} (KlubConnect)`, { network, denomination, quantity: qty, costPrice, sellingPrice, profit: sellingPrice - costPrice, provider: 'klubconnect', tier: req.user.tier || 'standard' });
      try {
        const payBody = { network, value: wantedValue, quantity: qty, requestId: transaction.reference };
        const parsed = await klubconnectBuyRechargePin(payBody);
        await logProviderCall('klubconnect', 'recharge_pin', transaction.reference, payBody, parsed.raw, true);
        await supabase.from('transactions').update({ status: 'success', provider_ref: parsed.providerRef, metadata: { pins: parsed.pins } }).eq('reference', transaction.reference);
        await payReferralBonusIfFirstPurchase(transaction.user_id);
        return ok(res, { transaction, pins: parsed.pins }, 'Recharge pins generated');
      } catch (providerErr) {
        await logProviderCall('klubconnect', 'recharge_pin', transaction.reference, { network, denomination, quantity: qty }, providerErr.response?.data || { message: providerErr.message }, false, providerErr.message);
        const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
        return err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
      }
    }

    const { data: plansResult } = await bigisub.get('/api/v2/vtu/recharge-pin/plans/');
    const plans = plansResult?.data || [];
    const networkId = Number(NETWORKS[network] || network);
    const wantedSize = String(denomination).replace(/[^\d]/g, '');
    const plan = plans.find(p => Number(p.network) === networkId && String(p.size).replace(/[^\d]/g, '') === wantedSize);
    if (!plan) return err(res, `No recharge pin plan found for ${network} ₦${denomination}`);

    const costPrice = Number(plan.regular_price) * qty;
    const margin = await getEffectiveMargin(req.user.tier, 'recharge_pin');
    const sellingPrice = applyMargin(costPrice, margin);
    const transaction = await debitWallet(req.user.id, sellingPrice, 'recharge_pin', null, `${network} ₦${denomination} pin x${qty}`, { network, denomination, quantity: qty, costPrice, sellingPrice, profit: sellingPrice - costPrice, tier: req.user.tier || 'standard' });
    try {
      const payBody = { plan: plan.id, quantity: qty, name_on_card: nameOnCard || req.user.full_name || 'Customer' };
      const { data: result } = await bigisub.post('/api/v2/vtu/recharge-pin/purchase/', { ...payBody, pin: process.env.BIGISUB_PIN });
      const parsed = parseBigisub(result);
      await logProviderCall('bigisub', 'recharge_pin', transaction.reference, payBody, result, true);
      await supabase.from('transactions').update({ status: 'success', provider_ref: parsed.providerRef, metadata: { pins: parsed.pins } }).eq('reference', transaction.reference);
      await payReferralBonusIfFirstPurchase(transaction.user_id);
      ok(res, { transaction, pins: parsed.pins }, 'Recharge pins generated');
    } catch (providerErr) {
      await logProviderCall('bigisub', 'recharge_pin', transaction.reference, { network, denomination, quantity: qty }, providerErr.response?.data || { message: providerErr.message }, false, providerErr.message);
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

// ─── AIRTIME-TO-CASH (manual review → Flutterwave payout) ─────────────────────

app.get('/api/v1/vtu/airtime-to-cash/receiving-numbers', auth, async (req, res) => {
  ok(res, AIRTIME_RECEIVE_NUMBERS);
});

app.post('/api/v1/vtu/airtime-to-cash', auth, requireUnfrozen, requireKYC, requireTransactionPin, async (req, res) => {
  try {
    const { network, airtimeAmount, senderPhone, payoutAccountNumber, payoutBankCode, payoutAccountName } = req.body;
    if (!network || !airtimeAmount || airtimeAmount < 200 || !senderPhone || !payoutAccountNumber || !payoutBankCode || !payoutAccountName) {
      return err(res, 'network, airtimeAmount (min ₦200), senderPhone, and payout account details are all required');
    }
    const receiveNumber = AIRTIME_RECEIVE_NUMBERS[network];
    if (!receiveNumber) return err(res, `Airtime-to-cash is not yet available for ${network}. Supported networks: ${Object.keys(AIRTIME_RECEIVE_NUMBERS).join(', ')}`);

    const cashAmount = Math.round(parseFloat(airtimeAmount) * 0.75 * 100) / 100;
    const wallet = await getWallet(req.user.id);
    const ref = genRef('A2C');
    await supabase.from('transactions').insert({
      user_id: req.user.id, wallet_id: wallet.id, type: 'debit', category: 'airtime_to_cash',
      amount: cashAmount, fee: 0, balance_before: wallet.balance, balance_after: wallet.balance,
      status: 'pending_review', reference: ref, phone: senderPhone,
      description: `Airtime-to-cash: ₦${airtimeAmount} ${network} → ₦${cashAmount} payout pending review`,
      metadata: { network, airtimeAmount, cashAmount, senderPhone, payoutAccountNumber, payoutBankCode, payoutAccountName, receiveNumber },
    });
    ok(res, { reference: ref, cashAmount, receiveNumber, status: 'pending_review' }, `Request submitted. Transfer the airtime to ${receiveNumber} now — your payout will be sent once we confirm it arrived.`);
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/vtu/airtime-to-cash/:reference', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('transactions').select('reference, status, amount, description, metadata, created_at').eq('reference', req.params.reference).eq('user_id', req.user.id).single();
    if (!data) return err(res, 'Not found', 404);
    ok(res, data);
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: airtime-to-cash review queue ───────────────────────────────────────

app.get('/api/v1/admin/airtime-to-cash/pending', auth, requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('transactions').select('*').eq('category', 'airtime_to_cash').eq('status', 'pending_review').order('created_at', { ascending: true });
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/admin/overview', auth, requireAdmin, async (req, res) => {
  try {
    const { data: wallets } = await supabase.from('wallets').select('balance');
    const totalWalletBalance = (wallets || []).reduce((sum, w) => sum + parseFloat(w.balance || 0), 0);

    const { count: totalUsers } = await supabase.from('users').select('*', { count: 'exact', head: true });

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const { count: transactionsToday } = await supabase.from('transactions').select('*', { count: 'exact', head: true }).gte('created_at', todayStart.toISOString());

    ok(res, { totalWalletBalance, totalUsers: totalUsers || 0, transactionsToday: transactionsToday || 0 });
  } catch (e) { err(res, e.message); }
});

// List today's transactions with the user's phone/name attached, for the
// admin dashboard's "Txns Today" card. Mirrors the same day-window used by
// /admin/overview's transactionsToday count above, so the number on the card
// and the length of this list always agree.
app.get('/api/v1/admin/transactions/today', auth, requireAdmin, async (req, res) => {
  try {
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);

    const { data, error } = await supabase
      .from('transactions')
      .select('id, reference, category, type, amount, status, created_at, users(phone, full_name)')
      .gte('created_at', todayStart.toISOString())
      .order('created_at', { ascending: false })
      .limit(200);

    if (error) throw new Error(error.message);

    ok(res, { transactions: data || [] });
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: COMMISSION / PROFIT SUMMARY ────────────────────────────────────
// Reads the `profit` field that's already being saved inside
// transactions.metadata on every successful sale (data, airtime, cable,
// electricity, exam, recharge_pin, betting) and sums it up.

app.get('/api/v1/admin/commission', auth, requireAdmin, async (req, res) => {
  try {
    // Only successful sales carry real profit — failed/reversed transactions
    // already get their sellingPrice refunded via creditWallet(), so they
    // must NOT be counted here. wallet_withdrawal is included here too — its
    // profit is the withdrawal fee (metadata.fee), same idea as the markup on
    // every other service, just named differently since it's a deduction from
    // payout rather than a markup on cost.
    const { data: txns } = await supabase
      .from('transactions')
      .select('category, amount, metadata, created_at')
      .eq('status', 'success')
      .in('category', ['data', 'airtime', 'cable', 'electric', 'exam', 'jamb', 'isp', 'social', 'sms', 'recharge_pin', 'betting', 'wallet_withdrawal']);

    const rows = txns || [];

    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const weekStart = new Date(todayStart);
    weekStart.setDate(weekStart.getDate() - weekStart.getDay()); // Sunday start
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

    let totalCommission = 0;
    let todayCommission = 0;
    let weekCommission = 0;
    let monthCommission = 0;
    const byService = {};

    for (const t of rows) {
      // profit is saved directly on metadata at purchase time — this is the
      // exact number your margin % produced for that sale. Withdrawals save
      // it as `fee` instead of `profit` since it's a deduction, not a markup.
      const profit = parseFloat(t.category === 'wallet_withdrawal' ? t.metadata?.fee : t.metadata?.profit);
      if (isNaN(profit)) continue; // skip any older rows saved before profit was tracked

      const createdAt = new Date(t.created_at);

      totalCommission += profit;
      if (createdAt >= todayStart) todayCommission += profit;
      if (createdAt >= weekStart) weekCommission += profit;
      if (createdAt >= monthStart) monthCommission += profit;

      if (!byService[t.category]) byService[t.category] = { commission: 0, count: 0 };
      byService[t.category].commission += profit;
      byService[t.category].count += 1;
    }

    // Round everything to 2dp for clean display
    const round2 = (n) => Math.round(n * 100) / 100;
    totalCommission = round2(totalCommission);
    todayCommission = round2(todayCommission);
    weekCommission = round2(weekCommission);
    monthCommission = round2(monthCommission);
    Object.keys(byService).forEach((k) => { byService[k].commission = round2(byService[k].commission); });

    ok(res, {
      totalCommission,
      todayCommission,
      weekCommission,
      monthCommission,
      byService, // { data: { commission, count }, airtime: {...}, ... }
      transactionCount: rows.length,
    }, 'Commission summary');
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: COMMISSION WITHDRAWALS (manual tracking, no auto-transfer) ────────
// Records that you personally moved money out of your business account.
// Does NOT touch Flutterwave or move any real money — it's just a ledger
// so the app can show "Available to withdraw" correctly.

app.get('/api/v1/admin/commission/withdrawals', auth, requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase
      .from('commission_withdrawals')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/admin/commission/withdrawals', auth, requireAdmin, async (req, res) => {
  try {
    const { amount, note } = req.body;
    if (!amount || isNaN(amount) || Number(amount) <= 0) return err(res, 'A valid amount greater than 0 is required');

    const { data: withdrawal, error } = await supabase
      .from('commission_withdrawals')
      .insert({
        amount: Number(amount),
        note: note || null,
        withdrawn_by: req.user.id,
      })
      .select('*')
      .single();

    if (error) throw new Error(error.message);
    logAdminAction(req.user.id, 'record_commission_withdrawal', 'commission_withdrawal', withdrawal?.id, { amount: Number(amount), note: note || null });
    ok(res, withdrawal, 'Withdrawal recorded');
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/admin/airtime-to-cash/network-totals', auth, requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('transactions').select('status, metadata').eq('category', 'airtime_to_cash');

    const blank = () => ({ collectedAirtime: 0, collectedCash: 0, collectedCount: 0, pendingAirtime: 0, pendingCash: 0, pendingCount: 0 });
    const totals = {};
    for (const network of Object.keys(AIRTIME_RECEIVE_NUMBERS)) totals[network] = blank();

    for (const txn of data || []) {
      const network = txn.metadata?.network;
      if (!network) continue;
      if (!totals[network]) totals[network] = blank();

      const airtimeAmount = parseFloat(txn.metadata?.airtimeAmount) || 0;
      const cashAmount = parseFloat(txn.metadata?.cashAmount) || 0;

      if (txn.status === 'success') {
        totals[network].collectedAirtime += airtimeAmount;
        totals[network].collectedCash += cashAmount;
        totals[network].collectedCount += 1;
      } else if (txn.status === 'pending_review') {
        totals[network].pendingAirtime += airtimeAmount;
        totals[network].pendingCash += cashAmount;
        totals[network].pendingCount += 1;
      }
    }

    ok(res, totals, 'Airtime-to-cash totals per network');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/admin/airtime-to-cash/:reference/approve', auth, requireAdmin, async (req, res) => {
  try {
    const { reference } = req.params;
    const { data: txn } = await supabase.from('transactions').select('*').eq('reference', reference).eq('category', 'airtime_to_cash').single();
    if (!txn) return err(res, 'Request not found', 404);
    if (txn.status !== 'pending_review') return err(res, `Already ${txn.status}`);

    const { payoutAccountNumber, payoutBankCode, payoutAccountName, cashAmount } = txn.metadata;
    const { data: result } = await flutterwave.post('/transfers', {
      account_bank: payoutBankCode,
      account_number: payoutAccountNumber,
      amount: Number(cashAmount),
      narration: 'Gora Data airtime-to-cash payout',
      currency: 'NGN',
      reference: `A2CPAY-${reference}`,
    });

    if (result?.status !== 'success') return err(res, result?.message || 'Payout could not be initiated');

    await supabase.from('transactions').update({
      status: 'success',
      provider_ref: String(result.data?.id || ''),
      metadata: { ...txn.metadata, flwTransferId: result.data?.id, flwTransferStatus: result.data?.status },
    }).eq('reference', reference);

    logAdminAction(req.user.id, 'approve_airtime_to_cash', 'transaction', reference, { flwTransferId: result.data?.id });
    ok(res, { reference, flwTransferId: result.data?.id }, 'Payout initiated — check Flutterwave for final settlement status');
  } catch (e) { err(res, e.message, e.status || 400); }
});

app.post('/api/v1/admin/airtime-to-cash/:reference/mark-paid', auth, requireAdmin, async (req, res) => {
  try {
    const { reference } = req.params;
    const { note } = req.body;
    const { data: txn } = await supabase.from('transactions').select('*').eq('reference', reference).eq('category', 'airtime_to_cash').single();
    if (!txn) return err(res, 'Request not found', 404);
    if (txn.status !== 'pending_review') return err(res, `Already ${txn.status}`);

    await supabase.from('transactions').update({
      status: 'success',
      metadata: { ...txn.metadata, manuallyPaidBy: req.user.id, manualNote: note || 'Paid manually via Flutterwave dashboard' },
    }).eq('reference', reference);

    logAdminAction(req.user.id, 'mark_airtime_to_cash_paid', 'transaction', reference, { note: note || null });
    ok(res, { reference }, 'Marked as paid');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/admin/airtime-to-cash/:reference/reject', auth, requireAdmin, async (req, res) => {
  try {
    const { reference } = req.params;
    const { reason } = req.body;
    const { data: txn } = await supabase.from('transactions').select('metadata, status').eq('reference', reference).eq('category', 'airtime_to_cash').single();
    if (!txn) return err(res, 'Request not found', 404);
    if (txn.status !== 'pending_review') return err(res, `Already ${txn.status}`);
    await supabase.from('transactions').update({ status: 'rejected', metadata: { ...txn.metadata, rejectReason: reason || 'Airtime not received' } }).eq('reference', reference);
    logAdminAction(req.user.id, 'reject_airtime_to_cash', 'transaction', reference, { reason: reason || null });
    ok(res, { reference }, 'Request rejected');
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: MANUAL WALLET ADJUSTMENT ───────────────────────────────────────────

app.post('/api/v1/admin/wallet/adjust', auth, requireAdmin, async (req, res) => {
  try {
    const { userId, amount, type, reason } = req.body; // type: 'credit' or 'debit'
    if (!userId || !amount || !type || !reason) return err(res, 'userId, amount, type (credit/debit) and reason are all required');
    if (!['credit', 'debit'].includes(type)) return err(res, "type must be 'credit' or 'debit'");
    if (Number(amount) <= 0) return err(res, 'amount must be greater than 0');

    const wallet = await getWallet(userId);
    if (!wallet) return err(res, 'User wallet not found', 404);

    if (type === 'credit') {
      const result = await creditWallet(userId, Number(amount), 'admin_adjustment', `Manual credit by admin: ${reason}`, { adjustedBy: req.user.id, reason });
      logAdminAction(req.user.id, 'wallet_credit', 'user', userId, { amount: Number(amount), reason });
      ok(res, result, 'Wallet credited');
    } else {
      if (parseFloat(wallet.balance) < Number(amount)) return err(res, 'User wallet balance is lower than the debit amount', 400);
      const ref = genRef('ADJ');
      const newBal = parseFloat(wallet.balance) - Number(amount);
      await supabase.from('wallets').update({ balance: newBal, ledger_balance: newBal, updated_at: new Date().toISOString() }).eq('id', wallet.id);
      await supabase.from('transactions').insert({ user_id: userId, wallet_id: wallet.id, type: 'debit', category: 'admin_adjustment', amount: Number(amount), fee: 0, balance_before: wallet.balance, balance_after: newBal, status: 'success', reference: ref, description: `Manual debit by admin: ${reason}`, metadata: { adjustedBy: req.user.id, reason } });
      logAdminAction(req.user.id, 'wallet_debit', 'user', userId, { amount: Number(amount), reason, reference: ref });
      ok(res, { reference: ref, newBalance: newBal }, 'Wallet debited');
    }
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/admin/wallet/adjustments', auth, requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('transactions').select('id, user_id, type, amount, description, metadata, created_at').eq('category', 'admin_adjustment').order('created_at', { ascending: false }).limit(100);
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

// List all registered users, newest first. Optional filters: role, tier, active, frozen.
// Paginated via page/limit (limit capped at 200, same convention as your other admin list routes).
app.get('/api/v1/admin/users', auth, requireAdmin, async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const from = (page - 1) * limit;
    const to = from + limit - 1;

    let q = supabase.from('users')
      .select('id, phone, email, full_name, role, tier, is_active, is_frozen, created_at, wallets(balance)', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(from, to);

    if (req.query.role) q = q.eq('role', req.query.role);
    if (req.query.tier) q = q.eq('tier', req.query.tier);
    if (req.query.active !== undefined) q = q.eq('is_active', req.query.active === 'true');
    if (req.query.frozen !== undefined) q = q.eq('is_frozen', req.query.frozen === 'true');

    const { data, count, error } = await q;
    if (error) throw new Error(error.message);

    ok(res, { users: data || [], page, limit, total: count ?? null, totalPages: count ? Math.ceil(count / limit) : null });
  } catch (e) { err(res, e.message); }
});

// ─── Expo Push Notifications ────────────────────────────────────────────────
// The app registers a device's Expo push token via /notifications/register-token,
// but until now nothing ever actually sent to it — notifyUser() only wrote an
// in-app row and an SMS. This calls Expo's push API so users get a real phone
// notification (wallet credited, purchase done, admin broadcast, etc.).
const expoPush = axios.create({ baseURL: 'https://exp.host/--/api/v2/push', timeout: 15000, headers: { 'Content-Type': 'application/json', Accept: 'application/json' } });

async function sendExpoPush(pushToken, title, body, data = {}) {
  if (!pushToken || typeof pushToken !== 'string' || !pushToken.startsWith('ExponentPushToken')) return;
  try {
    const { data: result } = await expoPush.post('/send', {
      to: pushToken,
      title,
      body,
      data,
      sound: 'default',
      priority: 'high',
    });
    // Expo's own delivery-error signal (e.g. token was revoked/uninstalled) comes back
    // inside a 200 response, not as an HTTP error — clean up the dead token so we stop
    // wasting calls on it.
    const ticket = Array.isArray(result?.data) ? result.data[0] : result?.data;
    if (ticket?.status === 'error' && ticket?.details?.error === 'DeviceNotRegistered') {
      return { deadToken: true };
    }
  } catch (e) {
    console.error('sendExpoPush failed:', e.message);
  }
}

// Requires a `notifications` table: id, user_id, type, title, message, is_read, created_at, sent_by.
// Delivers via SMS (reusing your existing Termii sendSMS) and always logs an in-app
// notification row so the user sees it in-app even if SMS fails or they have no credit.
async function notifyUser(userId, phone, title, body, adminId, type = 'admin_message') {
  await supabase.from('notifications').insert({ user_id: userId, type, title, message: body, is_read: false, sent_by: adminId, created_at: new Date().toISOString() });
  if (phone) { try { await sendSMS(phone, `${title ? title + ': ' : ''}${body}`); } catch (e) { console.error('notifyUser SMS failed:', e.message); } }
  try {
    const pushRecord = await kvGet(`push_token:${userId}`);
    const pushToken = pushRecord?.token || (typeof pushRecord === 'string' ? pushRecord : null); // tolerate the old string-only format already saved for existing users
    if (pushToken) {
      const result = await sendExpoPush(pushToken, title || APP_NAME, body, { type });
      if (result?.deadToken) await kvDel(`push_token:${userId}`).catch(() => {});
    }
  } catch (e) { console.error('notifyUser push failed:', e.message); }
}

// ─── Admin audit log ────────────────────────────────────────────────────────
// See admin_audit_log.sql for the table. Every admin action that changes state (as
// opposed to just viewing a list) calls this so there's always a WHO/WHAT/WHEN/WHY
// trail — the gap being closed here is that freeze/block previously recorded no
// admin identity at all, and even routes that did record one (pin reset, wallet
// adjust) each did it their own way, scattered across different columns instead of
// one queryable place. Never let a logging failure block the actual admin action —
// that would make the audit log more fragile than the thing it's supposed to make
// safer, so this always runs fire-and-forget with its own catch.
function logAdminAction(adminId, action, targetType, targetId, details = {}) {
  supabase.from('admin_audit_log').insert({
    admin_id: adminId,
    action,
    target_type: targetType,
    target_id: targetId ? String(targetId) : null,
    details,
    created_at: new Date().toISOString(),
  }).then(({ error }) => {
    if (error) console.error('logAdminAction failed:', error.message, { action, targetType, targetId });
  });
}

// Message a single user.
app.post('/api/v1/admin/users/:userId/message', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { title, body } = req.body;
    if (!body) return err(res, 'body is required');
    const { data: user } = await supabase.from('users').select('id, phone').eq('id', userId).single();
    if (!user) return err(res, 'User not found', 404);
    await notifyUser(user.id, user.phone, title, body, req.user.id);
    logAdminAction(req.user.id, 'message_user', 'user', userId, { title, body });
    ok(res, null, 'Message sent');
  } catch (e) { err(res, e.message); }
});

// Message many users at once, filtered the same way GET /api/v1/admin/users is
// (role, tier, active, frozen) — e.g. message everyone who's inactive, or every VIP.
app.post('/api/v1/admin/users/message-bulk', auth, requireAdmin, async (req, res) => {
  try {
    const { title, body, role, tier, active, frozen } = req.body;
    if (!body) return err(res, 'body is required');

    let q = supabase.from('users').select('id, phone');
    if (role) q = q.eq('role', role);
    if (tier) q = q.eq('tier', tier);
    if (active !== undefined) q = q.eq('is_active', active);
    if (frozen !== undefined) q = q.eq('is_frozen', frozen);

    const { data: users, error } = await q;
    if (error) throw new Error(error.message);
    if (!users?.length) return ok(res, { sent: 0 }, 'No users matched that filter');

    await Promise.all(users.map(u => notifyUser(u.id, u.phone, title, body, req.user.id)));
    logAdminAction(req.user.id, 'message_bulk', 'user_filter', null, { title, body, filters: { role, tier, active, frozen }, sentCount: users.length });
    ok(res, { sent: users.length }, `Message sent to ${users.length} user(s)`);
  } catch (e) { err(res, e.message); }
});

// ─── Admin: Account Deletion Requests ──────────────────────────────────────
app.get('/api/v1/admin/account-deletions', auth, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id, phone, email, full_name, deletion_status, deletion_requested_at, deletion_reason, wallets(balance)')
      .eq('deletion_status', 'pending')
      .order('deletion_requested_at', { ascending: true });
    if (error) throw new Error(error.message);
    ok(res, data);
  } catch (e) { err(res, e.message); }
});

// Anonymizes PII but keeps the row (and its id) so past transactions still trace correctly.
// Wallet/transactions are untouched — deletion is only allowed once balance is 0 anyway.
app.post('/api/v1/admin/account-deletions/:userId/approve', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { data: user } = await supabase.from('users').select('deletion_status').eq('id', userId).single();
    if (!user) return err(res, 'User not found', 404);
    if (user.deletion_status !== 'pending') return err(res, 'This user has no pending deletion request.', 400);

    const wallet = await getWallet(userId);
    if (wallet && parseFloat(wallet.balance) > 0) {
      return err(res, 'User wallet balance is not zero — cannot approve deletion.', 400, { balance: wallet.balance });
    }

    await supabase.from('users').update({
      full_name: 'Deleted User',
      email: null,
      phone: null,
      bvn: null,
      nin: null,
      pin_hash: null,
      is_active: false,
      deletion_status: 'approved',
      deleted_at: new Date().toISOString(),
    }).eq('id', userId);

    logAdminAction(req.user.id, 'approve_deletion_request', 'user', userId, {});
    ok(res, { deletionStatus: 'approved' }, 'Account deleted.');
  } catch (e) { err(res, e.message); }
});

// Direct admin-initiated deletion — same anonymization + zero-balance safety
// check as /account-deletions/:userId/approve above, but doesn't require the
// user to have requested it first. Lets an admin remove a user directly from
// AdminUsersScreen.
app.post('/api/v1/admin/users/:userId/delete', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { data: user } = await supabase.from('users').select('id, deletion_status').eq('id', userId).single();
    if (!user) return err(res, 'User not found', 404);
    if (user.deletion_status === 'approved') return err(res, 'This user is already deleted.', 400);

    const wallet = await getWallet(userId);
    if (wallet && parseFloat(wallet.balance) > 0) {
      return err(res, 'User wallet balance is not zero — cannot delete.', 400, { balance: wallet.balance });
    }

    await supabase.from('users').update({
      full_name: 'Deleted User',
      email: null,
      phone: null,
      bvn: null,
      nin: null,
      pin_hash: null,
      is_active: false,
      deletion_status: 'approved',
      deleted_at: new Date().toISOString(),
    }).eq('id', userId);

    logAdminAction(req.user.id, 'delete_user', 'user', userId, {});
    ok(res, { deletionStatus: 'approved' }, 'Account deleted.');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/admin/account-deletions/:userId/reject', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { reason } = req.body || {};
    if (!reason) return err(res, 'reason is required');

    const { data: user } = await supabase.from('users').select('deletion_status, phone').eq('id', userId).single();
    if (!user) return err(res, 'User not found', 404);
    if (user.deletion_status !== 'pending') return err(res, 'This user has no pending deletion request.', 400);

    await supabase.from('users').update({
      deletion_status: 'none',
      deletion_requested_at: null,
      deletion_rejected_reason: reason,
    }).eq('id', userId);

    await notifyUser(userId, user.phone, 'Account deletion request declined', reason, req.user.id);
    logAdminAction(req.user.id, 'reject_deletion_request', 'user', userId, { reason });
    ok(res, { deletionStatus: 'none' }, 'Deletion request rejected.');
  } catch (e) { err(res, e.message); }
});

// A user's own inbox — what they see in-app.
// NOTE: notification reads/writes are standardized on the `type, title, message, is_read`
// columns below (that's what the frontend and the unread-count/mark-read endpoints use).
// A second, inconsistent version of this route used to exist further down using
// `body`/`read_at` instead — Express only ever ran this first one and silently ignored the
// other, which meant notification text and read-status never matched what the app expected.
// That duplicate has been removed so there's only one source of truth.

app.get('/api/v1/admin/users/search', auth, requireAdmin, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) return err(res, 'q (search query) is required');
    const { data } = await supabase.from('users').select('id, phone, email, full_name, role, is_active, is_frozen').or(`phone.ilike.%${q}%,email.ilike.%${q}%,full_name.ilike.%${q}%`).limit(20);
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: WALLET FREEZE (spend-lock) & ACCOUNT BLOCK (login-lock) ───────────

app.post('/api/v1/admin/users/:userId/freeze', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { frozen, reason } = req.body;
    if (typeof frozen !== 'boolean') return err(res, 'frozen (boolean) is required');
    const { error } = await supabase.from('users').update({
      is_frozen: frozen,
      frozen_reason: frozen ? (reason || 'Frozen by admin') : null,
      frozen_at: frozen ? new Date().toISOString() : null,
    }).eq('id', userId);
    if (error) throw new Error(error.message);
    logAdminAction(req.user.id, frozen ? 'freeze_user' : 'unfreeze_user', 'user', userId, { reason: reason || null });
    ok(res, { userId, frozen }, frozen ? 'Wallet frozen' : 'Wallet unfrozen');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/admin/users/:userId/block', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { blocked } = req.body;
    if (typeof blocked !== 'boolean') return err(res, 'blocked (boolean) is required');
    const { error } = await supabase.from('users').update({ is_active: !blocked }).eq('id', userId);
    if (error) throw new Error(error.message);
    logAdminAction(req.user.id, blocked ? 'block_user' : 'unblock_user', 'user', userId, {});
    ok(res, { userId, blocked }, blocked ? 'User blocked' : 'User unblocked');
  } catch (e) { err(res, e.message); }
});

// Clears the user's transaction PIN (does not require the old one) — use when a user is
// locked out or has forgotten their PIN. The user simply sets a fresh PIN next time they
// try to buy something or open Settings; nothing else about their account changes.
app.post('/api/v1/admin/users/:userId/pin/reset', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { error } = await supabase.from('users').update({
      pin_hash: null,
      pin_failed_attempts: 0,
      pin_locked_until: null,
      pin_reset_by: req.user.id,
      pin_reset_at: new Date().toISOString(),
    }).eq('id', userId);
    if (error) throw new Error(error.message);
    logAdminAction(req.user.id, 'reset_pin', 'user', userId, {});
    ok(res, { userId }, "User's transaction PIN has been reset — they'll be asked to set a new one");
  } catch (e) { err(res, e.message); }
});

// Sets a new temporary password for a user who's locked out of their account (unlike PIN reset,
// login password can't be left blank — the user needs *something* to log in with). Returns the
// temp password once in the response so the admin can relay it to the user out-of-band (call,
// verified support ticket, etc.) after confirming identity — never send it back over an
// unauthenticated channel. The user should change it immediately after logging in.
app.post('/api/v1/admin/users/:userId/password/reset', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { data: targetUser } = await supabase.from('users').select('id').eq('id', userId).single();
    if (!targetUser) return err(res, 'User not found', 404);

    const tempPassword = genTempPassword();
    const passwordHash = await bcrypt.hash(tempPassword, 12);
    const { error } = await supabase.from('users').update({
      password_hash: passwordHash,
      password_reset_by: req.user.id,
      password_reset_at: new Date().toISOString(),
    }).eq('id', userId);
    if (error) throw new Error(error.message);

    logAdminAction(req.user.id, 'reset_password', 'user', userId, {});
    ok(res, { userId, tempPassword }, 'Temporary password generated — share it with the user securely, they should change it after logging in');
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/banks', auth, async (req, res) => {
  try {
    const { data } = await flutterwave.get('/banks/NG');
    ok(res, data?.data || []);
  } catch (e) { err(res, e.message); }
});

// ─── WALLET WITHDRAWAL SETTINGS (enable/disable, max per withdrawal) ──────────
// The commission percentage lives in service_margins under service: 'withdrawal', reusing the
// existing pricing endpoints (GET/PUT /api/v1/admin/pricing) — no separate storage needed for that.
// enabled/maxAmount aren't per-network or tiered, so kv_store is a simpler fit than a new table.
const getWithdrawalSettings = async () => {
  const stored = await kvGet('withdrawal_settings');
  return { enabled: stored?.enabled !== false, maxAmount: stored?.maxAmount ?? null };
};

app.get('/api/v1/wallet/withdraw/settings', auth, async (req, res) => {
  try {
    const settings = await getWithdrawalSettings();
    ok(res, settings);
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/admin/withdrawal-settings', auth, requireAdmin, async (req, res) => {
  try {
    const settings = await getWithdrawalSettings();
    ok(res, settings);
  } catch (e) { err(res, e.message); }
});

app.put('/api/v1/admin/withdrawal-settings', auth, requireAdmin, async (req, res) => {
  try {
    const { enabled, maxAmount } = req.body;
    const current = await getWithdrawalSettings();
    const next = {
      enabled: typeof enabled === 'boolean' ? enabled : current.enabled,
      maxAmount: maxAmount === undefined ? current.maxAmount : (maxAmount === null || maxAmount === '' ? null : Number(maxAmount)),
    };
    if (next.maxAmount !== null && (isNaN(next.maxAmount) || next.maxAmount <= 0)) return err(res, 'maxAmount must be a positive number or null (no limit)');
    await kvSet('withdrawal_settings', next);
    logAdminAction(req.user.id, 'update_withdrawal_settings', 'settings', 'withdrawal', next);
    ok(res, next, 'Withdrawal settings updated');
  } catch (e) { err(res, e.message); }
});

// Resolves the account holder's name for a bank account before a withdrawal.
app.get('/api/v1/wallet/resolve-account', auth, async (req, res) => {
  try {
    const { accountNumber, bankCode } = req.query;
    if (!accountNumber || !bankCode) return err(res, 'accountNumber and bankCode are required');
    const { data: result } = await flutterwave.post('/accounts/resolve', { account_number: accountNumber, account_bank: bankCode });
    if (result?.status !== 'success' || !result?.data?.account_name) return err(res, result?.message || 'Could not verify this account');
    ok(res, { accountName: result.data.account_name });
  } catch (e) { err(res, e.response?.data?.message || e.message, e.status || 400); }
});

app.post('/api/v1/wallet/withdraw', sensitiveLimiter, auth, requireUnfrozen, requireKYC, requireTransactionPin, async (req, res) => {
  try {
    const { amount, accountNumber, bankCode, accountName } = req.body;
    const amt = parseFloat(amount);
    if (!amt || amt < 100) return err(res, 'Minimum withdrawal is \u20a6100');
    if (!accountNumber || !bankCode || !accountName) return err(res, 'accountNumber, bankCode, and accountName are required');

    const settings = await getWithdrawalSettings();
    if (!settings.enabled) return err(res, 'Withdrawals are temporarily unavailable — please try again later', 403);
    if (settings.maxAmount !== null && amt > settings.maxAmount) return err(res, `Maximum withdrawal is \u20a6${settings.maxAmount.toLocaleString()} per transaction`);

    const wallet = await getWallet(req.user.id);
    if (!wallet || parseFloat(wallet.balance) < amt) return err(res, 'Insufficient wallet balance', 402);

    // Your commission on the withdrawal — comes off the payout, not on top of what the customer
    // pays, same convention as every other service's markup (service: 'withdrawal' in service_margins,
    // editable from Admin → Pricing & Margins like any other service).
    const margins = await getMargins();
    const feePercent = margins['withdrawal'] || 0;
    const fee = Math.round(amt * (feePercent / 100) * 100) / 100;
    const payoutAmount = Math.round((amt - fee) * 100) / 100;
    if (payoutAmount <= 0) return err(res, 'Withdrawal amount is too small after fees');

    let transaction;
    try {
      transaction = await debitWallet(req.user.id, amt, 'wallet_withdrawal', accountNumber, `Withdrawal to ${accountName} \u2014 ${bankCode} (${accountNumber})`, { accountNumber, bankCode, accountName, feePercent, fee, payoutAmount });
    } catch (e) {
      return err(res, e.message, e.status || 400);
    }

    try {
      const { data: result } = await flutterwave.post('/transfers', {
        account_bank: bankCode,
        account_number: accountNumber,
        amount: payoutAmount,
        narration: 'Gora Data wallet withdrawal',
        currency: 'NGN',
        reference: transaction.reference,
      });

      if (result?.status !== 'success') {
        await supabase.from('transactions').update({ status: 'failed' }).eq('reference', transaction.reference);
        await creditWallet(req.user.id, amt, 'reversal', `Reversal: withdrawal could not be initiated \u2014 ${result?.message || 'unknown error'}`);
        return err(res, result?.message || 'Withdrawal could not be initiated \u2014 you have not been charged');
      }

      await supabase.from('transactions').update({
        status: 'pending_review',
        provider_ref: String(result.data?.id || ''),
        metadata: { accountNumber, bankCode, accountName, feePercent, fee, payoutAmount, flwTransferId: result.data?.id, flwTransferStatus: result.data?.status },
      }).eq('reference', transaction.reference);

      ok(res, { reference: transaction.reference, payoutAmount, fee, newBalance: transaction.new_balance ?? transaction.newBalance }, 'Withdrawal is on its way \u2014 you will see it reflected in your bank shortly');
    } catch (transferErr) {
      // axios throws on ANY non-2xx response by default — so a clear, immediate rejection from
      // Flutterwave (e.g. "Transfers are disabled for this merchant", invalid account, etc.)
      // ends up here too, not in the `result?.status !== 'success'` branch above, which in
      // practice can only ever be reached if Flutterwave returns a 2xx with a non-success body.
      // transferErr.response means Flutterwave actually answered with an error status — that's
      // a definite outcome, not an ambiguous one, so refund immediately and tell the customer
      // the real reason instead of leaving them waiting on a "pending_review" that will never
      // resolve on its own. Only a true network-level failure (no response at all — timeout,
      // DNS, connection reset) is genuinely ambiguous, since we can't know if Flutterwave ever
      // received/processed the request; that case still needs pending_review + reconciliation.
      if (transferErr.response) {
        const flwMessage = transferErr.response.data?.message || 'Withdrawal could not be initiated';
        await supabase.from('transactions').update({ status: 'failed', metadata: { ...transaction.metadata, accountNumber, bankCode, accountName, feePercent, fee, payoutAmount, flwRejectionMessage: flwMessage } }).eq('reference', transaction.reference);
        await creditWallet(req.user.id, amt, 'reversal', `Reversal: withdrawal rejected \u2014 ${flwMessage}`);
        console.error(`Withdrawal ${transaction.reference} rejected by Flutterwave (${transferErr.response.status}):`, flwMessage);
        return err(res, `${flwMessage} \u2014 you have not been charged`);
      }
      await supabase.from('transactions').update({ status: 'pending_review' }).eq('reference', transaction.reference);
      console.error(`Withdrawal ${transaction.reference} left pending_review (no response from Flutterwave \u2014 network/timeout):`, transferErr.message);
      ok(res, { reference: transaction.reference }, 'Withdrawal submitted \u2014 we are confirming with our payment partner, this can take a few minutes');
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

app.get('/api/v1/vtu/provider/balance', auth, requireAdmin, async (req, res) => {
  try {
    const provider = await getActiveProvider();
    if (provider === 'klubconnect') {
      const data = await klubconnectBalance();
      ok(res, { provider, ...data });
    } else {
      // Bigisub's confirmed balance endpoint (per their WhatsApp API announcement) is
      // GET /api/v2/financial/wallet/balance/ — the old '/balance' path was never a real
      // Bigisub route and would have 404'd. Response is normalized defensively since the
      // balance may come back nested under `data` or under a differently-cased key.
      const { data } = await bigisub.get('/api/v2/financial/wallet/balance/');
      const inner = data?.data && typeof data.data === 'object' ? data.data : data;
      const balance = parseFloat(inner?.balance ?? inner?.wallet_balance ?? inner?.amount ?? 0);
      ok(res, { provider, balance, raw: data });
    }
  } catch (e) { err(res, e.message); }
});

// ─── BETTING WALLET FUNDING ─────────────────────────────────────────────────────

// `billerCode`/`customerId` below refer to the betting company (e.g. bet9ja, sportybet) and the
// customer's betting account ID — same shape for both providers.
app.get('/api/v1/betting/billers', auth, async (req, res) => {
  try {
    const activeProvider = await getProviderForRoute('ALL', 'betting');
    if (activeProvider === 'klubconnect') {
      const result = await klubconnectBettingCompanies();
      const rawList = Array.isArray(result) ? result : (result?.data || result?.companies || []);
      const billers = (Array.isArray(rawList) ? rawList : []).map(b => ({
        code: b.company_code ?? b.code ?? b.BettingCompany, name: b.company_name ?? b.name ?? b.BettingCompany,
      }));
      return ok(res, billers);
    }
    const { data } = await bigisub.get('/api/v2/betting/billers/');
    ok(res, data?.data || []);
  } catch (e) { err(res, e.message); }
});

// KlubConnect has no separate "products" list per biller for betting (just verify + fund),
// so on KlubConnect this returns an empty list rather than erroring — the frontend can skip
// straight to verify/fund once a biller is picked.
app.get('/api/v1/betting/products', auth, async (req, res) => {
  try {
    const { billerCode } = req.query;
    if (!billerCode) return err(res, 'billerCode is required');
    const activeProvider = await getProviderForRoute('ALL', 'betting');
    if (activeProvider === 'klubconnect') {
      return ok(res, []);
    }
    const { data } = await bigisub.get('/api/v2/betting/products/', { params: { biller_code: billerCode } });
    ok(res, data?.data || []);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/betting/validate', auth, async (req, res) => {
  try {
    const { billerCode, customerId } = req.body;
    if (!billerCode || !customerId) return err(res, 'billerCode and customerId are required');
    const activeProvider = await getProviderForRoute('ALL', 'betting');

    if (activeProvider === 'klubconnect') {
      const result = await klubconnectVerifyBettingCustomer({ bettingCompany: billerCode, customerId });
      if (!result?.customer_name) return err(res, result?.remark || result?.status || 'Could not validate customer ID');
      return ok(res, { customerName: result.customer_name, validationReference: null, requiresValidationRef: false, minAmount: null, maxAmount: null });
    }

    const { data: result } = await bigisub.post('/api/v2/betting/validate/', { biller_code: billerCode, customer_id: customerId });
    const inner = result?.data || result;
    const success = result?.success === true || inner?.valid === true;
    if (!success) return err(res, result?.message || 'Could not validate customer ID');
    ok(res, { customerName: inner?.customer_name, validationReference: inner?.validation_reference, requiresValidationRef: !!inner?.requires_validation_ref, minAmount: inner?.min_amount, maxAmount: inner?.max_amount });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/betting/fund', auth, requireUnfrozen, requireTransactionPin, async (req, res) => {
  try {
    const { billerCode, customerId, amount, phone } = req.body;
    if (!billerCode || !customerId || !amount) return err(res, 'billerCode, customerId and amount are required');

    const enabled = await isServiceEnabled('ALL', 'betting');
    if (!enabled) return err(res, 'Betting wallet funding is temporarily unavailable. Please try again later.', 503);

    const activeProvider = await getProviderForRoute('ALL', 'betting');
    const costPrice = parseFloat(amount);
    const margin = await getEffectiveMargin(req.user.tier, 'betting');
    const sellingPrice = applyMargin(costPrice, margin);
    const transaction = await debitWallet(req.user.id, sellingPrice, 'betting', phone, `${billerCode} wallet funding (${customerId})`, { billerCode, customerId, costPrice, sellingPrice, profit: sellingPrice - costPrice, provider: activeProvider, tier: req.user.tier || 'standard' });

    if (activeProvider === 'klubconnect') {
      try {
        const verifyResult = await klubconnectVerifyBettingCustomer({ bettingCompany: billerCode, customerId });
        if (!verifyResult?.customer_name) throw new Error(verifyResult?.remark || verifyResult?.status || 'Customer ID validation failed');
        const customerName = verifyResult.customer_name;

        const result = await withProviderLog('klubconnect', 'betting', transaction.reference, { billerCode, customerId, amount }, async () => {
          const parsed = await klubconnectFundBetting({ bettingCompany: billerCode, customerId, amount: Number(amount), requestId: transaction.reference });
          return { result: parsed, raw: parsed.raw };
        });
        await supabase.from('transactions').update({ status: 'success', provider_ref: result.providerRef, metadata: { customerName } }).eq('reference', transaction.reference);
        await payReferralBonusIfFirstPurchase(transaction.user_id);
        return ok(res, { transaction, customerName, providerTransactionId: result.providerRef }, 'Betting wallet funded');
      } catch (providerErr) {
        const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
        return err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
      }
    }

    try {
      const { data: validateResult } = await bigisub.post('/api/v2/betting/validate/', { biller_code: billerCode, customer_id: customerId });
      const validateInner = validateResult?.data || validateResult;
      const validateSuccess = validateResult?.success === true || validateInner?.valid === true;
      if (!validateSuccess) throw new Error(validateResult?.message || 'Customer ID validation failed');
      const customerName = validateInner?.customer_name;
      const validationReference = validateInner?.validation_reference;

      const fundBody = { biller_code: billerCode, customer_id: customerId, customer_name: customerName, amount: Number(amount) };
      if (validateInner?.requires_validation_ref && validationReference) fundBody.validation_reference = validationReference;

      const { data: result } = await bigisub.post('/api/v2/betting/fund/', { ...fundBody, pin_code: process.env.BIGISUB_PIN });
      const inner = result?.data || result;
      const success = result?.success === true || inner?.status === 'successful';
      if (!success) throw new Error(result?.message || 'Betting wallet funding failed');

      await logProviderCall('bigisub', 'betting', transaction.reference, fundBody, result, true);
      await supabase.from('transactions').update({ status: 'success', provider_ref: inner?.transaction_id, metadata: { customerName, statusDetail: inner?.status_detail } }).eq('reference', transaction.reference);
      await payReferralBonusIfFirstPurchase(transaction.user_id);
      ok(res, { transaction, customerName, providerTransactionId: inner?.transaction_id }, 'Betting wallet funded');
    } catch (providerErr) {
      await logProviderCall('bigisub', 'betting', transaction.reference, { billerCode, customerId, amount }, providerErr.response?.data || { message: providerErr.message }, false, providerErr.message);
      const { refunded } = await handlePurchaseFailure(transaction, providerErr, req.user, sellingPrice);
      err(res, refunded ? `${providerErr.message} — refunded to your wallet.` : `${providerErr.message} — this is under review, you'll be refunded if it didn't go through.`, 400, { refunded });
    }
  } catch (e) { err(res, e.message, e.status || 400); }
});

app.get('/api/v1/betting/requery', auth, async (req, res) => {
  try {
    const { transactionId } = req.query;
    if (!transactionId) return err(res, 'transactionId is required');
    const { data } = await bigisub.get('/api/v2/betting/requery/', { params: { transaction_id: transactionId } });
    ok(res, data?.data || data);
  } catch (e) { err(res, e.message); }
});

// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────
app.get('/api/v1/notifications', auth, async (req, res) => {
  try {
    const { data } = await supabase.from('notifications').select('id, type, title, message, is_read, created_at').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(20);
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/notifications/unread-count', auth, async (req, res) => {
  try {
    const { count } = await supabase.from('notifications').select('*', { count: 'exact', head: true }).eq('user_id', req.user.id).eq('is_read', false);
    ok(res, { count: count || 0 });
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/notifications/mark-read', auth, async (req, res) => {
  try {
    await supabase.from('notifications').update({ is_read: true }).eq('user_id', req.user.id).eq('is_read', false);
    ok(res, null, 'Marked as read');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/notifications/:id/mark-read', auth, async (req, res) => {
  try {
    const { error } = await supabase.from('notifications').update({ is_read: true }).eq('id', req.params.id).eq('user_id', req.user.id);
    if (error) throw new Error(error.message);
    ok(res, null, 'Marked as read');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/notifications/register-token', auth, async (req, res) => {
  try {
    // NOTE: the app sends { pushToken, platform } — this used to read req.body.token,
    // which meant every registration silently failed (client swallows the error) and
    // no push token was ever actually stored.
    const { pushToken, platform } = req.body;
    if (!pushToken) return err(res, 'pushToken is required');
    await kvSet(`push_token:${req.user.id}`, { token: pushToken, platform: platform || null, updatedAt: new Date().toISOString() });
    ok(res, null, 'Push token registered');
  } catch (e) { err(res, e.message); }
});

// ─── REFERRAL ──────────────────────────────────────────────────────────────
app.get('/api/v1/referrals', auth, async (req, res) => {
  try {
    const { data: userRow } = await supabase.from('users').select('referral_code').eq('id', req.user.id).single();
    const { data: referred } = await supabase.from('users').select('id, full_name, phone, created_at').eq('referred_by', req.user.id);

    // Pull actual referral bonus payouts tied to this referrer, so bonusEarned/totalEarned
    // reflect real credited amounts instead of a hardcoded 0. Only purchases (not signup or
    // funding) trigger a payout, so a referred user with no bonus simply hasn't bought yet.
    const { data: bonusTxns } = await supabase
      .from('transactions')
      .select('amount, metadata')
      .eq('user_id', req.user.id)
      .eq('category', 'referral_bonus');

    const bonusByReferredId = {};
    let totalEarned = 0;
    for (const t of bonusTxns || []) {
      const rid = t.metadata?.referredUserId;
      const amt = Number(t.amount) || 0;
      if (rid) bonusByReferredId[rid] = (bonusByReferredId[rid] || 0) + amt;
      totalEarned += amt;
    }

    ok(res, {
      code: userRow?.referral_code,
      link: `${process.env.FRONTEND_URL || 'https://goradata.ng'}/register?ref=${userRow?.referral_code}`,
      referredCount: referred?.length || 0,
      totalEarned,
      referrals: (referred || []).map(r => ({ id: r.id, name: r.full_name, joinedAt: r.created_at, bonusEarned: bonusByReferredId[r.id] || 0 })),
    });
  } catch (e) { err(res, e.message); }
});

// Low-balance provider alerts (auto SMS/email on low balance) were removed per request —
// they fired every 30 min plus on every server restart and were too noisy.

// ─── ADMIN: TIERED / VIP PRICING ───────────────────────────────────────────────

app.get('/api/v1/admin/tier-pricing', auth, requireAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('tier_margins').select('*').order('tier').order('service');
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

app.put('/api/v1/admin/tier-pricing/:tier/:service', auth, requireAdmin, async (req, res) => {
  try {
    const { tier, service } = req.params;
    const { markupPercent } = req.body;
    if (!VALID_TIERS.includes(tier)) return err(res, `tier must be one of: ${VALID_TIERS.join(', ')}`);
    if (markupPercent === undefined || markupPercent === null || isNaN(markupPercent)) return err(res, 'markupPercent is required and must be a number');
    const { error } = await supabase.from('tier_margins').upsert(
      { tier, service, markup_percent: markupPercent, updated_at: new Date().toISOString(), updated_by: req.user.id },
      { onConflict: 'tier,service' }
    );
    if (error) throw new Error(error.message);
    invalidateTierMarginCache();
    logAdminAction(req.user.id, 'update_tier_pricing', 'tier_pricing', `${tier}/${service}`, { markupPercent });
    ok(res, { tier, service, markupPercent }, 'Tier pricing updated');
  } catch (e) { err(res, e.message); }
});

app.delete('/api/v1/admin/tier-pricing/:tier/:service', auth, requireAdmin, async (req, res) => {
  try {
    const { tier, service } = req.params;
    await supabase.from('tier_margins').delete().eq('tier', tier).eq('service', service);
    invalidateTierMarginCache();
    logAdminAction(req.user.id, 'delete_tier_pricing', 'tier_pricing', `${tier}/${service}`, {});
    ok(res, null, 'Reverted to base pricing for this tier');
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/admin/users/:userId/tier', auth, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { tier } = req.body;
    if (!VALID_TIERS.includes(tier)) return err(res, `tier must be one of: ${VALID_TIERS.join(', ')}`);
    const { error } = await supabase.from('users').update({ tier }).eq('id', userId);
    if (error) throw new Error(error.message);
    logAdminAction(req.user.id, 'set_user_tier', 'user', userId, { tier });
    ok(res, { userId, tier }, 'User tier updated');
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: AUTOMATED FAILOVER LOG ─────────────────────────────────────────────

app.get('/api/v1/admin/failover-events', auth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const { data } = await supabase.from('failover_events').select('*').order('created_at', { ascending: false }).limit(limit);
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/admin/provider-logs', auth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    let q = supabase.from('provider_logs').select('*').order('created_at', { ascending: false }).limit(limit);
    if (req.query.provider) q = q.eq('provider', req.query.provider);
    if (req.query.success !== undefined) q = q.eq('success', req.query.success === 'true');
    const { data } = await q;
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: AUDIT LOG ───────────────────────────────────────────────────────
// Every admin action that changes state gets written here by logAdminAction() —
// this is just the read side. Filter by who did it, what kind of action, or what
// it was done to (e.g. target_type=user&targetId=<uuid> to pull one user's full
// admin history for a dispute).
app.get('/api/v1/admin/audit-log', auth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    let q = supabase
      .from('admin_audit_log')
      .select('*, admin:admin_id(full_name, phone)')
      .order('created_at', { ascending: false })
      .limit(limit);
    if (req.query.adminId) q = q.eq('admin_id', req.query.adminId);
    if (req.query.action) q = q.eq('action', req.query.action);
    if (req.query.targetType) q = q.eq('target_type', req.query.targetType);
    if (req.query.targetId) q = q.eq('target_id', req.query.targetId);
    const { data, error } = await q;
    if (error) throw new Error(error.message);
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

// ─── SUPPORT TICKETS ────────────────────────────────────────────────────────
// The gap: support was contact-only (WhatsApp/call/email), so a complaint had
// no trail — the user couldn't check "is my complaint still pending?" inside
// the app, and if a dispute came up later there was nothing to point back to.
// This gives every complaint a persistent, checkable record on both sides.
// See support_tickets.sql for the table. Each ticket carries a small JSONB
// thread of messages (both user and admin can reply) rather than a separate
// messages table — same pattern this file already uses for transaction
// metadata, and simple enough that a join table would be overkill here.
const TICKET_CATEGORIES = ['wallet', 'transaction', 'account', 'kyc', 'other'];
const TICKET_STATUSES = ['open', 'in_progress', 'resolved', 'closed'];

app.post('/api/v1/support/tickets', auth, async (req, res) => {
  try {
    const { subject, message, category, relatedReference } = req.body;
    if (!subject || !message) return err(res, 'subject and message are required');
    const cat = TICKET_CATEGORIES.includes(category) ? category : 'other';

    const { data, error } = await supabase.from('support_tickets').insert({
      user_id: req.user.id,
      subject: String(subject).trim().slice(0, 140),
      category: cat,
      status: 'open',
      related_reference: relatedReference || null,
      messages: [{ sender: 'user', senderId: req.user.id, text: String(message).trim(), createdAt: new Date().toISOString() }],
    }).select().single();
    if (error) throw new Error(error.message);
    ok(res, data, 'Support ticket created — we\'ll get back to you soon');
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/support/tickets', auth, async (req, res) => {
  try {
    let q = supabase
      .from('support_tickets')
      .select('id, subject, category, status, related_reference, created_at, updated_at, messages')
      .eq('user_id', req.user.id)
      .order('updated_at', { ascending: false });
    if (req.query.status) q = q.eq('status', req.query.status);
    const { data, error } = await q;
    if (error) throw new Error(error.message);
    // Trim to a preview so the list endpoint stays light — full thread is fetched per-ticket.
    const withPreview = (data || []).map((t) => ({ ...t, messages: undefined, lastMessage: t.messages?.[t.messages.length - 1] || null }));
    ok(res, withPreview);
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/support/tickets/:id', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('support_tickets').select('*').eq('id', req.params.id).eq('user_id', req.user.id).single();
    if (error || !data) return err(res, 'Ticket not found', 404);
    ok(res, data);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/support/tickets/:id/reply', auth, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return err(res, 'message is required');
    const { data: ticket } = await supabase.from('support_tickets').select('*').eq('id', req.params.id).eq('user_id', req.user.id).single();
    if (!ticket) return err(res, 'Ticket not found', 404);
    if (ticket.status === 'closed') return err(res, 'This ticket is closed. Please open a new one.', 400);

    const newMessages = [...(ticket.messages || []), { sender: 'user', senderId: req.user.id, text: String(message).trim(), createdAt: new Date().toISOString() }];
    // A user replying to a resolved ticket re-opens it — they're telling us it's not actually resolved.
    const nextStatus = ticket.status === 'resolved' ? 'open' : ticket.status;
    const { data, error } = await supabase.from('support_tickets').update({
      messages: newMessages, status: nextStatus, updated_at: new Date().toISOString(),
    }).eq('id', req.params.id).select().single();
    if (error) throw new Error(error.message);
    ok(res, data);
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: SUPPORT TICKETS ─────────────────────────────────────────────────

app.get('/api/v1/admin/support/tickets', auth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    let q = supabase
      .from('support_tickets')
      .select('id, subject, category, status, related_reference, created_at, updated_at, messages, users:user_id(full_name, phone, email)')
      .order('updated_at', { ascending: false })
      .limit(limit);
    if (req.query.status) q = q.eq('status', req.query.status);
    const { data, error } = await q;
    if (error) throw new Error(error.message);
    const withPreview = (data || []).map((t) => ({ ...t, messages: undefined, lastMessage: t.messages?.[t.messages.length - 1] || null }));
    ok(res, withPreview);
  } catch (e) { err(res, e.message); }
});

app.get('/api/v1/admin/support/tickets/:id', auth, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('support_tickets').select('*, users:user_id(full_name, phone, email)').eq('id', req.params.id).single();
    if (error || !data) return err(res, 'Ticket not found', 404);
    ok(res, data);
  } catch (e) { err(res, e.message); }
});

app.post('/api/v1/admin/support/tickets/:id/reply', auth, requireAdmin, async (req, res) => {
  try {
    const { message, status } = req.body;
    if (!message && !status) return err(res, 'message or status is required');
    if (status && !TICKET_STATUSES.includes(status)) return err(res, `status must be one of: ${TICKET_STATUSES.join(', ')}`);

    const { data: ticket } = await supabase.from('support_tickets').select('*, users:user_id(phone)').eq('id', req.params.id).single();
    if (!ticket) return err(res, 'Ticket not found', 404);

    const newMessages = message
      ? [...(ticket.messages || []), { sender: 'admin', senderId: req.user.id, text: String(message).trim(), createdAt: new Date().toISOString() }]
      : ticket.messages;
    const nextStatus = status || ticket.status;

    const { data, error } = await supabase.from('support_tickets').update({
      messages: newMessages, status: nextStatus, updated_at: new Date().toISOString(),
    }).eq('id', req.params.id).select().single();
    if (error) throw new Error(error.message);

    if (message) {
      notifyUser(ticket.user_id, ticket.users?.phone, 'Support replied to your ticket', message, req.user.id, 'support_reply')
        .catch((e) => console.error('ticket reply notify failed:', e.message));
    }
    logAdminAction(req.user.id, 'reply_support_ticket', 'support_ticket', req.params.id, { status: nextStatus, replied: !!message });
    ok(res, data);
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: PROVIDER BALANCE MONITORING ────────────────────────────────────────

// ─── ADMIN: VIRTUAL ACCOUNT / GATEWAY RECONCILER ───────────────────────────────

app.get('/api/v1/admin/gateway-events', auth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    let q = supabase.from('gateway_webhook_log').select('*').order('created_at', { ascending: false }).limit(limit);
    if (req.query.unmatchedOnly === 'true') q = q.eq('wallet_credited', false);
    const { data } = await q;
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

// Purchases (data/airtime/electric/cable/exam/isp/social/sms/recharge-pin/betting) that hit an
// AMBIGUOUS provider failure — a timeout or dropped connection where we genuinely don't know if
// the provider processed it — land here instead of being auto-refunded (see handlePurchaseFailure).
// An admin needs to check with the provider (their dashboard, or the requery endpoints already in
// this file) and then resolve each one as either delivered or refunded.
app.get('/api/v1/admin/pending-purchases', auth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const { data } = await supabase.from('transactions').select('id, reference, user_id, category, amount, phone, description, metadata, created_at, users:user_id(full_name, phone, email)').eq('status', 'pending_review').order('created_at', { ascending: true }).limit(limit);
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

// Resolve a pending_review purchase. action='delivered' means the admin confirmed with the
// provider that it actually went through — mark it success, no refund. action='refund' means it
// genuinely never happened — mark it failed and credit the customer back.
app.post('/api/v1/admin/pending-purchases/:reference/resolve', auth, requireAdmin, async (req, res) => {
  try {
    const { reference } = req.params;
    const { action, note } = req.body;
    if (!['delivered', 'refund'].includes(action)) return err(res, "action must be 'delivered' or 'refund'");

    const { data: txn, error: fetchErr } = await supabase.from('transactions').select('*').eq('reference', reference).single();
    if (fetchErr || !txn) return err(res, 'Transaction not found', 404);
    if (txn.status !== 'pending_review') return err(res, `This transaction is already ${txn.status}, not pending review`, 409);

    const { data: txnUser } = await supabase.from('users').select('id, phone').eq('id', txn.user_id).single();
    const newStatus = action === 'delivered' ? 'success' : 'failed';
    const newDescription = note ? `${txn.description} — ${action === 'delivered' ? 'confirmed delivered' : 'refunded'} by admin: ${note}` : txn.description;

    // Atomic claim: only succeeds if the row is STILL pending_review at update time — this closes
    // the race where the same admin (or two rapid clicks) could both pass the check above before
    // either write lands, which would double-refund. Whichever request's update actually matches
    // a row is the only one that proceeds to credit/notify.
    const { data: claimed, error: claimErr } = await supabase
      .from('transactions')
      .update({ status: newStatus, description: newDescription })
      .eq('reference', reference)
      .eq('status', 'pending_review')
      .select('id');
    if (claimErr) throw new Error(claimErr.message);
    if (!claimed || claimed.length === 0) return err(res, 'This transaction was already resolved (possibly by a duplicate request)', 409);

    if (action === 'delivered') {
      if (txnUser) await notifyUser(txnUser.id, txnUser.phone, 'Purchase confirmed', `Good news — your ${reference} purchase was confirmed delivered. No refund needed.`, req.user.id, 'transaction').catch(e => console.error('notify (delivered) failed:', e.message));
      logAdminAction(req.user.id, 'resolve_pending_purchase_delivered', 'transaction', reference, { note: note || null });
      ok(res, null, 'Marked as delivered — no refund issued');
    } else {
      await creditWallet(txn.user_id, txn.amount, 'reversal', `Manual refund (admin review): ${note || 'confirmed not delivered'}`);
      if (txnUser) await notifyUser(txnUser.id, txnUser.phone, 'Purchase refunded', `Your ${reference} purchase didn't go through. ₦${txn.amount} was refunded to your wallet.`, req.user.id, 'wallet_credit').catch(e => console.error('notify (refunded) failed:', e.message));
      logAdminAction(req.user.id, 'resolve_pending_purchase_refunded', 'transaction', reference, { amount: txn.amount, note: note || null });
      ok(res, null, 'Refunded to customer wallet');
    }
  } catch (e) { err(res, e.message); }
});

// Manually credit a wallet for a webhook event that couldn't be auto-matched to a user
// (e.g. customer paid from an account under a different phone number). Idempotent: refuses
// to double-credit an event that's already marked wallet_credited.
app.post('/api/v1/admin/gateway-events/:id/resolve', auth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { userId } = req.body;
    if (!userId) return err(res, 'userId is required');

    // 1. Fetch the event log with a fresh request
    const { data: event, error: fetchErr } = await supabase.from('gateway_webhook_log').select('*').eq('id', id).single();
    if (fetchErr || !event) return err(res, 'Gateway event not found', 404);
    
    // 2. STOPS DOUBLE CREDIT: Strict immediate return if already processed
    if (event.wallet_credited) return err(res, 'This event has already been credited', 409);

    const wallet = await getWallet(userId);
    if (!wallet) return err(res, 'Target user has no wallet', 404);

    // 3. Mark it credited in the database FIRST to lock it down
    const { error: updateErr } = await supabase.from('gateway_webhook_log')
      .update({ wallet_credited: true, matched_user_id: userId, resolved_by: req.user.id, resolved_at: new Date().toISOString() })
      .eq('id', id)
      .eq('wallet_credited', false); // Extra guard safety check

    if (updateErr) return err(res, 'Could not lock event status. Try again.');

    // 4. Now safely add the money to their wallet
    const result = await creditWallet(userId, event.amount, 'wallet_funding', `Manual reconciliation: ${event.provider} charge ${event.flw_charge_id}`, { manuallyResolvedBy: req.user.id, gatewayEventId: id, txRef: event.tx_ref });

    logAdminAction(req.user.id, 'resolve_gateway_event', 'gateway_event', id, { userId, amount: event.amount });
    ok(res, result, 'Wallet credited and event marked resolved');
  } catch (e) { err(res, e.message); }
});


    

// ─── ADMIN: WALLET WITHDRAWALS ─────────────────────────────────────────────────

app.get('/api/v1/admin/withdrawals', auth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    let q = supabase.from('transactions').select('id, reference, user_id, amount, phone, description, metadata, status, created_at, users:user_id(full_name, phone, email)').eq('category', 'wallet_withdrawal').order('created_at', { ascending: false }).limit(limit);
    if (req.query.status) q = q.eq('status', req.query.status);
    const { data } = await q;
    ok(res, data || []);
  } catch (e) { err(res, e.message); }
});

// Manual resolution for a withdrawal stuck in pending_review (e.g. the transfer.completed
// webhook never arrived, or the transfer call to Flutterwave itself timed out). action='paid'
// confirms it settled (matches admin-checked reality with the Flutterwave dashboard, no refund).
// action='refund' means it never landed — refund the customer.
app.post('/api/v1/admin/withdrawals/:reference/resolve', auth, requireAdmin, async (req, res) => {
  try {
    const { reference } = req.params;
    const { action, note } = req.body;
    if (!['paid', 'refund'].includes(action)) return err(res, "action must be 'paid' or 'refund'");

    const { data: txn, error: fetchErr } = await supabase.from('transactions').select('*').eq('reference', reference).eq('category', 'wallet_withdrawal').single();
    if (fetchErr || !txn) return err(res, 'Withdrawal not found', 404);
    if (txn.status !== 'pending_review') return err(res, `This withdrawal is already ${txn.status}, not pending review`, 409);

    const { data: wdUser } = await supabase.from('users').select('id, phone').eq('id', txn.user_id).single();
    const newStatus = action === 'paid' ? 'success' : 'failed';
    const newMetadata = action === 'paid'
      ? { ...txn.metadata, manuallyConfirmedBy: req.user.id, manualNote: note || 'Confirmed settled by admin' }
      : { ...txn.metadata, manuallyRefundedBy: req.user.id, manualNote: note || 'Confirmed not delivered by admin' };

    // Atomic claim: only succeeds if the row is STILL pending_review at update time — same
    // protection as the pending-purchases resolver, closes the double-refund race on rapid
    // duplicate clicks/requests.
    const { data: claimed, error: claimErr } = await supabase
      .from('transactions')
      .update({ status: newStatus, metadata: newMetadata })
      .eq('reference', reference)
      .eq('status', 'pending_review')
      .select('id');
    if (claimErr) throw new Error(claimErr.message);
    if (!claimed || claimed.length === 0) return err(res, 'This withdrawal was already resolved (possibly by a duplicate request)', 409);

    if (action === 'paid') {
      if (wdUser) await notifyUser(wdUser.id, wdUser.phone, 'Withdrawal confirmed', `Your withdrawal of ₦${txn.amount} has been confirmed settled.`, req.user.id, 'transaction').catch(e => console.error('notify (withdrawal paid) failed:', e.message));
      logAdminAction(req.user.id, 'resolve_withdrawal_paid', 'transaction', reference, { note: note || null });
      ok(res, null, 'Marked as paid — no refund issued');
    } else {
      await creditWallet(txn.user_id, txn.amount, 'reversal', `Manual refund (admin review): ${note || 'withdrawal did not land'}`);
      if (wdUser) await notifyUser(wdUser.id, wdUser.phone, 'Withdrawal refunded', `Your withdrawal of ₦${txn.amount} could not be completed and was refunded to your wallet.`, req.user.id, 'wallet_credit').catch(e => console.error('notify (withdrawal refund) failed:', e.message));
      logAdminAction(req.user.id, 'resolve_withdrawal_refunded', 'transaction', reference, { amount: txn.amount, note: note || null });
      ok(res, null, 'Refunded to customer wallet');
    }
  } catch (e) { err(res, e.message); }
});

// ─── ADMIN: TRANSACTION TRACE (full journey for one reference) ────────────────

app.get('/api/v1/admin/transactions/:reference/trace', auth, requireAdmin, async (req, res) => {
  try {
    const { reference } = req.params;

    const { data: transaction } = await supabase.from('transactions').select('*').eq('reference', reference).single();
    if (!transaction) return err(res, 'Transaction not found', 404);

    const { data: providerCalls } = await supabase.from('provider_logs').select('*').eq('reference', reference).order('created_at', { ascending: true });
    const { data: failovers } = await supabase.from('failover_events').select('*').eq('reference', reference).order('created_at', { ascending: true });

    ok(res, {
      transaction,
      providerCalls: providerCalls || [],
      failoverEvents: failovers || [],
    }, 'Transaction trace');
  } catch (e) { err(res, e.message); }
});

// ─── 404 fallback (JSON, not HTML) ─────────────────────────────────────────
// Without this, any unmatched route (typo'd path, wrong method, client hitting
// a stale/renamed endpoint) falls through to Express's default HTML 404 page.
// The client's `res.json()` then throws "Unexpected character: <" because it
// got HTML instead of JSON.
app.use((req, res) => {
  err(res, `No route matches ${req.method} ${req.originalUrl}`, 404);
});

// ─── Global error handler (JSON, not HTML) ─────────────────────────────────
// Catches anything thrown outside a route's own try/catch (e.g. body-parser
// errors, sync throws in middleware before a route handler runs). Without
// this, Express falls back to its default HTML error/stack-trace page, which
// breaks any client expecting JSON. Must be defined last, with 4 args so
// Express treats it as an error handler.
//
// setupExpressErrorHandler must be registered before this one (Sentry's own
// requirement) — it reports the error to Sentry, then calls next(error) so
// this handler still runs afterward and the JSON response behavior below is
// unchanged. Note this only catches errors that escape a route's try/catch;
// since almost every route in this file already catches its own errors and
// responds via err(), those never reach here or Sentry automatically — they
// stay purely in your existing console.error/Render logs unless you also add
// Sentry.captureException(e) inside those individual catch blocks.
Sentry.setupExpressErrorHandler(app);
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  err(res, error.message || 'Internal server error', 500);
});

// ─── RECONCILIATION: stuck wallet withdrawals ──────────────────────────────────
// Safety net for the gap described at /api/v1/wallet/withdraw: a withdrawal is left in
// 'pending_review' until Flutterwave's `transfer.completed` webhook arrives. If that webhook
// is delayed, never configured for transfer events, or never fires at all (and in the
// "ambiguous failure" branch, where the /transfers call itself timed out and we never even
// got a transfer id back), the transaction would otherwise sit in pending_review forever —
// exactly what you saw in the transaction history (one stuck 3 days until an admin manually
// resolved it). This polls Flutterwave directly for the real status instead of waiting on
// the webhook, so most cases resolve themselves within a few minutes of being initiated.
//
// Uses the same atomic 'claim' pattern as /admin/withdrawals/:reference/resolve (update
// WHERE status = 'pending_review') so this can never race with an admin manually resolving
// the same transaction, or with the transfer.completed webhook landing at the same moment.
const RECONCILE_MIN_AGE_MS = 5 * 60 * 1000; // don't chase transfers that just started — give the webhook a fair chance first
const RECONCILE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // don't keep polling something ancient/abandoned — surface it for a human instead
const RECONCILE_INTERVAL_MS = 5 * 60 * 1000;

async function settleWithdrawal(txn, flwStatus, flwData) {
  const newStatus = flwStatus === 'SUCCESSFUL' ? 'success' : 'failed';
  const newMetadata = { ...txn.metadata, flwTransferStatus: flwStatus, flwComplaint: flwData?.complete_message, reconciledAt: new Date().toISOString() };

  // Atomic claim: only proceed if the row is STILL pending_review right now. If the webhook
  // (or an admin) beat us to it, this update matches 0 rows and we just skip — no double refund.
  const { data: claimed, error: claimErr } = await supabase
    .from('transactions')
    .update({ status: newStatus, metadata: newMetadata })
    .eq('reference', txn.reference)
    .eq('status', 'pending_review')
    .select('id');
  if (claimErr) { console.error(`Reconcile: could not claim ${txn.reference}:`, claimErr.message); return; }
  if (!claimed || claimed.length === 0) return; // already resolved elsewhere in the meantime

  if (newStatus === 'success') {
    console.log(`Reconcile: ${txn.reference} confirmed SUCCESSFUL by Flutterwave — no refund needed`);
  } else {
    await creditWallet(txn.user_id, txn.amount, 'reversal', `Reversal: withdrawal transfer ${String(flwStatus || 'failed').toLowerCase()} (reconciled)`, { originalReference: txn.reference });
    const { data: wUser } = await supabase.from('users').select('id, phone').eq('id', txn.user_id).single();
    if (wUser) await notifyUser(wUser.id, wUser.phone, 'Withdrawal failed — refunded', `Your withdrawal of ₦${txn.amount} could not be completed and was refunded to your wallet.`, null, 'wallet_credit').catch(e => console.error('notify (reconcile refund) failed:', e.message));
    console.log(`Reconcile: ${txn.reference} confirmed ${flwStatus} — refunded ₦${txn.amount} to user ${txn.user_id}`);
  }
}

async function reconcilePendingWithdrawals() {
  const cutoff = new Date(Date.now() - RECONCILE_MIN_AGE_MS).toISOString();
  const floor = new Date(Date.now() - RECONCILE_MAX_AGE_MS).toISOString();

  const { data: stuck, error } = await supabase
    .from('transactions')
    .select('*')
    .eq('category', 'wallet_withdrawal')
    .eq('status', 'pending_review')
    .lte('created_at', cutoff)
    .gte('created_at', floor)
    .order('created_at', { ascending: true })
    .limit(50);

  if (error) { console.error('Reconcile: failed to fetch pending withdrawals:', error.message); return; }
  if (!stuck || stuck.length === 0) return;

  console.log(`Reconcile: checking ${stuck.length} pending withdrawal(s) against Flutterwave`);

  for (const txn of stuck) {
    try {
      const flwId = txn.provider_ref || txn.metadata?.flwTransferId;

      if (flwId) {
        // Normal case: we have Flutterwave's transfer id from when the transfer call succeeded.
        const { data: result } = await flutterwave.get(`/transfers/${flwId}`);
        const status = result?.data?.status;
        if (status === 'SUCCESSFUL' || status === 'FAILED' || status === 'REVERSED') {
          await settleWithdrawal(txn, status, result.data);
        }
        // else: still PENDING on Flutterwave's side too — leave it, check again next run.
        continue;
      }

      // Ambiguous-failure case (server.js line ~3898): the /transfers call itself threw before
      // we ever got an id back, so we don't know if Flutterwave actually created the transfer.
      // Fall back to looking it up by our reference instead of the Flutterwave id.
      const { data: byRef } = await flutterwave.get('/transfers', { params: { reference: txn.reference } });
      const match = Array.isArray(byRef?.data) ? byRef.data[0] : null;
      if (!match) {
        // Flutterwave has no record of it at all — the transfer call genuinely never went
        // through, so it's safe to refund without risking a double-payout.
        await settleWithdrawal(txn, 'FAILED', null);
      } else if (['SUCCESSFUL', 'FAILED', 'REVERSED'].includes(match.status)) {
        await settleWithdrawal(txn, match.status, match);
      }
    } catch (e) {
      // Network/API error talking to Flutterwave for this one — leave it pending_review,
      // it'll be retried on the next interval. Don't let one bad lookup stop the batch.
      console.error(`Reconcile: lookup failed for ${txn.reference}:`, e.response?.data?.message || e.message);
    }
  }
}

// ─── START SERVER ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Gora Data server running on port ${PORT}`);
  setInterval(() => { reconcilePendingWithdrawals().catch(e => console.error('Reconcile: unhandled error:', e.message)); }, RECONCILE_INTERVAL_MS);
  reconcilePendingWithdrawals().catch(e => console.error('Reconcile: unhandled error:', e.message)); // run once at boot too
});
module.exports = app;
