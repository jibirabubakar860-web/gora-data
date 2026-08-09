
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
