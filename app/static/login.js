/* VulnScanner session login. Dependency-free and CSP-friendly. */
'use strict';

(function () {
  const form = document.getElementById('login-form');
  const username = document.getElementById('login-username');
  const password = document.getElementById('login-password');
  const code = document.getElementById('login-code');
  const recovery = document.getElementById('login-recovery');
  const mfaFields = document.getElementById('mfa-fields');
  const totpField = document.getElementById('totp-field');
  const recoveryField = document.getElementById('recovery-field');
  const useRecovery = document.getElementById('use-recovery');
  const errorBox = document.getElementById('login-error');
  const submit = document.getElementById('login-submit');
  const subtitle = document.getElementById('login-subtitle');
  let mfaMode = false;
  let recoveryMode = false;

  function nextUrl() {
    const params = new URLSearchParams(location.search);
    const next = params.get('next') || '/';
    return next.startsWith('/') && !next.startsWith('//') ? next : '/';
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.add('show');
  }

  function clearError() {
    errorBox.textContent = '';
    errorBox.classList.remove('show');
  }

  function setBusy(value) {
    submit.disabled = value;
    submit.textContent = value ? 'Signing in…' : (mfaMode ? 'Verify and sign in' : 'Sign in');
  }

  function showMfa() {
    mfaMode = true;
    mfaFields.classList.remove('hidden');
    subtitle.textContent = 'Enter the 6-digit code from your authenticator app.';
    setBusy(false);
    code.focus();
  }

  useRecovery.addEventListener('click', function () {
    recoveryMode = !recoveryMode;
    totpField.classList.toggle('hidden', recoveryMode);
    recoveryField.classList.toggle('hidden', !recoveryMode);
    useRecovery.textContent = recoveryMode ? 'Use an authenticator code instead' : 'Use a recovery code instead';
    (recoveryMode ? recovery : code).focus();
  });

  async function bootstrap() {
    try {
      const response = await fetch('/api/auth/status', { headers: { Accept: 'application/json' } });
      const status = await response.json();
      if (!status.auth_enabled) {
        location.replace('/');
        return;
      }
      if (status.authenticated) {
        location.replace(nextUrl());
        return;
      }
      if (status.mfa_enabled) {
        subtitle.textContent = 'Enter your password, then your authenticator code.';
      }
    } catch (error) {
      showError('Cannot reach the VulnScanner server.');
    }
  }

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    clearError();
    setBusy(true);
    const payload = {
      username: username.value.trim(),
      password: password.value,
      code: recoveryMode ? '' : code.value.trim(),
      recovery_code: recoveryMode ? recovery.value.trim() : ''
    };
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(payload)
      });
      let body = null;
      try { body = await response.json(); } catch (ignore) { body = null; }
      if (response.ok && body && body.ok) {
        location.replace(nextUrl());
        return;
      }
      if (body && body.mfa_required) {
        showMfa();
        return;
      }
      if (response.status === 429) {
        showError((body && body.detail) || 'Too many attempts. Try again later.');
        return;
      }
      showError((body && body.detail) || 'Sign-in failed.');
      password.select();
    } catch (error) {
      showError('Cannot reach the VulnScanner server.');
    } finally {
      setBusy(false);
    }
  });

  bootstrap();
})();
