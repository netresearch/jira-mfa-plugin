/* Passkey (WebAuthn) ceremonies for the Jira MFA plugin pages. */
(function () {
  'use strict';

  function b64urlToBuf(s) {
    var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function creationOptions(pk) {
    if (window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON) {
      return PublicKeyCredential.parseCreationOptionsFromJSON(pk);
    }
    pk.challenge = b64urlToBuf(pk.challenge);
    pk.user.id = b64urlToBuf(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    return pk;
  }

  function requestOptions(pk) {
    if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON) {
      return PublicKeyCredential.parseRequestOptionsFromJSON(pk);
    }
    pk.challenge = b64urlToBuf(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
    return pk;
  }

  function credentialJson(cred) {
    if (typeof cred.toJSON === 'function') return cred.toJSON();
    var r = cred.response;
    var response = { clientDataJSON: bufToB64url(r.clientDataJSON) };
    if (r.attestationObject) {
      response.attestationObject = bufToB64url(r.attestationObject);
      if (typeof r.getTransports === 'function') response.transports = r.getTransports();
    } else {
      response.authenticatorData = bufToB64url(r.authenticatorData);
      response.signature = bufToB64url(r.signature);
      if (r.userHandle) response.userHandle = bufToB64url(r.userHandle);
    }
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: response,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
    };
  }

  function post(url, csrf, body, extraHeaders) {
    var headers = { 'X-MFA-Token': csrf, 'Content-Type': 'application/json', 'Accept': 'application/json' };
    Object.keys(extraHeaders || {}).forEach(function (k) { headers[k] = extraHeaders[k]; });
    return fetch(url, { method: 'POST', credentials: 'same-origin', headers: headers, body: body || '{}' })
      .then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
          return j;
        });
      });
  }

  function showError(el, msg) {
    el.textContent = msg;
    el.hidden = false;
  }

  function fill(template, detail) {
    return (template || '{0}').replace('{0}', function () { return detail; });
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }

  // Second step: the passkey prompt opens by itself once the page has focus. A cancelled or
  // refused automatic prompt is not an error (an attempt counts only when an assertion is sent),
  // so it leaves a quiet hint and the button; an explicit click reports every failure.
  var login = document.getElementById('passkey-box');
  if (login) {
    var loginBtn = document.getElementById('passkey-login');
    var loginErr = login.querySelector('#passkey-error');
    var loginStatus = login.querySelector('#passkey-status');
    var d = login.dataset;
    var running = false;
    var pending = null;

    var start = function (automatic) {
      if (running) return;
      loginErr.hidden = true;
      loginStatus.textContent = '';
      if (!supported()) {
        if (!automatic) showError(loginErr, d.msgUnsupported);
        return;
      }
      running = true;
      loginBtn.disabled = true;
      loginStatus.textContent = d.msgWaiting || '';
      var ctrl = window.AbortController ? new AbortController() : null;
      pending = ctrl;
      post(d.options, d.csrf)
        .then(function (opts) {
          var req = { publicKey: requestOptions(opts.publicKey) };
          if (ctrl) req.signal = ctrl.signal;
          return navigator.credentials.get(req);
        })
        .then(function (cred) { return post(d.finish, d.csrf, JSON.stringify(credentialJson(cred))); })
        .then(function (res) { window.location.assign(res.redirect); })
        .catch(function (e) {
          pending = null;
          running = false;
          loginBtn.disabled = false;
          loginStatus.textContent = '';
          var dismissed = e && (e.name === 'NotAllowedError' || e.name === 'AbortError');
          // AbortError: the user opened "Other ways to sign in", which closed the prompt
          if ((automatic && dismissed) || (e && e.name === 'AbortError')) {
            loginStatus.textContent = d.msgDismissed || '';
            loginBtn.focus();
          } else {
            showError(loginErr, fill(d.msgFailed, e.message));
          }
        });
    };

    loginBtn.addEventListener('click', function () { start(false); });
    // Choosing another way closes an open passkey prompt.
    var other = document.getElementById('other-ways');
    if (other) {
      other.addEventListener('toggle', function () {
        if (other.open && pending) pending.abort();
      });
    }
    if (d.autostart === 'true' && supported()) {
      // Browsers refuse a WebAuthn request from a page without focus, so wait for it.
      if (document.hasFocus()) {
        start(true);
      } else {
        window.addEventListener('focus', function once() {
          window.removeEventListener('focus', once);
          start(true);
        });
      }
    }
  }

  // Enrolment: a passkey is the recommended factor; without WebAuthn the authenticator app is
  // the way, so its section opens.
  var reg = document.getElementById('passkey-register');
  if (reg) {
    var regBtn = document.getElementById('passkey-add');
    var regErr = reg.querySelector('#passkey-error');
    var rd = reg.dataset;
    if (!supported()) {
      showError(regErr, rd.msgUnsupported);
      var totp = document.getElementById('totp-section');
      if (totp) totp.open = true;
    }
    regBtn.addEventListener('click', function () {
      regErr.hidden = true;
      if (!supported()) {
        showError(regErr, rd.msgUnsupported);
        return;
      }
      regBtn.disabled = true;
      var label = document.getElementById('passkey-label').value || rd.defaultName || 'Passkey';
      post(rd.options, rd.csrf)
        .then(function (opts) { return navigator.credentials.create({ publicKey: creationOptions(opts.publicKey) }); })
        .then(function (cred) {
          return post(rd.finish, rd.csrf, JSON.stringify(credentialJson(cred)), { 'X-MFA-Label': encodeURIComponent(label) });
        })
        .then(function () {
          // show the result (and first recovery codes) through a normal form post
          var f = document.createElement('form');
          f.method = 'post';
          f.action = rd.done;
          [['csrf', rd.csrf], ['action', 'passkey-registered']].forEach(function (p) {
            var i = document.createElement('input');
            i.type = 'hidden'; i.name = p[0]; i.value = p[1];
            f.appendChild(i);
          });
          document.body.appendChild(f);
          f.submit();
        })
        .catch(function (e) {
          regBtn.disabled = false;
          showError(regErr, fill(rd.msgFailed, e.message));
        });
    });
  }
})();
