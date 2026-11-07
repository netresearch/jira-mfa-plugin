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

  function unsupported(errEl) {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      showError(errEl, 'This browser does not support passkeys.');
      return true;
    }
    return false;
  }

  var login = document.getElementById('passkey-box');
  if (login) {
    var loginBtn = document.getElementById('passkey-login');
    var loginErr = login.querySelector('#passkey-error');
    loginBtn.addEventListener('click', function () {
      loginErr.hidden = true;
      if (unsupported(loginErr)) return;
      loginBtn.disabled = true;
      var d = login.dataset;
      post(d.options, d.csrf)
        .then(function (opts) { return navigator.credentials.get({ publicKey: requestOptions(opts.publicKey) }); })
        .then(function (cred) { return post(d.finish, d.csrf, JSON.stringify(credentialJson(cred))); })
        .then(function (res) { window.location.assign(res.redirect); })
        .catch(function (e) {
          loginBtn.disabled = false;
          showError(loginErr, 'The passkey was not accepted (' + e.message + '). Try again or enter a code.');
        });
    });
  }

  var reg = document.getElementById('passkey-register');
  if (reg) {
    var regBtn = document.getElementById('passkey-add');
    var regErr = reg.querySelector('#passkey-error');
    regBtn.addEventListener('click', function () {
      regErr.hidden = true;
      if (unsupported(regErr)) return;
      regBtn.disabled = true;
      var d = reg.dataset;
      var label = document.getElementById('passkey-label').value || 'Passkey';
      post(d.options, d.csrf)
        .then(function (opts) { return navigator.credentials.create({ publicKey: creationOptions(opts.publicKey) }); })
        .then(function (cred) {
          return post(d.finish, d.csrf, JSON.stringify(credentialJson(cred)), { 'X-MFA-Label': encodeURIComponent(label) });
        })
        .then(function () {
          // show the result (and first recovery codes) through a normal form post
          var f = document.createElement('form');
          f.method = 'post';
          f.action = d.done;
          [['csrf', d.csrf], ['action', 'passkey-registered']].forEach(function (p) {
            var i = document.createElement('input');
            i.type = 'hidden'; i.name = p[0]; i.value = p[1];
            f.appendChild(i);
          });
          document.body.appendChild(f);
          f.submit();
        })
        .catch(function (e) {
          regBtn.disabled = false;
          showError(regErr, 'The passkey could not be added (' + e.message + ').');
        });
    });
  }
})();
