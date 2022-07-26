document.addEventListener('alpine:init', function () {
  function sendRequest(method, url, data, onSuccess, onError) {
    if (!onError) {
      onError = function (err) {
        Alpine.store('notify').alert("danger", err.error);
      }
    }
    let xhr = new XMLHttpRequest();
    if ("withCredentials" in xhr) {
      xhr.open(method, url, true);
    } else if (typeof XDomainRequest != "undefined") {
      xhr = new XDomainRequest();
      xhr.open(method, url);
    } else {
      onError({
        error: "An error has occurred."
      })
      return;
    }
    xhr.setRequestHeader('Content-Type', 'application/json');
    const accTok = Alpine.store("values").accessToken;
    if (accTok) {
      xhr.setRequestHeader('Authorization', 'Bearer ' + accTok)
    }
    xhr.onreadystatechange = function () {
      if (xhr.readyState === 4) {
        Alpine.store("values").loading = false;
        const result = xhr.responseText ? JSON.parse(xhr.responseText) : {};
        if (xhr.status >= 400) {
          if (xhr.status === 401 && accTok) {
            Alpine.store("values").accessToken = null;
            if (location.pathname !== bPath(env.login)) toLogin();
          }
          onError(result, xhr.status);
        } else {
          onSuccess(result, xhr.status);
        }
      }
    };
    Alpine.store("values").loading = true;
    xhr.send(data ? JSON.stringify(data) : undefined);
  }
  const env = document.getElementById("env").dataset;

  function bPath(p) {
    return env.base + p;
  }

  function toLogin() {
    location.href = bPath(env.login) + "?r=" + encodeURIComponent(location.pathname + location.search);
  }
  const actPath = bPath("/action");

  function accessToken(onSuccess) {
    try {
      const aTok = Alpine.store("values").accessToken;
      if (aTok) {
        const payload = JSON.parse(window.atob(aTok.split('.')[1]))
        if (new Date().getTime() / 1000 < payload.exp) {
          onSuccess(aTok);
          return;
        }
      }
    } catch {
      Alpine.store("values").accessToken = null;
    }
    sendRequest("GET", bPath(env.refresh), null, (r) => {
      Alpine.store("values").accessToken = r.access_token;
      onSuccess(r.access_token);
    }, function (err, code) {
      if (code === 401 && location.pathname !== bPath(env.login)) {
        toLogin();
      } else if (code !== 401)
        Alpine.store('notify').alert("danger", err.error);
    });
  }
  Alpine.store('values', {
    recaptcha: null,
    loading: false,
    accessToken: null
  });
  Alpine.store('notify', {
    alertId: 0,
    alerts: [],
    close: function (index) {
      this.alerts.splice(index, 1);
    },
    alert: function (type, message) {
      this.alerts.push({
        type: type,
        message: message,
        id: ++this.alertId
      });
      const self = this;
      setTimeout(function () {
        const id = this.id;
        const idx = self.alerts.findIndex(function (a) {
          return a.id === id
        });
        if (idx !== -1) {
          self.alerts.splice(idx, 1);
        }
      }.bind({
        id: this.alertId
      }), 5000);
    },
  });
  Alpine.store('nav', {
    tab: document.querySelectorAll(".nav a.pointer").length ? document.querySelectorAll(".nav a.pointer")[0].innerText : null,
    setTab: function (tab) {
      this.tab = tab;
    },
    isTab: function (tab) {
      return this.tab === tab.split(",")[0];
    },
    logout: function () {
      sendRequest("DELETE", bPath(env.refresh), null, function () {
        location.href = bPath(env.login);
      }, function (err) {
        sessionStorage.setItem("alertDanger", err.error);
        location.href = bPath(env.login);
      });
    }
  });

  const query = {};
  window.location.search.substring(1).split("&").map(function (s) {
    const vals = s.split("=");
    query[vals[0]] = vals.length > 1 ? decodeURIComponent(vals[1]) : null;
  });
  const alerts = {
    success: "alertSuccess",
    danger: "alertDanger"
  };
  for (let k in alerts) {
    const msg = sessionStorage.getItem(alerts[k]);
    if (msg) {
      Alpine.store('notify').alert(k, msg);
      sessionStorage.removeItem(alerts[k]);
    }
  }

  function goLogin() {
    accessToken(function () {
      location.href = query.r || sessionStorage.getItem("ref") || env.base + env.account;
      sessionStorage.removeItem("ref");
    });
  }
  Alpine.data('form', function () {
    const isAccount = location.pathname === bPath(env.account);
    const isLogin = location.pathname === bPath(env.login);
    const isRegister = location.pathname === bPath(env.register);
    const confirmFields = [];
    return {
      init: function () {
        if (query.r) {
          sessionStorage.setItem("ref", query.r);
        } else if (document.referrer && !sessionStorage.getItem("ref") && document.referrer.indexOf(bPath(env.login)) === -1 && document.referrer.indexOf(bPath(env.register)) === -1) {
          sessionStorage.setItem("ref", document.referrer);
        }
        if (query.a === "verify") {
          sendRequest("POST", actPath, {
            action: query.a,
            token: query.t
          }, () => {
            sessionStorage.setItem("alertSuccess", "Email Verified");
            location.href = "?";
          }, (err) => {
            sessionStorage.setItem("alertDanger", err.error);
            location.href = "?";
          });
        } else if (query.a === "login") {
          sendRequest("POST", location.pathname, {
            token: query.t
          }, () => {
            goLogin();
          }, (err) => {
            sessionStorage.setItem("alertDanger", err.error);
            location.href = "?";
          });
        }
        if (isAccount) {
          accessToken(() => {
            if (query.a === "emailupdate") {
              sendRequest("POST", actPath, {
                action: query.a,
                token: query.t
              }, () => {
                sessionStorage.setItem("alertSuccess", "Email updated!");
                location.href = bPath(env.account);
              });
              return;
            }
            sendRequest("GET", location.pathname, null, (r) => {
              this.updateAccount(r);
            });

            Alpine.effect(() => {
              if (Alpine.store("nav").tab && this.original) {
                this.input = JSON.parse(this.original);
                this.updateAccount();
              }
            });
          });
        } else if (isLogin && this.$refs.field_code) {
          this.$refs.field_code.classList.add("hidden");
        }
        const els = document.querySelectorAll("input[id$=_confirm]");
        for (let i = 0; i < els.length; i++) {
          confirmFields.push(els[i].id.substring(0, els[i].id.indexOf("_confirm")));
        }
      },
      original: null,
      input: {},
      hide: {},
      errors: {},
      mfa: {
        url: null
      },
      updateAccount: function (acct, reset) {
        if (acct) {
          this.original = JSON.stringify(acct);
          this.input = acct;
          if (this.input.totpsecret === true) {
            this.mfa.url = null;
          }
        }
        if (this.original) {
          if (this.input.totpsecret === true && !reset) {
            this.$refs.field_code.classList.add("hidden");
          } else if (this.mfa.url === null || reset) {
            this.mfa.url = "";
            sendRequest("POST", actPath, {
              action: "newTotpKey"
            }, (r) => {
              this.mfa.url = actPath + "?qr=" + encodeURIComponent(r.url);
              this.mfa.secret = r.secret;
              this.$refs.field_code.classList.remove("hidden");
            });
          }
        }
      },
      genRecovery: function () {
        sendRequest("POST", actPath, {
          action: "newRecovery"
        }, (r) => {
          this.mfa.recovery = r.join("\n");
        });
      },
      submit: function (e) {
        this.errors = {};
        for (let i = 0; i < confirmFields.length; i++) {
          const field = confirmFields[i];
          if (this.input[field] && this.input[field] !== this.input[field + "_confirm"]) {
            this.errors[field + "_confirm"] = "password do not match";
            return;
          }
        }
        if (window.grecaptcha) {
          if (!Alpine.store("values").recaptcha) {
            this.errors.recaptcha = "required";
            return;
          }
          this.input.recaptcha = Alpine.store("values").recaptcha;
        }
        let path = location.pathname;
        if (query.a || e.act) {
          path = actPath;
          this.input.action = query.a || e.act;
          if (query.t) {
            this.input.token = query.t;
          }
        }
        const success = {
          resetlink: "Reset link sent!",
          reset: "Password updated!",
          confirmemail: "Confirmation link sent!"
        };
        const input = JSON.parse(JSON.stringify(this.input));
        for (let k in input) {
          if (!input[k]) delete (input[k]);
        }
        if (input.code) {
          input.totpsecret = this.mfa.secret;
        }
        if (this.mfa.recovery) {
          input.recoverycodes = this.mfa.recovery.split("\n").join("|");
          this.mfa.recovery = null;
        }
        sendRequest("POST", path, input, (r, code) => {
          if (input.action && success[input.action]) {
            sessionStorage.setItem("alertSuccess", success[input.action]);
            location.href = "?";
            return;
          }
          if (isLogin) {
            if (!input.password && code === 201) {
              const el = document.querySelectorAll("input[type=email]")[0];
              this.input[el.id] = null;
              Alpine.store('notify').alert("success", "An email was sent to " + input[el.id] + ".");
            } else {
              goLogin();
            }
          } else if (isRegister) {
            sessionStorage.setItem("alertSuccess", code === 201 ? "Email confirmation link sent to your email." : "Registration success!");
            location.href = bPath(env.login);
          } else if (isAccount) {
            this.updateAccount(r);
            Alpine.store('notify').alert("success", code === 201 ? "Email update link sent to your email." : "Updated!");
          }
        }, function (err) {
          Alpine.store("values").recaptcha = null;
          if (window.grecaptcha) {
            window.grecaptcha.reset(window.recaptcha);
          }
          if (err.error === "validation") {
            this.errors = err.data;
            if (isLogin && this.$refs.field_code) {
              this.$refs.field_code.classList[this.errors.code ? "remove" : "add"]("hidden");
            }
          } else {
            Alpine.store('notify').alert("danger", err.error);
          }
        }.bind(this));
      }
    }
  });
});

window.recaptchaCallback = function () {
  const recaptchaField = document.getElementById("recaptcha-field");
  if (!recaptchaField) return;
  window.recaptcha = grecaptcha.render(recaptchaField, {
    sitekey: recaptchaField.dataset.key,
    callback: function (resp) {
      Alpine.store("values").recaptcha = resp;
    },
  });
};