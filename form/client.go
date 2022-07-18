package form

var clientJS = `
document.addEventListener('alpine:init', () => {
    function sendRequest(method, url, data, onSuccess, onError) {
        var xhr = new XMLHttpRequest();
        if ("withCredentials" in xhr) {
            xhr.open(method, url, true);
        } else if (typeof XDomainRequest != "undefined") {
            xhr = new XDomainRequest();
            xhr.open(method, url);
        } else {
            onError({error:"An error has occurred."})
			return;
        }
		xhr.setRequestHeader('Content-Type', 'application/json');
		const accTok = sessionStorage.getItem("atok");
		if (accTok) {
			xhr.setRequestHeader('Authorization', 'Bearer ' + accTok)
		}
		xhr.onreadystatechange = function (oEvent) {
			if (xhr.readyState === 4) {
				this.sending = false;
				const result = xhr.responseText ? JSON.parse(xhr.responseText) : {};
				if (result.error) {
					if (xhr.status === 401 && accTok) {
						sessionStorage.removeItem("atok");
						if (location.pathname !== bPath(env.login)) toLogin();
					}
					onError(result, xhr.status);
				} else {
					onSuccess(result);
				}
			}
		}.bind(this);
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
			const aTok = sessionStorage.getItem("atok");
			if (aTok) {
				const payload = JSON.parse(window.atob(aTok.split('.')[1]))
				if (new Date().getTime() / 1000 < payload.exp) {
					onSuccess(aTok);
					return;
				}
			}
		} catch {
			sessionStorage.removeItem("atok");
		}
		sendRequest("GET", bPath(env.refresh), null, function(r) {
			sessionStorage.setItem("atok", r.access_token);
			onSuccess(r.access_token);
		}, function (err, code) {
			if (code === 401 && location.pathname !== bPath(env.login)) {
				toLogin();
				return;
			}
			Alpine.store('notify').alert("danger", err.error);
		});
	}
	Alpine.store('recaptcha', {
		value: null
	});
	Alpine.store('notify', {
		alertId: 0,
		alerts: [],
		close: function (index) {
			this.alerts.splice(index, 1);
		},
		alert: function(type, message) {
			this.alerts.push({type: type, message: message, id: ++this.alertId});
			const self = this;
			setTimeout(function() {
				const id = this.id;
				const idx = self.alerts.findIndex(function(a) { return a.id === id });
				if (idx !== -1) {
					self.alerts.splice(idx, 1);
				}
			}.bind({id: this.alertId}), 5000);
		},
	});
	Alpine.store('nav', {
		tab: document.querySelectorAll(".nav a.pointer").length ? document.querySelectorAll(".nav a.pointer")[0].innerText : null,
		setTab: function (tab) {
			this.tab = tab;
		},
		isTab: function(tab) {
			return this.tab === tab.split(",")[0];
		},
		logout: function() {
			sessionStorage.removeItem("atok");
			sendRequest("DELETE", bPath(env.refresh), null, function() {
				location.href = bPath(env.login);
			}, function (err) {
				sessionStorage.setItem("alertDanger", err.error);
				location.href = bPath(env.login);
			});
		}
	});

	const query = {};
	window.location.search.substring(1).split("&").map(function(s) {
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
	Alpine.data('form', function() {
		return {
			init: function () {
				const self = this;
				if (query.a === "verify") {
					this.loading = true;
					sendRequest("POST", actPath, {action: query.a, token: query.t}, function(r) {
						sessionStorage.setItem("alertSuccess", "Email Verified");
						location.href = "?";
						self.loading = false;
					}, function (err) {
						sessionStorage.setItem("alertDanger", err.error);
						location.href = "?";
						self.loading = false;
					});
				}
				if (location.pathname === bPath(env.account)) {
					const self = this;
					accessToken(function() {
						if (query.a === "emailupdate") {
							sendRequest("POST", actPath, {action: query.a, token: query.t}, function() {
								location.href = bPath(env.account);
							}, function (err, code) {
								Alpine.store('notify').alert("danger", err.error);
							});
							return;
						}
						sendRequest("GET", location.pathname, null, function(r) {
							self.original = JSON.stringify(r);
							self.input = r;
							Alpine.effect(() => {
								if (Alpine.store("nav").tab) {
									console.log("Moved tab");
									self.input = JSON.parse(self.original);
								}
							});
						}, function (err, code) {
							Alpine.store('notify').alert("danger", err.error);
						});
					});
				}
			},
			original: null,
			input: {},
			hide: {},
			errors: {},
			loading: false,
			submit: function (e) {
				this.errors = {};
				if (this.input.terms !== undefined) {
					this.input.terms = this.input.terms ? "agree" : "";
				}
				if (window.grecaptcha) {
					if (!Alpine.store("recaptcha").value) {
						this.errors.recaptcha = "required";
						return;
					}
					this.input.recaptcha = Alpine.store("recaptcha").value;
				}
				this.loading = true;
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
				const input = this.input;
				sendRequest("POST", path, this.input, function(r) {
					if (input.action && success[input.action]) {
						sessionStorage.setItem("alertSuccess", success[input.action]);
						location.href = "?";
						return;
					}
					if (location.pathname === bPath(env.login)) {
						accessToken(function() {
							location.href = query.r ? query.r : env.base + env.account;
						});
					} else if (location.pathname === bPath(env.register)) {
						sessionStorage.setItem("alertSuccess", r === "SENT" ? "Email confirmation link sent to your email." : "Registration success!");
						location.href = bPath(env.login);
					} else if (location.pathname === bPath(env.account)) {
						Alpine.store('notify').alert("success", "Updated!");
					}
					this.loading = false;
				}, function (err) {
					this.loading = false;
					Alpine.store("recaptcha").value = null;
					if (window.grecaptcha) {
						window.grecaptcha.reset(window.recaptcha);
					}
					if (err.error === "validation") {
						this.errors = err.data;
					} else {
						Alpine.store('notify').alert("danger", err.error);
					}
				}.bind(this));
			}
		}
	});
});

window.recaptchaCallback = function() {
	const recaptchaField = document.getElementById("recaptcha-field");
	if (!recaptchaField) return;
	window.recaptcha = grecaptcha.render(recaptchaField, {
		sitekey: recaptchaField.dataset.key,
		callback: function(resp) {
			Alpine.store("recaptcha").value = resp;
			console.log("Recaptcha", resp);
		},
	});
};
`
