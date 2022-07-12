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
		xhr.onreadystatechange = function (oEvent) {
			if (xhr.readyState === 4) {
				this.sending = false;
				const result = JSON.parse(xhr.responseText);
				if (result.error) {
					onError(result);
				} else {
					onSuccess(result);
				}
			}
		}.bind(this);
		xhr.send(data ? JSON.stringify(data) : undefined);
    }
	const env = document.getElementById("env").dataset;
	function actionUrl() {
		return env.base + "/action"
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
		}
	});

	const query = {};
	window.location.search.substring(1).split("&").map(function(s) {
		const vals = s.split("=");
		query[vals[0]] = vals.length > 1 ? decodeURIComponent(vals[1]) : null;
	});
	if (query.a === "verify") {
		sendRequest("POST", actionUrl(), {action: query.a, token: query.t}, function(r) {
			Alpine.store('notify').alert("success", "Email Verified");
			this.loading = false;
		}, function (err) {
			this.loading = false;
			Alpine.store('notify').alert("danger", err.error);
		});
	}
	const success = sessionStorage.getItem("alertSuccess");
	if (success) {
		Alpine.store('notify').alert("success", success);
		sessionStorage.removeItem("alertSuccess");
	}
	Alpine.data('form', function() {
		return {
			init: function () {
				if (location.pathname === env.base + env.account) {
					const self = this;
					sendRequest("GET", location.pathname, null, function(r) {
						self.input = r;
					}, function (err) {
						Alpine.store('notify').alert("danger", err.error);
					});
				}
			},
			input: {},
			hide: {},
			errors: {},
			loading: false,
			submit(e) {
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
				if (query.a) {
					path = actionUrl();
					this.input.action = query.a;
					if (query.t) {
						this.input.token = query.t;
					}
				}
				sendRequest("POST", path, this.input, function(r) {
					if (query.a === "resetlink" || query.a === "reset") {
						location.href = "?";
						sessionStorage.setItem("alertSuccess", query.a === "resetlink" ? "Reset link sent!" : "Password updated!");
						return;
					}
					location.href = env.home;
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
