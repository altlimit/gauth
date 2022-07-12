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
		xhr.send(JSON.stringify(data));
    }

	function actionUrl() {
		return location.pathname.substring(0, location.pathname.lastIndexOf("/") + 1) + "action";
	}

	const query = {};
	window.location.search.substring(1).split("&").map(function(s) {
		const vals = s.split("=");
		query[vals[0]] = vals.length > 1 ? vals[1] : null;
	});

	if (query.verify) {
		sendRequest("POST", actionUrl(), query, function(r) {
			Alpine.store('notify').alert("success", "Email Verified");
			this.loading = false;
		}, function (err) {
			this.loading = false;
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

	Alpine.data('form', function() {
		return {
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
				if (query.fp === "1") {
					path = actionUrl();
					this.input.forgot = "password";
				}
				sendRequest("POST", path, this.input, function(r) {
					location.href = document.getElementById("home-link").href;
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
