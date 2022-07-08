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
			errors: {},
			loading: false,
			submit(e) {
				this.errors = {};
				if (this.input.terms !== undefined) {
					this.input.terms = this.input.terms ? "agree" : "";
				}
				this.loading = true;
				sendRequest("POST", location.pathname, this.input, function(r) {
					console.log("Success", r);
					this.loading = false;
				}, function (err) {
					this.loading = false;
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
`
