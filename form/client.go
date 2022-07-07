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

	function handleError(r) {
		console.log("Error", r);
	}

	Alpine.data('loginForm', function() {
		return {
			input: {},
			errors: {},
			loading: false,
			submit(e) {
				this.loading = true;
				sendRequest("POST", location.pathname, this.input, function(r) {
					console.log("Success", r);
					this.loading = false;
				}, function (err) {
					this.loading = false;
					if (err.error === "validation") {
						this.errors = err.data;
					}
				}.bind(this));
			}
		}
	})
})
`
