package form

var layout = `{{define "layout"}}
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{{.Title}} - {{.Brand.AppName}}</title>
<meta name="description" content="{{.Description}}">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0" />
<style>
:root {
    --primary: {{.Brand.Primary}};
    --primary-inverse: {{.Brand.PrimaryInverse}};
    --accent: {{.Brand.Accent}};
    --neutral: {{.Brand.Neutral}};
    --neutral-inverse: {{.Brand.NeutralInverse}};
    --danger: #D9422B;
    --success: #689342;
    --warning: #E66700;
    --sans-serif: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    --serif: Georgia, 'Times New Roman', Times, serif;
    --code: 'Courier New', Courier, monospace;
}
* {
    box-sizing: border-box;
    color: var(--neutral);
}
html,body {
    margin: 0;
}
body {
    font-family: var(--sans-serif);
    display: flex;
    min-height: 100vh;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background-color: var(--accent);
}
h1,h2,h3,h4,h5,h6 {
    font-family: var(--serif);
    color: var(--primary);
}
p {
    font-size: large;
}
.backdrop {
    position:fixed;
    top:0;
    left:0;
    width:100vw;
    height:100vh;
    z-index:-10;
    background-color: var(--accent);
    opacity: 0.4;
    background-image:  linear-gradient(var(--neutral-inverse) 2px, transparent 2px), linear-gradient(90deg, var(--neutral-inverse) 2px, transparent 2px), linear-gradient(var(--neutral-inverse) 1px, transparent 1px), linear-gradient(90deg, var(--neutral-inverse) 1px, var(--accent) 1px);
    background-size: 50px 50px, 50px 50px, 10px 10px, 10px 10px;
    background-position: -2px -2px, -2px -2px, -1px -1px, -1px -1px;
}
.title {
    align-self: start;
}
.workspace {
    display: flex;
    flex-direction: column;
    width: 100vw;
    background-color: var(--primary-inverse);
}
.sidebar {
    display: flex;
    flex-direction: column;
    justify-content: center;
    justify-items: flex-start;
    align-items: center;
    margin:0;
}
.main {
    flex-grow: 1;
    display: flex;
    align-items: flex-start;
}
.container {
    background-color: var(--primary-inverse);
    padding: 0 2rem 2rem;
    width: 100%;
    display: flex;
    flex-direction: column;
    justify-items: stretch;
    align-items: center;
    justify-content: center;
    filter: drop-shadow(0 1px 1px rgb(0 0 0 / 0.05));
}
.form {
    display: flex;
    flex-direction: column;
    flex-grow: 1;
    width: 100%;
    max-width: 400px;
    gap: 1rem;
    background: var(--primary-inverse);
}
.field {
    display: flex;
    width: auto;
    flex-direction: column;
    gap: 0.375rem;
}
.checkbox {
    flex-direction: row;
    justify-content: left;
    align-items: baseline;
}
label {
    font-weight: 500;
    letter-spacing: 0.075rem;
}
.checkbox > label {
    font-weight: 300;
    user-select: none;
    letter-spacing:normal;
    font-size:medium;
}
input[type=text],input[type=password],input[type=number],input[type=email],select {
    outline-color: var(--primary);
    border: solid 1px var(--neutral);
    font-size:large;
    width: 100%;
    height: 2.5rem;
}
textarea {
    outline-color: var(--accent);
    border: solid 1px var(--neutral);
    font-family: sans-serif;
    font-size: large;
}
input[type=checkbox] {
    position: relative;
    cursor: pointer;
    margin-right: 0.75rem;
    height: 1rem;
}
input[type=checkbox]:before {
    content: "";
    display: block;
    position: absolute;
    width: 20px;
    height: 20px;
    top: 0;
    left: 0;
    background-color: var(--neutral-inverse);
}
input[type=checkbox]:checked:before {
    content: "";
    display: block;
    position: absolute;
    width: 20px;
    height: 20px;
    top: 0;
    left: 0;
    background-color: var(--primary);
}
input[type=checkbox]:checked:after {
    content: "";
    display: block;
    width: 5px;
    height: 10px;
    border: solid var(--primary-inverse);
    border-width: 0 2px 2px 0;
    -webkit-transform: rotate(45deg);
    -ms-transform: rotate(45deg);
    transform: rotate(45deg);
    position: absolute;
    top: 2px;
    left: 6px;
}
.help {
    font-size: small;
    font-weight: 400;
    letter-spacing: 1px;
}
.help.danger {
    color: var(--danger);
}
.help::first-letter {
    text-transform: capitalize;
}
.button {
    color: var(--primary-inverse);
    background-color: var(--primary);
    padding: 1rem 1.5rem;
    font-size: large;
    font-weight: 500;
    letter-spacing: 0.075rem;
    border:none;
    border-radius: 0.375rem;
    cursor: pointer;
}
.button:hover {
    filter: brightness(85%);
    filter: drop-shadow(0 4px 3px rgb(0 0 0 / 0.07)) drop-shadow(0 2px 2px rgb(0 0 0 / 0.06));
}
footer {
    padding: 2rem;
    color: var(--primary);
    font-size: smaller;
}
.notify {
    width:100%;
}
.notification {
    position: fixed;
    bottom: 0;
    width: 100%;
    padding: 1rem;
    background-color: var(--primary-inverse);
    border: var(--neutral);
    filter: drop-shadow(0 4px 3px rgb(0 0 0 / 0.07)) drop-shadow(0 2px 2px rgb(0 0 0 / 0.06));
    display: flex;
}
.notification .message {
    color: white;
    width: 100%;
    font-weight: 500;
}
.notification .close {
    cursor: pointer;
}
.notification.success {
    background-color: var(--success);
    color: white;
}
.notification.warning {
    background-color: var(--warning);
    color: white;
}
.notification.danger {
    background-color: var(--danger);
    color: white;
}
:disabled,.disable{
    cursor: not-allowed;
    opacity:.5;
}
.logo {
    font-weight: 100;
    font-size: 1.5rem;
    padding: 1rem;
    display: flex;
    flex-direction: row;
    text-align: left;
    align-items: center;
}
.logo img {
    margin: 0 1rem 0 1rem;
    width: 70px;
    height: 70px;
}
.nav-panel {
    display: flex;
    width: 100%;
    flex-direction: row;
    justify-content: space-between;
    justify-items: center;
    align-items: center;
    background-color: var(--neutral-inverse);
    color: var(--neutral);
}
.back {
    padding: 1rem;
}
.nav {
    display: inline-flex;
    flex-direction: row;
    align-items: center;
    gap: 2px;
}
.nav a:not(:last-child) {
    border-right: solid 1px var(--accent);
}
.nav > a {
    text-decoration: none;
    width: 100%;
    padding: 1rem;
    text-align: center;
    font-weight: 500;
    color: var(--neutral);
}
.nav > a:hover {
    color: var(--primary);
}
.link {
    color: var(--primary);
    filter: brightness(90%);
    font-size: large;
    font-weight: 500;
    text-decoration: none;
    justify-items: flex-start;
}
.link:hover {
    filter: drop-shadow(0 4px 3px rgb(0 0 0 / 0.07)) drop-shadow(0 2px 2px rgb(0 0 0 / 0.06));
}
.action-panel {
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: flex-start;
    flex-grow: 0;
    gap: 1rem;
}
.list {
    display: flex;
    flex-direction: column;
}
pre {
    padding: 1rem;
    background-color: var(--neutral);
    color: var(--neutral-inverse);
    max-width: 500px;
    overflow-x: scroll;
    font-family: var(--code);
    font-size:large;
}
@media only screen and (min-width: 600px) {
    .container {
        padding: 2rem 4rem;
    }
    .workspace {
        flex-direction: row;
        width: 800px;
    }
    .logo {
        font-size: 2rem;
        flex-direction: column;
        text-align: center;
    }
    .logo img {
        width: 100px;
        height: 100px;
    }
    .sidebar {
        flex-direction: column-reverse;
        justify-content: space-between;
        justify-items: center;
        align-items: center;
        padding: 1.5rem 1rem;
        margin: 0;
        background-color: var(--neutral-inverse);
        width: 35%;
    }
    .logo > img {
        background-color:var(--neutral-inverse);
    }
    .main {
        width: auto;
    }
    .button {
        padding: 1rem 3rem;
        justify-self: flex-start;
        align-self: flex-start;
    }
    .nav-panel {
        width: 100%;
        flex-direction: column-reverse;
    }
    .back {
        background-color: transparent;
        justify-self: start;
        align-self: flex-start;
    }
    .nav {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 2px;
        margin: 0 3rem;
    }
    .nav > a:not(:last-child) {
        border-bottom: solid 1px var(--accent);
        border-right: 0;
    }
    .nav > a {
        padding: 0.5rem 3rem;
    }
}
</style>
<script src="{{.Path.Base}}/client.js"></script>
<script defer src="{{.Path.Base}}{{.AlpineJSURL}}"></script>
{{if .Recaptcha}}
<script defer src="https://www.google.com/recaptcha/api.js?onload=recaptchaCallback&render=explicit"></script>
{{end}}
</head>

<body>
    <div class="backdrop"></div>
    <div class="workspace">
        <figure class="sidebar">
            <div class="nav-panel">
                {{template "nav" .}}
            </div>
            <figure class="logo">
                {{if .Brand.LogoURL}}
                    <a href="{{.Brand.AppURL}}">
                        <img src="{{.Brand.LogoURL}}" />
                    </a>
                {{end}}
                {{.Brand.AppName}}
            </figure>
        </figure>
        <div class="main">
            {{template "content" .}}
        </div>
    </div>
    <div x-data class="notify">
        <template x-for="(a, i) in $store.notify.alerts">
            <div class="notification" :class="a.type">
                <span class="message" x-text="a.message"></span>
                <span class="close" @click="$store.notify.close(i)">X</span>
            </div>
        </template>
    </div>
</body>
</html>
{{end}}`

var nav = `
{{ define "nav"}}
<div class="nav-panel">
    <a href="{{.Path.Home}}" id="home-link" class="link back">&#x1F844; Home</a>
</div>
{{ end }}
`
