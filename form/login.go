package form

var login = `{{define "content"}}
<div class="container" x-data="loginForm">
    <form class="form" @submit.prevent="submit">
        <h1 class="title">Login</h1>
        {{range .Fields}}
        <div class="field">
            <label for="{{.ID}}">{{.Label}}</label>
            <input id="{{.ID}}" type="{{.Type}}" x-model="input.{{.ID}}"/>
            <span class="help danger" x-show="errors.{{.ID}}" x-text="errors.{{.ID}}"></span>
        </div>
        {{end}}
        <button type="submit" :disabled="loading" class="button">Login</button>
    </form>
</div>
{{end}}


{{ define "nav"}}
<div class="nav-panel">
    <a href="/" class="link back">&#x1F844; Home</a>
    <nav class="nav">
        <a href="/register">Register</a>
    </nav>
</div>
{{ end }}
`
