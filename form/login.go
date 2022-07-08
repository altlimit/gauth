package form

var login = `{{define "content"}}
<div class="container" x-data="form">
    <form class="form" @submit.prevent="submit">
        <h1 class="title">Login</h1>
        {{range .Fields}}
        <div class="field">
            <label for="{{.ID}}">{{.Label}}</label>
            <input id="{{.ID}}" type="{{.Type}}" x-model="input.{{.ID}}"/>
            <span class="help danger" x-show="errors.{{.ID}}" x-text="errors.{{.ID}}"></span>
        </div>
        {{end}}
        <div class="action-panel">
            <button type="submit" :disabled="loading" class="button">Login</button>
            <div class="list">
                <a href="{{.Path.Base}}{{.Path.Register}}" class="link">&#x25B6; Register</a>
            </div>
        </div>

    </form>
</div>
{{end}}


{{ define "nav"}}
<div class="nav-panel">
    <a href="{{.Path.Home}}" class="link back">&#x1F844; Home</a>
</div>
{{ end }}
`
