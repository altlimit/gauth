package form

var register = `{{define "content"}}
<div class="container" x-data="form">
    <form class="form" @submit.prevent="submit">
        <h1 class="title">Create An Account</h1>
        <span x-html="JSON.stringify(input)"></span>
        {{range .Fields}}
            <div class="field">
                <label for="{{.ID}}">{{.Label}}</label>
                {{if eq .Type "select"}}
                    <select id="{{.ID}}" x-model="input.{{.ID}}">
                    {{range .Options}}
                        <option value="{{.ID}}">{{.Label}}</option>
                    {{end}}
                    </select>
                {{else if eq .Type "textarea"}}
                    <textarea id="{{.ID}}" x-model="input.{{.ID}}" rows=5></textarea>
                {{else}}
                    <input id="{{.ID}}" type="{{.Type}}" x-model="input.{{.ID}}"/>
                {{end}}
                <span class="help danger" x-show="errors.{{.ID}}" x-text="errors.{{.ID}}"></span>
            </div>
        {{end}}
        {{if .Path.Terms}}
        <div class="field">
            <div class="checkbox">
                <input id="agreeTerms" type="checkbox" value="agree" x-model="input.terms"/>
                <label for="agreeTerms">I agree to the <a href="{{.Path.Terms}}">terms and agreement</a>.</label>
            </div>
            <span class="help danger" x-show="errors.terms" x-text="errors.terms"></span>
        </div>
        {{end}}
        <div class="action-panel">
            <button type="submit" class="button">Register</button>
            <div class="list">
                <a href="{{.Path.Base}}{{.Path.Login}}" class="link">&#x25B6; Login</a>
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
