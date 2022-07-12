package form

var formTemplate = `{{define "content"}}
<div class="container" x-data="form">
    <form class="form" @submit.prevent="submit">
        <h1 class="title">{{.Title}}</h1>
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
        {{if .Terms}}
        <div class="field">
            <div class="checkbox">
                <input id="agreeTerms" type="checkbox" value="agree" x-model="input.terms"/>
                <label for="agreeTerms">I agree to the <a href="{{.Path.Terms}}">terms and agreement</a>.</label>
            </div>
            <span class="help danger" x-show="errors.terms" x-text="errors.terms"></span>
        </div>
        {{end}}
        {{if .Recaptcha}}
        <div class="field">
            <div id="recaptcha-field" data-key="{{.Recaptcha}}"></div>
            <span class="help danger" x-show="errors.recaptcha" x-text="errors.recaptcha"></span>
        </div>
        {{end}}
        <div class="action-panel">
            <button type="submit" class="button">{{.Submit}}</button>
            <div class="list">
            {{range .Links}}
                <a href="{{.URL}}" class="link">&#x25B6; {{.Label}}</a>
            {{end}}
            </div>
        </div>
    </form>
</div>
{{end}}
`
