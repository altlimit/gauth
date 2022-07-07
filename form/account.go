package form

var account = `{{define "content"}}
<div class="container">
    <form class="form">
        <h1 class="title">Password</h1>
        <div class="field">
            <label for="password">Password</label>
            <input id="password" type="password"/>
        </div>
        <div class="field">
            <label for="confirm">Re-Type Password</label>
            <input id="confirm" type="password"/>
        </div>
        <button type="submit" class="button">Update</button>
    </form>
</div>
{{end}}`
