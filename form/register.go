package form

var register = `{{define "content"}}
<div class="container">
    <form class="form">
        <h1 class="title">Create An Account</h1>
        <div class="field">
            <label for="email">Email Address</label>
            <input id="email" type="email"/>
            <span class="help danger">please enter a valid email address</span>
        </div>
        <div class="field">
            <label for="password">Password</label>
            <input id="password" type="password"/>
        </div>
        <div class="field">
            <label for="confirm">Re-Type Password</label>
            <input id="confirm" type="password"/>
        </div>
        <div class="field">
            <label for="question">Security Question</label>
            <select id="question" name="question">
                <option value="">Pick a security question</option>
                <option value="1">What is the name of your favorite pet?</option>
                <option value="2">What is your mother's maiden name?</option>
                <option value="3">What high school did you attend?</option>
                <option value="4">What is the name of your first school?</option>
                <option value="5">What was the make of your first car?</option>
                <option value="6">What was your favorite food as a child?</option>
              </select>
        </div>
        <div class="field">
            <label for="answer">Answer</label>
            <textarea id="answer" rows=5></textarea>
        </div>
        <div class="field checkbox">
            <label for="agree">I agree to the terms and agreement.</label>
            <input id="agree" type="checkbox"/>
        </div>
        <div class="action-panel">
            <button type="submit" class="button">Register</button>
            <div class="list">
                <a href="#" class="link">&#x25B6; Login</a>
            </div>

        </div>
    </form>
</div>
{{end}}`
