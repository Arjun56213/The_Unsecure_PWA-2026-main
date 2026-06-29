from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask_cors import CORS
import secrets
from flask import session
import user_management as dbHandler

# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)
# Enable CORS to allow cross-origin requests 
CORS(app, resources={r"/*": {"origins": "http://localhost:5000"}})

# Secret key required for session management and CSRF token generation - Without this sessions can't be used securely
app.secret_key = "asdbjkl#*@&Sah#*dgfrtyui[oiljkghfbfauisdgdhsjwe9*&weewrwe798*&*&*&"

@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    
    if request.method == "GET" and request.args.get("url"):

        # Generate CSRF token and pass to feedback form for verification on submission
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        if request.form.get("csrf_token") != session.get("csrf_token"):
            return "Invalid CSRF token", 403
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        # Regenerate CSRF token after feedback submission so the form can be used again
        session["csrf_token"] = secrets.token_hex(32)
        return render_template("/success.html", state=True, value="Back", csrf_token=session["csrf_token"])
    else:
        dbHandler.listFeedback()
        session["csrf_token"] = secrets.token_hex(32)
        return render_template("/success.html", state=True, value="Back", csrf_token=session["csrf_token"])


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):

        # Generate CSRF token and pass to signup form for verification on submission
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":

        # Check CSRF token matches session token before processing signup
        if request.form.get("csrf_token") != session.get("csrf_token"):
            return "Invalid CSRF token", 403
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]
        dbHandler.insertUser(username, password, DoB)
        # Regenerate CSRF token after signup so login form can be submitted
        session["csrf_token"] = secrets.token_hex(32)
        return render_template("/index.html", csrf_token=session["csrf_token"])
    else:
        session["csrf_token"] = secrets.token_hex(32)
        return render_template("/signup.html", csrf_token=session["csrf_token"])


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    # Simple Dynamic menu
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    # Pass message to front end
    elif request.method == "GET":
        msg = request.args.get("msg", "")

        # Generate a random CSRF token and store it in the session for later verification
        session["csrf_token"] = secrets.token_hex(32)
        return render_template("/index.html", msg=msg, csrf_token=session["csrf_token"])
    elif request.method == "POST":

        # Check the token submitted with the form matches the one stored in the session - If they do not match the request is rejected as a potential CSRF attack
        if request.form.get("csrf_token") != session.get("csrf_token"):
            return "Invalid CSRF token", 403
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            dbHandler.listFeedback()
            # Generate CSRF token for the feedback form on the success page
            session["csrf_token"] = secrets.token_hex(32)
            return render_template("/success.html", value=username, state=isLoggedIn, csrf_token=session["csrf_token"])

        else:
            # Regenerate CSRF token when login fails so the form can be resubmitted
            session["csrf_token"] = secrets.token_hex(32)
            return render_template("/index.html", csrf_token=session["csrf_token"])
    else:
        return render_template("/index.html")


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)