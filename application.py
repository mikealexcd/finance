import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Define Variables that will be used in the index
    user_id = session.get("user_id")
    cash = db.execute("SELECT cash FROM users where id = :user_id", user_id = user_id)
    # Select required data for the index display and group them by symbol
    stockinfo = db.execute("SELECT symbol,SUM(shares) as shares,SUM(Cost) as cost FROM transactions WHERE user_id=:user_id GROUP BY symbol;", user_id=user_id)
    # Check allows stocks whose transactions = 0 to not be displayed in the index
    check = len(stockinfo)
    cashc = cash[0].get("cash")
    grandtotal = cash[0].get("cash")


    # For each row in stockinfo (from transactions made)
    for row in stockinfo:
        query = lookup(row["symbol"])
        title = query["name"]
        price = query["price"]
        stocktotal = query["price"] * row["shares"]
        # Add values from lookup or computed values to the dictionary in the current part of the list
        row.update({"current_price":price})
        row.update({"title":title})
        row.update({"stocktotal":stocktotal})
        grandtotal += stocktotal
    print(stockinfo)
    return render_template("index.html", check=check, stockinfo=stockinfo, cash=cashc, grandtotal=grandtotal)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        # Check for an empty input, non-numbers in shares, and negative integers.
        if not symbol:
            return apology("enter a symbol")
        try:
            int(shares)
        except ValueError as error:
            return apology("only integers allowed")
        if not shares or int(shares) <= 0:
            return apology("enter a valid number of shares")
        stocks = lookup(symbol)
        if stocks == None:
            return apology("your stock was not found!")
        user_id = session.get("user_id")
        user_info = db.execute("SELECT * FROM users where id = :user_id", user_id = user_id)
        cash = user_info[0].get("cash")
        cost = stocks["price"] * float(shares)
        if cost > cash:
            return apology("You can't afford that")
        else:
            db.execute("INSERT INTO transactions (user_id, cost, symbol, shares, type, trans_date) VALUES (:user_id, :cost, :symbol, :shares, 'buy', datetime('now'))",
                        user_id = user_id,
                        cost = cost * (-1),
                        symbol = symbol.upper(),
                        shares = shares)
            db.execute("UPDATE users SET cash = :cash WHERE id = :user_id",
                        cash = cash - cost,
                        user_id = user_id)
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Define Variables that will be used in the index
    user_id = session.get("user_id")
    stockinfo = db.execute("SELECT * FROM transactions WHERE user_id=:user_id;", user_id=user_id)
    check = len(stockinfo)

    # For each row in stockinfo (from transactions made)
    for row in stockinfo:
        query = lookup(row["symbol"])
        title = query["name"]
        row.update({"title":title})
        value = row["cost"]
        row.update({"value":value})
    return render_template("history.html", check=check, stockinfo=stockinfo,)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == ("POST"):
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("you must enter a valid symbol")
        stock = lookup(symbol)
        print(stock)
        return render_template("quoted.html", stock=stock)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("must provide username", 403)
        elif not password or not confirmation:
            return apology("you must enter a password and password confirmation")
        if password != confirmation:
            return apology("password and confirmation must match")
        reg = db.execute("INSERT INTO users (username,hash,cash) VALUES (:username, :password, :cash)",
                        username=username, password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8), cash=10000)
        return redirect("/")
    else:
        return render_template("/register.html")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password"""
    if request.method == "POST":
        password = request.form.get("password")
        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")
        user_id = session.get("user_id")
        if not password:
            return apology("must provide your password", 403)
        elif not newpassword or not confirmation:
            return apology("you must enter a new password and password confirmation")
        if newpassword != confirmation:
            return apology("password and confirmation must match")
        reg = db.execute("UPDATE users SET hash=:password WHERE id=:user_id",
                        user_id=user_id, password=generate_password_hash(newpassword, method='pbkdf2:sha256', salt_length=8))
        return redirect("/")
    else:
        return render_template("/password.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session.get("user_id")
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        # Check if the inputs are empty
        if not symbol or not shares:
            return apology("you have to complete all fields")
        # Check if input is an integer
        try:
            int(shares)
        except ValueError as error:
            return apology("only integers allowed")
        if int(shares) < 1:
            return apology("you cannot sell less than 1 share")
        #
        tosell = db.execute("SELECT * FROM transactions WHERE user_id = :user_id AND symbol=:symbol GROUP BY symbol", user_id=user_id, symbol=symbol)
        print(f"tosell = {tosell}")
        stocks = lookup(symbol)
        cost = stocks["price"] * float(shares)
        user_info = db.execute("SELECT * FROM users WHERE id = :user_id", user_id = user_id)
        cash = user_info[0].get("cash")
        sellableshares = tosell[0].get("shares")
        if int(shares) > sellableshares:
            return apology("you cannot sell more shares than you own")
        else:
            shares = int(shares) * -1
            print("updated shares:", shares)
            db.execute("UPDATE users SET cash = :cash WHERE id = :user_id",
                        cash = cash + cost,
                        user_id = user_id)
            db.execute("INSERT INTO transactions (user_id, cost, symbol, shares, type, trans_date) VALUES (:user_id, :cost, :symbol, :shares, 'sell', datetime('now'))",
                        user_id = user_id,
                        cost = cost,
                        symbol = symbol.upper(),
                        shares = shares)
            return redirect("/")

    else:
        options = db.execute("SELECT symbol FROM transactions where user_id = :user_id GROUP BY symbol", user_id = user_id)
        for row in options:
            print(row["symbol"])
        return render_template("sell.html", options=options)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
