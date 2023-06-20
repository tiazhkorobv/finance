import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("provide username!", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("provide password!!!", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("bad username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["user_name"] = rows[0]["username"]
        session["user_hash"] = rows[0]["hash"]

        # print(session["user_name"])
        # print(session["user_hash"])
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


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Retrieve the values from the form
        username = str(request.form.get("username"))
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate form data
        if not username:
            return apology("provide username for registration!", 400)
        if not password:
            return apology("provide password for registration!", 400)
        if password != confirmation:
            return apology("passwords do not match for registration!", 400)

        # Check if the username is already taken
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return apology("username already exist", 400)

        # Generate password hash
        password_hash = generate_password_hash(password)

        # Add the user and hash to the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hash)
        # Redirect the user to the login page
        return redirect("/login")
    else:
        # Display the registration form
        return render_template("registration.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        user_id = session["user_id"]
        # session["user_name"] = rows[0]["username"]
        current_password_hash = session["user_hash"]
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Check if the new password matches the confirm password
        if new_password != confirm_password:
            flash("New password and confirm password must match.")
            return redirect("/change_password")

        # Retrieve the user's current password hash from the database
        # row = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session["user_id"])
        # current_password_hash = row["hash"]

        # Verify the current password
        if not check_password_hash(current_password_hash, current_password):
            flash("Invalid current password.")
            return redirect("/change_password")

        # Generate the new password hash
        new_password_hash = generate_password_hash(new_password)

        # Update the user's password hash in the database
        # db.execute("UPDATE users SET hash = :new_password_hash WHERE id=:user_id",
        #            new_password_hash=new_password_hash, user_id=user_id)
        db.execute("UPDATE users SET hash = ? WHERE id = ?",
                   new_password_hash, user_id)

        flash("Password changed successfully.")
        return redirect("/")

    return render_template("change_password.html")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":

        action = request.form.get("action")
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if action == "sell":
            return redirect(f"/sell?symbol={symbol}&shares={shares}")
        elif action == "buy":
            return redirect(f"/buy?symbol={symbol}&shares={shares}")

    # Get user's cash balance
    # rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash_balance = rows[0]["cash"]

    # Get user's portfolio
    portfolio = db.execute("""
        SELECT purchases.symbol, stocks.name, SUM(purchases.shares) as total_shares, purchases.price
        FROM purchases
        JOIN stocks ON purchases.symbol = stocks.symbol
        WHERE purchases.user_id = ?
        GROUP BY purchases.symbol, stocks.name
        HAVING total_shares > 0
    """, session["user_id"])

    # Calculate the total value of each holding and the grand total
    total_value = 0
    for stock in portfolio:
        symbol = stock["symbol"]
        shares = stock["total_shares"]
        price = stock["price"]
        total_value += shares * price

    grand_total = total_value + cash_balance

    return render_template("index.html", portfolio=portfolio, cash_balance=cash_balance, grand_total=grand_total)


@app.route("/quote", methods=["GET", "POST"])
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        stock_info = lookup(symbol)

        if stock_info:
            return render_template("quoted.html", stock=stock_info)
        else:
            apology_s = f"Sorry, the stock symbol '{symbol}' doesn't exist."
            # XXXXXXXX return render_template("apology.html", message=apology_s)
            return apology(apology_s, 400)
    else:
        return render_template("quote.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Ensure symbol and shares are provided
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("Missing symbol", 400)
        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Invalid number of shares", 400)

        # Look up stock symbol and get current price
        quote = lookup(symbol)
        if quote is None:
            return apology("Invalid symbol", 400)

        # Calculate total cost of purchase
        price = quote["price"]
        total_cost = price * int(shares)

        # Retrieve user's cash balance
        # rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash_balance = rows[0]["cash"]

        # Check if the user can afford the purchase
        if total_cost > cash_balance:
            return apology("Insufficient funds", 400)

        # Update user's cash balance
        updated_cash = cash_balance - total_cost
        # db.execute("UPDATE users SET cash = :cash WHERE id = :user_id",
        #     cash=updated_cash,
        #     user_id=session["user_id"]
        # )
        # !!!! db.execute("UPDATE users SET cash = ? WHERE id = ?", (updated_cash, session["user_id"]))
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, session["user_id"])

        # Check if the stock symbol already exists in the stocks table
        rows = db.execute("SELECT * FROM stocks WHERE symbol = ?", symbol)
        if len(rows) == 0:
            # If the stock symbol doesn't exist, insert it into the stocks table
            # db.execute(
            #     "INSERT INTO stocks (symbol, name) VALUES (:symbol, :name)",
            #     symbol=symbol,
            #     name=quote["name"]
            # )
            db.execute("INSERT INTO stocks (symbol, name) VALUES (?, ?)",
                       symbol, quote["name"])

        # Record the purchase in the database
        # db.execute(
        #     "INSERT INTO purchases (user_id, symbol, shares, price, type) VALUES (:user_id, :symbol, :shares, :price, :type)",
        #     user_id=session["user_id"],
        #     symbol=symbol,
        #     shares=int(shares),
        #     price=price,
        #     type="Bought"
        # )
        db.execute("INSERT INTO purchases (user_id, symbol, shares, price, type) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol, int(shares), price, "Bought")

        # Update the name and symbol in the stocks table
        # db.execute(
        #     "UPDATE stocks SET user_id = :user_id, name = :name, symbol = :symbol WHERE symbol = :old_symbol",
        #     user_id=session["user_id"],
        #     name=quote["name"],
        #     symbol=symbol,
        #     # user_id=session["user_id"],
        #     old_symbol=symbol
        # )
        db.execute("UPDATE stocks SET user_id = ?, name = ?, symbol = ? WHERE symbol = ?",
                   session["user_id"], quote["name"], symbol, symbol)

        # Redirect to home page
        return redirect("/")

    else:
        # Display the buy form
        return render_template("buy.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    # Get user's portfolio with total shares
    portfolio = db.execute("""
        SELECT purchases.symbol, stocks.name, SUM(purchases.shares) as total_shares
        FROM purchases
        JOIN stocks ON purchases.symbol = stocks.symbol
        WHERE purchases.user_id = ?
        GROUP BY purchases.symbol, stocks.name
        HAVING total_shares > 0
    """, session["user_id"])

    """Sell shares of stock"""
    if request.method == "POST":
        # Ensure symbol and shares are provided
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol:
            return apology("Missing symbol", 400)
        if not shares or int(shares) <= 0:
            return apology("Invalid number of shares", 400)

        # Check if the user owns the specified stock and has enough shares to sell
        stock_to_sell = next((stock for stock in portfolio if stock["symbol"] == symbol), None)
        if not stock_to_sell or stock_to_sell["total_shares"] < int(shares):
            return apology("You don't own enough shares of this stock", 400)

        # Look up stock symbol and get current price
        quote = lookup(symbol)
        if quote is None:
            return apology("Invalid symbol", 400)

        # Calculate total cost of shares to sell
        price = quote["price"]
        total_value = price * int(shares)

        # Retrieve user's cash balance
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash_balance = rows[0]["cash"]

        # # Check if the user does not own that many shares of the stock
        # if total_cost > cash_balance:
        #     return apology("Insufficient funds", 400)

        # Update user's cash balance
        updated_cash = cash_balance + total_value
        # db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", cash=updated_cash, user_id=session["user_id"])
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash,
                   session["user_id"])

        # Update the quantity of shares in the database
        # db.execute(
        #     "INSERT INTO purchases (user_id, symbol, shares, price, type) VALUES (:user_id, :symbol, :shares, :price, :type)",
        #     user_id=session["user_id"],
        #     symbol=symbol,
        #     shares=-int(shares),  # Negative shares to represent selling
        #     price=price,
        #     type="Sold"
        # )
        db.execute(
            "INSERT INTO purchases (user_id, symbol, shares, price, type) VALUES (?, ?, ?, ?, ?)",
            session["user_id"],
            symbol,
            -int(shares),  # Negative shares to represent selling
            price,
            "Sold"
        )

        # Redirect to home page
        return redirect("/")

    else:
        # Fetch the symbols from the 'stocks' table
        rows = db.execute("SELECT symbol FROM stocks WHERE user_id = ?", session["user_id"])
        symbols = [row["symbol"] for row in rows]

        return render_template("sell.html", symbols=symbols)


@app.route("/history")
@login_required
def history():
    # Retrieve user's transaction history from the database
    transactions = db.execute("SELECT * FROM purchases WHERE user_id = ?", session["user_id"])

    # Render the history template and pass the transactions data
    return render_template("history.html", transactions=transactions)

