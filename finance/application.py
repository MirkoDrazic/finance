import os
import datetime
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
db = SQLAlchemy(app)

class User(db.Model):
    #__tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hash = db.Column(db.String(120), unique=True, nullable=False)
    cash = db.Column(db.Float, default = '10000', nullable = False)
    hist = db.relationship('History', backref = 'user', lazy = True)
    portfol = db.relationship('Portfolio', backref = 'user', lazy = True)

class History(db.Model):
    #__tablename__ = 'history'
    id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False, primary_key=True)
    symbol = db.Column(db.String(20), nullable = False, primary_key=True)
    shares = db.Column(db.Integer, nullable = False, primary_key=True)
    price = db.Column(db.Float, nullable = False, primary_key=True)
    transacted = db.Column(db.DateTime, default=datetime.datetime.utcnow, primary_key=True)

class Portfolio(db.Model):
    #__tablename__ = 'portfolio'
    id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False, primary_key=True)
    symbol = db.Column(db.String(20), nullable = False, primary_key=True)
    shares = db.Column(db.Integer, nullable = False)
db.create_all()
db.session.commit()

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



@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    rows_of_pf = Portfolio.query.filter_by(id = session['user_id']).all()
    #rows_of_pf = db.execute('SELECT * from portfolio WHERE id=:id', id = session['user_id'])
    if rows_of_pf == []:
        cashier = User.query.get(session['user_id'])
        #cashier = db.execute('SELECT cash FROM users WHERE id = :id', id = session['user_id'])
        cash = cashier.cash
        #cash = cashier[0]['cash']
        return render_template('index.html', current_cash = cash, total_cash = cash)
    else:
        new_rows_of_pf = []
        for row in rows_of_pf:
            new_pf_dict = {}
            quote = lookup(row.symbol)
            new_pf_dict['symbol'] = quote['symbol']
            new_pf_dict['name'] = quote['name']
            new_pf_dict['price'] = quote['price']
            new_pf_dict['shares'] = row.shares
            new_pf_dict['total'] = row.shares * quote['price']
            new_rows_of_pf.append(new_pf_dict)
    cashier = User.query.get(session['user_id'])
    #cashier = db.execute('SELECT cash FROM users WHERE id = :id', id = session['user_id'])
    cash = cashier.cash
    #cash = cashier[0]['cash']
    total_cash = cash
    for row in new_rows_of_pf:
        total_cash += row['total']
    return render_template('index.html', rows_of_pf = new_rows_of_pf, current_cash = cash, total_cash = total_cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        #ensure that symbol is not missing
        if not request.form.get('symbol'):
            return apology('missing symbol')
        #ensure that number of shares is not missing, and is an integer
        elif not request.form.get('shares'):
            return apology('missig number of shares')
        elif not request.form.get('shares').isdigit():
            return apology('invalid symbol')

        #storing symbol entered by user in ALL CAPS
        symbol = request.form.get('symbol').upper()

        # usig helper function quote to get quote
        quote = lookup(symbol)

        # checking if lookup failed
        if quote == None:
            return apology('Invalid Symbol')

        # if you can't afford the share
        cash = User.query.get(session['user_id']).cash
        #cash = db.execute('SELECT cash FROM users WHERE id = :id', id = session['user_id'])[0]['cash']
        price = int(quote['price'])
        shares = int(request.form.get('shares'))
        updated_cash =cash - shares * price
        if updated_cash < 0:
            return apology('Can not afford that many shares since you have ${0} and the full price is ${1}'.format(cash, shares*price))
        # Everything OK now: 1. update cash 2. update portfolio table 3. update history table
        else:
            # update the cash in the users table
            user = User.query.get(session['user_id'])
            user.cash = updated_cash
            db.session.commit()
            #db.execute('UPDATE users SET cash = :updated_cash WHERE id = :id', updated_cash = updated_cash, id = session['user_id'])

            # update portfolio table based on the appropriate stock symbol
            rows = Portfolio.query.filter_by(id = session['user_id'], symbol = symbol).all()
            #rows = db.execute('SELECT * FROM portfolio WHERE id=:id AND symbol=:symbol', id=session['user_id'], symbol=symbol)

            # if there are no shares of the particular symbol, INSERT a new row into portfolio
            if len(rows) == 0:
                new_row = Portfolio(id = session['user_id'], symbol = symbol, shares = shares)
                db.session.add(new_row)
                db.session.commit()
                #db.execute('INSERT INTO portfolio (id, symbol, shares) VALUES (:id, :symbol, :shares)', id = session['user_id'], symbol = symbol, shares = shares)
            else:
                asset = Portfolio.query.filter_by(id = session['user_id'], symbol = symbol).all()[0]
                asset.shares += shares
                db.session.commit()
                #db.execute('UPDATE portfolio SET shares = shares + :shares WHERE id=:id AND symbol=:symbol', id=session['user_id'], symbol = symbol,  shares = shares)
            # update history table
            new_row = History(id = session['user_id'], symbol =symbol, shares = shares, price = price)
            db.session.add(new_row)
            db.session.commit()
            #db.execute('INSERT INTO history (id, symbol, shares, price) VALUES (:id, :symbol, :shares, :price)', id = session['user_id'], symbol =symbol, shares = shares, price = price)
            # return to the index.html page
            return redirect(url_for('index'))
    else:
        return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = History.query.filter_by(id = session['user_id']).all()
    #rows = db.execute('SELECT * FROM history WHERE id = :id', id = session['user_id'])
    return render_template('history.html', history_list = rows)


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
        rows = User.query.filter_by(username = request.form.get("username")).all()
        #rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0].hash, request.form.get("password")):
        #if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0].id

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
    # User reached route via POST (as by submitting a form via POST)
    if request.method == 'POST':
        # ensure quote was submitted
        if not request.form.get('symbol'):
            return apology('Missing Symbol')

        #storing symbol entered by user in ALL CAPS
        symbol = request.form.get('symbol').upper()

        # usig helper function quote to get quote
        quote = lookup(symbol)

        # checking if lookup failed
        if quote == None:
            return apology('Invalid Symbol')

        return render_template('quoted.html', name = quote['name'], symbol=quote['symbol'], price=quote['price'])
    else:
    # User reached route via GET (as by clicking a link or via redirect)
        return render_template('quote.html')
    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()
    #If the user reached the route via POST
    if request.method == 'POST':
        # ensure username was subimtted
        if not request.form.get("username"):
            return apology('must provide username')

        # ensure password was submitted
        elif not request.form.get('password'):
            return apology('must provide password')
        # ensure password confirmation was submitted
        elif not request.form.get('password_confirmation'):
            return apology('must provide password confirmation')
        # ensure passwords match
        elif request.form.get('password_confirmation') != request.form.get('password'):
            return apology("passwords don't match")
        # ensure username is not taken
        elif User.query.filter_by(username = request.form.get('username')).all():
        #elif db.execute('SELECT * FROM users WHERE username = :username', username = request.form.get("username")):
            return apology('username is already taken')

        # all's well now, we can add the user into our database
        new_row = User(username = request.form.get("username"), hash = generate_password_hash(request.form.get("password")))
        db.session.add(new_row)
        db.session.commit()
        #db.execute('INSERT INTO users (username, hash) VALUES (:username, :hash);', username = request.form.get("username"), hash = generate_password_hash(request.form.get("password")))

        # redirect the user to index/home page
        return redirect(url_for('login'))
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    #if the user has submitted the form
    if request.method == 'POST':
        #ensure that symbol is not missing
        if not request.form.get('symbol'):
            return apology('missing symbol')
        #ensure that number of shares is not missing, and is an integer
        elif not request.form.get('shares'):
            return apology('missig number of shares')
        elif not request.form.get('shares').isdigit():
            return apology('invalid symbol')

        #storing symbol entered by user in ALL CAPS
        symbol = request.form.get('symbol').upper()

        # usig helper function quote to get quote
        quote = lookup(symbol)

        # checking if lookup failed
        if quote == None:
            return apology('Invalid Symbol')

        #shares is the number of shares typed in by the user
        shares = int(request.form.get('shares'))

        #checking if shares are positive
        if shares < 0:
            return apology('invalid shares, has to be positive integer')

        # checking if the user has the share he has typed in
        shares_already_list = Portfolio.query.filter_by(id=session['user_id'], symbol=symbol).all()
        #shares_already_list = [asset.shares for asset in shares_already_list]
        #shares_already_list = db.execute('SELECT shares FROM portfolio WHERE id=:id AND symbol=:symbol', id=session['user_id'], symbol=symbol)
        if len(shares_already_list) == 0:
            return apology('symbol not owned')
        shares_already = shares_already_list[0].shares
        updated_shares = shares_already - shares
        if updated_shares < 0:
            return apology('Too many shares')


        # price is the current price of the stock
        price = quote['price']

        # cash increase is the increase in price after selling the shares
        cash_increase = price * shares

        # update cash from users table
        user = User.query.get(session['user_id'])
        user.cash += cash_increase
        db.session.commit()
        #db.execute('UPDATE users SET cash=cash + :cash_increase WHERE id=:id', id=session['user_id'], cash_increase = cash_increase)

        # update the portfolio table
        # if the updated shares==0 then delete the row with the symbol
        if updated_shares == 0:
            asset_for_deletion = Portfolio.query.filter_by(id=session['user_id'], symbol=symbol).all()[0]
            db.session.delete(asset_for_deletion)
            db.session.commit()
            #db.execute('DELETE FROM portfolio WHERE id=:id AND symbol = :symbol', id=session['user_id'], symbol=symbol)
        #else
        elif updated_shares > 0 :
            asset = Portfolio.query.filter_by(id=session['user_id'], symbol = symbol).all()[0]
            asset.shares = updated_shares
            db.session.commit()
            #db.execute('UPDATE portfolio SET shares= :updated_shares WHERE id=:id AND symbol=:symbol', id = session['user_id'], symbol = symbol, updated_shares = updated_shares)

        #update the history table
        new_row = History(id=session['user_id'], symbol=symbol, shares=-(shares), price=price)
        db.session.add(new_row)
        db.session.commit()
        #db.execute('INSERT INTO history (id, symbol, shares, price) VALUES (:id, :symbol, :shares, :price)', id=session['user_id'], symbol=symbol, shares=-(shares), price=price)

        return redirect(url_for('index'))
    # if the user came here via GET
    else:
        return render_template('sell.html')

@app.route('/password', methods=["GET", "POST"])
@login_required
def password():
    """Changes Password for user already logged in"""
    #missing information
    if request.method == "POST":
        if not request.form.get('old_password'):
            return apology('must enter old password')
        elif not request.form.get('new_password'):
            return apology('must enter new password')
        elif not request.form.get('confirmation'):
            return apology('must enter new password again')
        # confirming the password and password again
        if request.form.get('new_password') != request.form.get('confirmation'):
            return apology('new passwords must match')
        # checking if the old password is correct
        hashes = User.query.get(session['user_id']).hash
        #hashes = db.execute('SELECT * FROM users WHERE id = :id', id = session['user_id'])[0]['hash']
        print(hashes)
        if not check_password_hash(hashes, request.form.get('old_password')):
            return apology('old_password is wrong')
        # updating the users table's hash
        user = User.query.get(session['user_id'])
        user.hash = generate_password_hash(request.form.get("new_password"))
        db.session.commit()
        #db.execute('UPDATE users SET hash = :hash WHERE id=:id', hash = generate_password_hash(request.form.get("new_password")), id= session['user_id'])
        flash('password changed successfully')
        return redirect(url_for('index'))
    else:
        return render_template('password.html')



def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__=='__main__':
    app.run()
