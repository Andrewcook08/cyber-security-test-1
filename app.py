# Imports the Flask library and some other helper libraries.
from dataclasses import dataclass
import logging
from typing import Dict, List, Optional

from flask import Flask, redirect, request, render_template, session
import os
import secrets
import bcrypt
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from markupsafe import escape
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initializes the Flask web server.
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_urlsafe(64))
csrf = CSRFProtect(app)

limiter = Limiter(
      app=app,
      key_func=get_remote_address,  # IP Address
      default_limits=["200 per day", "50 per hour"],  # Global limits
      storage_uri="memory://",  # Use in-memory storage
  )

# In order to rete limit per user not sitewide
def get_user_or_ip():
    """Rate limit by username if logged in, otherwise by IP"""
    username = session.get('username')
    if username:
        return f"user:{username}"
    return get_remote_address()

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("error.html", error=f"Too many requests. Please try again in {e.description}"), 429

'''
This code sets up the data structures which are used to store all of the information used by the app.
'''
@dataclass
class User:
    username: str
    password_hash: str
    balance: int
    is_admin: bool

@dataclass
class Product:
    product_id: int
    name: str
    description: str
    price: int
    image_url: str

@dataclass
class Purchase:
    user: User
    product: Product
    quantity: int

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# The user database is a dictionary where the keys are usernames and the values are User structs.
user_database: Dict[str, User] = {
    'admin': User(username='admin', password_hash=hash_password('admin'), balance=1000, is_admin=True),
    'test': User(username='test', password_hash=hash_password('test'), balance=100, is_admin=False),
}

@limiter.request_filter
def exempt_admins():
    username = session.get('username')
    if username and user_database.get(username):
        user = user_database.get(username)
        if user.is_admin:
            return True
    return False

# The product database is a pre-populated list of every available product.
product_database: List[Product] = [
    Product(product_id=0, name='Toaster', description='It does everything! Well, it toasts. Just that, really.', price=23, image_url='toaster.jpg'),
    Product(product_id=1, name='Stapler', description='Excuse me, I believe we have what will soon be your favorite stapler!', price=12, image_url='stapler.jpg'),
    Product(product_id=2, name='One Sock', description='Have you ever lost one sock, but you can\'t replace it because they\'re only sold in pairs? Well look no further!', price=2, image_url='sock.jpg'),
    Product(product_id=3, name='Laptop', description='A perfect gift for your friend who doesn\'t have enough screens in their life.', price=800, image_url='laptop.jpg'),
    Product(product_id=4, name='Worm on a String', description='You will never find a closer confidant, a more dutiful servant, or a more loyal friend than this worm on a string.', price=1, image_url='worm_on_string.jpg'),
    Product(product_id=5, name='Grand Piano', description='At $170, this piano is a steal! Seriously, at that price it must be stolen right? Or haunted? What\'s the catch?', price=170, image_url='piano.jpg'),
    Product(product_id=6, name='Oud', description='It\'s like a guitar, except you now get confused looks when you bring it to jam night.', price=65, image_url='oud.jpg'),
    Product(product_id=7, name='Sewall Hall', description='Yep, we\'re selling the entirety of Sewall hall! Students not included. No refunds.', price=1000000, image_url='sewall_hall.jpg'),
]

# The purchase database starts empty, but will get filled as purchases are made
purchase_database: List[Purchase] = []

'''
These routes handle the main user-facing pages, including viewing products and purchasing them.
'''
@app.route("/", methods=["GET"])
def index():
    '''Displays the home page of the website.'''

    # If the user is not logged in, redirect them to the login page.
    username = get_current_user()
    if not username:
        return redirect("/login")

    user = user_database.get(username)
    if not user:
        return redirect("/login")
    balance = user.balance
    products = product_database

    return render_template("index.html", username=username, balance=balance, products=products)

@app.route("/product/<int:product_id>", methods=["GET"])
def product(product_id: int):
    '''Displays the details of a specific product.'''

    # If the user is not logged in, redirect them to the login page.
    username = get_current_user()
    if not username:
        return redirect("/login")

    user = user_database.get(username)
    product = product_database[product_id]

    return render_template("product.html", product=product, username=username, admin=user.is_admin)

@app.route("/purchase", methods=["POST"])
@limiter.limit("10 per minute", key_func=get_user_or_ip)
def purchase():
    '''Purchases a product.'''

    # If the user is not logged in, redirect them to the login page.
    username = get_current_user()
    if not username:
        return redirect("/login")

    product_id = request.form.get("product_id", type=int)
    quantity = request.form.get("quantity", type=int)
    # Move price determination to server side.

    # Ensure product_id is valid
    if product_id is None or product_id >= len(product_database) or product_id < 0:
        return render_template("error.html", error="Invalid product ID.")

    # get the actual product and set the price
    actual_product = product_database[product_id]
    price = actual_product.price

    if quantity is None or quantity <= 0 or quantity > 100:
        return render_template("error.html", error="Invalid quantity. If you tried to order more than 100 products at once, please call to place your order.")

    new_balance = user_database[username].balance - (price * quantity)

    if new_balance < 0:
        return render_template("error.html", error="Cannot make purchase due to insufficient funds")
    else:
        logging.info(f"New purchase: {username} bought {quantity}x {product_id}")
        user_database[username].balance = new_balance

    purchase_record = Purchase(
        user=user_database.get(username),
        product=product_database[product_id],
        quantity=quantity
    )
    purchase_database.append(purchase_record)
    return render_template("purchase_success.html", username=username, purchase=purchase_record)

'''
These routes are only used by administrators.
'''

def admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        username = get_current_user()
        if not username:
            return redirect("/login")

        user = user_database.get(username)
        if not user or not user.is_admin:
            return render_template("error.html", error="You are not an administrator.")

        return function(*args, **kwargs)
    return decorated_function

@app.route("/admin", methods=["GET"])
@admin_required
def admin_dashboard():
    '''Allows admins to view recent purchases.'''

    # Gets the 10 most recent purchases
    recent_purchases = purchase_database[-10:]
    return render_template("admin.html", purchases=recent_purchases)

@app.route("/update_product", methods=["POST"])
@admin_required
def update_product():
    '''Allows admins to change the product description.'''

    product_id = request.form.get("product_id", type=int)
    new_description = request.form.get("description")

    if product_id is None or product_id >= len(product_database) or product_id < 0:
        return render_template("error.html", error="Invalid product ID.")

    if new_description is None:
        return render_template("error.html", error="Description is empty.")

    # XSS prevention
    product_database[product_id].description = escape(new_description)
    return redirect(f"/product/{product_id}")

'''
These routes handle logging in, creating accounts, and determining who is currently logged in.
'''
@app.route("/login", methods=["GET"])
def login_get():
    '''Return the login page of the website.'''

    return render_template("login.html")

@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute", key_func=get_user_or_ip)
def login_post():
    '''Logs the user in, if they supply the correct password.'''

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return render_template("error.html", error="Username and password are both required")

    user = user_database.get(username)
    if user is None:
        return render_template("error.html", error="User does not exist")

    if verify_password(password, user.password_hash):
        session['username'] = username
        session['csrf_token'] = secrets.token_urlsafe(32)
        return redirect("/")

    return render_template("error.html", error="Incorrect password")

@app.route("/create_account", methods=["GET"])
def create_account_get():
    '''Return the create_account page of the website.'''

    return render_template("create_account.html")

@app.route("/create_account", methods=["POST"])
@limiter.limit("10 per minute", key_func=get_user_or_ip)
def create_account_post():
    '''Creates a new account.'''

    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return render_template("error.html", error="Username and password are both required")

    if username in user_database:
        return render_template("error.html", error="A user with that username already exists")

    user_database[username] = User(
        username=username,
        password_hash=hash_password(password),
        balance=100,
        is_admin=False
    )

    # Log in as the newly created user.
    session['username'] = username
    return redirect("/")

@app.route("/logout", methods=["GET"])
def logout():
    '''Logs the user out.'''
    session.clear()
    return redirect("/login")

def get_current_user() -> Optional[str]:
    '''Return the current logged-in user if they exist, otherwise return None.'''
    return session.get('username')

# Run the app
app.run(debug=True, port=8000)