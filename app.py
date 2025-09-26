import os
import sqlite3
import uuid
from datetime import datetime, date
from decimal import Decimal
from flask import Flask, render_template, request, redirect, session, url_for, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'data.sqlite')

# Mail setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'enayabasmaji9@gmail.com'
app.config['MAIL_PASSWORD'] = 'yymu fxwr hnws yzxu'
mail = Mail(app)

REWARD_PER_VIEW = Decimal('0.001')
DAILY_LIMIT_PER_AD = 25
REFERRAL_COMMISSION_PCT = Decimal('5')  # 5%


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        balance REAL DEFAULT 0,
        referrer_id TEXT
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS ad_views (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        ad_type TEXT NOT NULL,
        view_date TEXT NOT NULL,
        count INTEGER DEFAULT 0,
        UNIQUE(user_id, ad_type, view_date)
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS withdrawals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL
    )''')
    db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


@app.before_request
def ensure_db():
    if not os.path.exists(DB_PATH):
        init_db()


@app.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    ref = request.args.get('ref')
    referrer = None
    if ref:
        referrer = ref
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            flash('Passwords do not match', 'error')
            return render_template('signup.html', referrer=referrer)
        existing = query_db('SELECT * FROM users WHERE email = ?', (email,), one=True)
        if existing:
            flash('Email already registered', 'error')
            return render_template('signup.html', referrer=referrer)
        user_id = str(uuid.uuid4())
        pw_hash = generate_password_hash(password)
        db = get_db()
        db.execute('INSERT INTO users (id, email, password_hash, balance, referrer_id) VALUES (?, ?, ?, ?, ?)',
                   (user_id, email, pw_hash, 0.0, ref))
        db.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', referrer=referrer)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = query_db('SELECT * FROM users WHERE email = ?', (email,), one=True)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash('Logged in', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


@app.route('/dashboard')
@login_required
def dashboard():
    user = query_db('SELECT * FROM users WHERE id = ?', (session['user_id'],), one=True)
    today = date.today().isoformat()
    ad1 = query_db('SELECT * FROM ad_views WHERE user_id = ? AND ad_type = ? AND view_date = ?', (session['user_id'], 'ad1', today), one=True)
    ad2 = query_db('SELECT * FROM ad_views WHERE user_id = ? AND ad_type = ? AND view_date = ?', (session['user_id'], 'ad2', today), one=True)
    counts = {
        'ad1': ad1['count'] if ad1 else 0,
        'ad2': ad2['count'] if ad2 else 0,
    }
    counts['total'] = counts['ad1'] + counts['ad2']
    return render_template('dashboard.html', user=user, counts=counts)


@app.route('/watch_ad', methods=['POST'])
@login_required
def watch_ad():
    ad_type = request.form['ad_type']
    if ad_type not in ('ad1', 'ad2'):
        flash('Invalid ad', 'error')
        return redirect(url_for('dashboard'))
    today = date.today().isoformat()
    db = get_db()
    cur = db.cursor()
    rec = query_db('SELECT * FROM ad_views WHERE user_id = ? AND ad_type = ? AND view_date = ?', (session['user_id'], ad_type, today), one=True)
    count = rec['count'] if rec else 0
    other = query_db('SELECT * FROM ad_views WHERE user_id = ? AND ad_type = ? AND view_date = ?', (session['user_id'], 'ad1' if ad_type=='ad2' else 'ad2', today), one=True)
    other_count = other['count'] if other else 0
    if count >= DAILY_LIMIT_PER_AD:
        flash('Daily limit for this ad reached', 'error')
        return redirect(url_for('dashboard'))
    if (count + other_count) >= DAILY_LIMIT_PER_AD * 2:
        flash('Total daily limit reached', 'error')
        return redirect(url_for('dashboard'))
    # redirect to the popup page which will load the ad script and call /confirm_view on successful load
    return redirect(url_for('open_ad') + f'?ad_type={ad_type}')


@app.route('/open_ad')
@login_required
def open_ad():
    ad_type = request.args.get('ad_type')
    if ad_type not in ('ad1', 'ad2'):
        flash('Invalid ad', 'error')
        return redirect(url_for('dashboard'))
    # Render a small page that loads the external ad script and calls /confirm_view when the script loads
    return render_template('open_ad.html', ad_type=ad_type)


@app.route('/confirm_view', methods=['POST'])
@login_required
def confirm_view():
    ad_type = request.form['ad_type']
    # This endpoint is called by the ad popup page after script loaded successfully
    today = date.today().isoformat()
    db = get_db()
    cur = db.cursor()
    # re-check limits to avoid bypass
    rec = query_db('SELECT * FROM ad_views WHERE user_id = ? AND ad_type = ? AND view_date = ?', (session['user_id'], ad_type, today), one=True)
    other = query_db('SELECT * FROM ad_views WHERE user_id = ? AND ad_type = ? AND view_date = ?', (session['user_id'], 'ad1' if ad_type=='ad2' else 'ad2', today), one=True)
    count = rec['count'] if rec else 0
    other_count = other['count'] if other else 0
    if count >= DAILY_LIMIT_PER_AD or (count + other_count) >= DAILY_LIMIT_PER_AD * 2:
        # limit reached; do not credit
        return ('', 400)
    if rec:
        cur.execute('UPDATE ad_views SET count = count + 1 WHERE id = ?', (rec['id'],))
    else:
        cur.execute('INSERT INTO ad_views (user_id, ad_type, view_date, count) VALUES (?, ?, ?, ?)', (session['user_id'], ad_type, today, 1))
    # add reward
    cur.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (float(REWARD_PER_VIEW), session['user_id']))
    db.commit()
    return ('', 204)


@app.route('/referrals')
@login_required
def referrals():
    user = query_db('SELECT * FROM users WHERE id = ?', (session['user_id'],), one=True)
    referral_link = request.host_url.rstrip('/') + url_for('signup') + '?ref=' + user['id']
    referred = query_db('SELECT COUNT(*) as c FROM users WHERE referrer_id = ?', (user['id'],), one=True)
    referred_count = referred['c'] if referred else 0
    return render_template('referrals.html', referral_link=referral_link, referred_count=referred_count, commission_pct=REFERRAL_COMMISSION_PCT)


@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    amount = Decimal(request.form['amount'])
    if amount < Decimal('0.5'):
        flash('Minimum withdrawal is $0.50', 'error')
        return redirect(url_for('dashboard'))
    user = query_db('SELECT * FROM users WHERE id = ?', (session['user_id'],), one=True)
    if Decimal(str(user['balance'])) < amount:
        flash('Insufficient balance', 'error')
        return redirect(url_for('dashboard'))
    db = get_db()
    cur = db.cursor()
    # deduct
    new_balance = Decimal(str(user['balance'])) - amount
    cur.execute('UPDATE users SET balance = ? WHERE id = ?', (float(new_balance), session['user_id']))
    cur.execute('INSERT INTO withdrawals (user_id, amount, created_at) VALUES (?, ?, ?)', (session['user_id'], float(amount), datetime.utcnow().isoformat()))
    # commission to referrer
    if user['referrer_id']:
        commission = (amount * (REFERRAL_COMMISSION_PCT / Decimal('100')))
        cur.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (float(commission), user['referrer_id']))
    db.commit()
    # send email
    msg = Message('Withdrawal Request', sender=app.config['MAIL_USERNAME'], recipients=[app.config['MAIL_USERNAME']])
    msg.body = f"User {user['email']} requested withdrawal of ${amount:.2f}"
    mail.send(msg)
    flash('Withdrawal requested. You will receive an email confirmation.', 'success')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)
