def dashboard():
def watch_ad():
def open_ad():
def confirm_view():
def referrals():
def withdraw():
import os
import uuid
from datetime import date, datetime
from decimal import Decimal
from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID

# Configuration from environment
DATABASE_URL = os.environ.get('DATABASE_URL')  # e.g., postgres://... (Supabase)
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
FLASK_SECRET = os.environ.get('FLASK_SECRET', 'dev-secret')

app = Flask(__name__)
app.secret_key = FLASK_SECRET

# Database config
if DATABASE_URL:
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Mail setup
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
mail = Mail(app)

REWARD_PER_VIEW = Decimal('0.001')
DAILY_LIMIT_PER_AD = 25
REFERRAL_COMMISSION_PCT = Decimal('5')  # 5%


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    balance = db.Column(db.Numeric(18, 8), default=0)
    referrer_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)


class AdView(db.Model):
    __tablename__ = 'ad_views'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    ad_type = db.Column(db.String(10), nullable=False)
    view_date = db.Column(db.String(10), nullable=False)
    count = db.Column(db.Integer, default=0, nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'ad_type', 'view_date', name='_user_ad_date_uc'),)


class Withdrawal(db.Model):
    __tablename__ = 'withdrawals'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Numeric(18, 8), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@app.before_first_request
def create_tables():
    db.create_all()


@app.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    ref = request.args.get('ref')
    referrer = ref if ref else None
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            flash('Passwords do not match', 'error')
            return render_template('signup.html', referrer=referrer)
        existing = User.query.filter_by(email=email).first()
        if existing:
            flash('Email already registered', 'error')
            return render_template('signup.html', referrer=referrer)
        user_id = str(uuid.uuid4())
        pw_hash = generate_password_hash(password)
        u = User(id=user_id, email=email, password_hash=pw_hash, balance=0, referrer_id=ref)
        db.session.add(u)
        db.session.commit()
        flash('Account created. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', referrer=referrer)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
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
    user = User.query.get(session['user_id'])
    today = date.today().isoformat()
    ad1 = AdView.query.filter_by(user_id=session['user_id'], ad_type='ad1', view_date=today).first()
    ad2 = AdView.query.filter_by(user_id=session['user_id'], ad_type='ad2', view_date=today).first()
    counts = {
        'ad1': ad1.count if ad1 else 0,
        'ad2': ad2.count if ad2 else 0,
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
    rec = AdView.query.filter_by(user_id=session['user_id'], ad_type=ad_type, view_date=today).first()
    count = rec.count if rec else 0
    other = AdView.query.filter_by(user_id=session['user_id'], ad_type='ad1' if ad_type == 'ad2' else 'ad2', view_date=today).first()
    other_count = other.count if other else 0
    if count >= DAILY_LIMIT_PER_AD:
        flash('Daily limit for this ad reached', 'error')
        return redirect(url_for('dashboard'))
    if (count + other_count) >= DAILY_LIMIT_PER_AD * 2:
        flash('Total daily limit reached', 'error')
        return redirect(url_for('dashboard'))
    return redirect(url_for('open_ad') + f'?ad_type={ad_type}')


@app.route('/open_ad')
@login_required
def open_ad():
    ad_type = request.args.get('ad_type')
    if ad_type not in ('ad1', 'ad2'):
        flash('Invalid ad', 'error')
        return redirect(url_for('dashboard'))
    return render_template('open_ad.html', ad_type=ad_type)


@app.route('/confirm_view', methods=['POST'])
@login_required
def confirm_view():
    ad_type = request.form['ad_type']
    today = date.today().isoformat()
    rec = AdView.query.filter_by(user_id=session['user_id'], ad_type=ad_type, view_date=today).first()
    other = AdView.query.filter_by(user_id=session['user_id'], ad_type='ad1' if ad_type == 'ad2' else 'ad2', view_date=today).first()
    count = rec.count if rec else 0
    other_count = other.count if other else 0
    if count >= DAILY_LIMIT_PER_AD or (count + other_count) >= DAILY_LIMIT_PER_AD * 2:
        return ('', 400)
    if rec:
        rec.count += 1
    else:
        rec = AdView(user_id=session['user_id'], ad_type=ad_type, view_date=today, count=1)
        db.session.add(rec)
    user = User.query.get(session['user_id'])
    user.balance = Decimal(user.balance) + REWARD_PER_VIEW
    db.session.commit()
    return ('', 204)


@app.route('/referrals')
@login_required
def referrals():
    user = User.query.get(session['user_id'])
    referral_link = request.host_url.rstrip('/') + url_for('signup') + '?ref=' + user.id
    referred_count = User.query.filter_by(referrer_id=user.id).count()
    return render_template('referrals.html', referral_link=referral_link, referred_count=referred_count, commission_pct=REFERRAL_COMMISSION_PCT)


@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    try:
        amount = Decimal(request.form['amount'])
    except Exception:
        flash('Invalid amount', 'error')
        return redirect(url_for('dashboard'))
    if amount < Decimal('0.5'):
        flash('Minimum withdrawal is $0.50', 'error')
        return redirect(url_for('dashboard'))
    user = User.query.get(session['user_id'])
    if Decimal(user.balance) < amount:
        flash('Insufficient balance', 'error')
        return redirect(url_for('dashboard'))
    # deduct
    user.balance = Decimal(user.balance) - amount
    w = Withdrawal(user_id=user.id, amount=amount)
    db.session.add(w)
    # commission to referrer
    if user.referrer_id:
        commission = (amount * (REFERRAL_COMMISSION_PCT / Decimal('100')))
        ref = User.query.get(user.referrer_id)
        if ref:
            ref.balance = Decimal(ref.balance) + commission
    db.session.commit()
    # send email to site owner
    if MAIL_USERNAME:
        msg = Message('Withdrawal Request', sender=MAIL_USERNAME, recipients=[MAIL_USERNAME])
        msg.body = f"User {user.email} requested withdrawal of ${amount:.2f}"
        try:
            mail.send(msg)
        except Exception as e:
            app.logger.error('Mail send failed: %s', e)
    flash('Withdrawal requested. You will receive an email confirmation.', 'success')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)
