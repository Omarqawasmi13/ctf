import os
import time
import hmac
import hashlib
from datetime import datetime

from flask import Flask, render_template, redirect, url_for, request, flash, session, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, UniqueConstraint, event
from sqlalchemy.engine import Engine
from dotenv import load_dotenv
from flask_wtf.file import FileField, FileAllowed
from uuid import uuid4


# Load environment variables
load_dotenv()


def create_app():
    app = Flask(__name__)

    # Config
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')
    db_path = os.path.join(os.getcwd(), 'ctf.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20MB uploads
    app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

    # Flag hashing pepper (for HMAC)
    app.config['FLAG_SECRET'] = os.getenv('FLAG_SECRET', app.config['SECRET_KEY'])

    # Admin bootstrap settings
    app.config['ADMIN_EMAIL'] = os.getenv('ADMIN_EMAIL', '')
    app.config['ADMIN_PASSWORD'] = os.getenv('ADMIN_PASSWORD', '')
    app.config['ADMIN_TEAM'] = os.getenv('ADMIN_TEAM', 'Admin')

    return app


app = create_app()
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Enable WAL and set synchronous to NORMAL
@event.listens_for(Engine, 'connect')
def set_sqlite_pragma(dbapi_connection, connection_record):
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute('PRAGMA journal_mode=WAL;')
        cursor.execute('PRAGMA synchronous=NORMAL;')
        cursor.close()
    except Exception:
        # If not SQLite or fails silently, ignore
        pass


# Models
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    join_secret_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    users = db.relationship('User', backref='team', lazy=True, cascade='all, delete-orphan')
    solves = db.relationship('Solve', backref='team', lazy=True, cascade='all, delete-orphan')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)

    solves = db.relationship('Solve', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)


class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), unique=True, nullable=False)
    category = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False)
    points = db.Column(db.Integer, nullable=False)
    flag_hash = db.Column(db.String(64), nullable=False)
    visible = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    solves = db.relationship('Solve', backref='challenge', lazy=True, cascade='all, delete-orphan')
    attachment = db.relationship('ChallengeAttachment', backref='challenge', uselist=False, cascade='all, delete-orphan')


class Solve(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint('team_id', 'challenge_id', name='uq_team_challenge'),
    )


class ChallengeAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False, unique=True)
    stored_name = db.Column(db.String(255), nullable=False)
    orig_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


# Forms
class RegisterForm(FlaskForm):
    team_name = StringField('Team Name', validators=[DataRequired(), Length(min=2, max=80)])
    team_password = PasswordField('Team Password (create or join)', validators=[DataRequired(), Length(min=3, max=128)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class FlagSubmitForm(FlaskForm):
    flag = StringField('Flag', validators=[DataRequired(), Length(max=256)])
    submit = SubmitField('Submit')


class ChallengeForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=120)])
    category = StringField('Category', validators=[DataRequired(), Length(min=1, max=80)])
    description = TextAreaField('Description', validators=[DataRequired()])
    points = IntegerField('Points', validators=[DataRequired(), NumberRange(min=1, max=100000)])
    flag = StringField('Flag (set new to change)')
    visible = BooleanField('Visible')
    attachment = FileField('Attachment (optional)', validators=[FileAllowed(['zip','txt','pdf','png','jpg','jpeg','gif','tar','gz','bz2','xz'])])
    remove_attachment = BooleanField('Remove existing attachment')
    submit = SubmitField('Save')


# Helpers
def hmac_flag(flag: str) -> str:
    secret = app.config['FLAG_SECRET'].encode()
    digest = hmac.new(secret, flag.encode(), hashlib.sha256).hexdigest()
    return digest


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def ensure_upload_folder():
    folder = app.config['UPLOAD_FOLDER']
    os.makedirs(folder, exist_ok=True)
    return folder


def save_attachment(file_storage):
    if not file_storage:
        return None, None
    ensure_upload_folder()
    orig = secure_filename(file_storage.filename)
    if not orig:
        return None, None
    stored = f"{uuid4().hex}_{orig}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], stored)
    file_storage.save(path)
    return stored, orig


def delete_attachment_file(stored_name: str):
    try:
        if not stored_name:
            return
        path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)
        if os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/')
def index():
    total_challs = Challenge.query.filter_by(visible=True).count()
    total_teams = Team.query.count()
    total_solves = Solve.query.count()
    return render_template('index.html', total_challs=total_challs, total_teams=total_teams, total_solves=total_solves)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        # Email uniqueness
        if User.query.filter(User.email == form.email.data.strip().lower()).first():
            flash('Email already in use.', 'error')
            return render_template('register.html', form=form)

        tname = form.team_name.data.strip()
        tpass = form.team_password.data
        team = Team.query.filter_by(name=tname).first()
        if team:
            # Enforce max team size of 2
            member_count = User.query.filter_by(team_id=team.id).count()
            if member_count >= 2:
                flash('This team already has the maximum of 2 members.', 'error')
                return render_template('register.html', form=form)
            # Join existing team: verify team password
            if not check_password_hash(team.join_secret_hash, tpass):
                flash('Incorrect team password for existing team.', 'error')
                return render_template('register.html', form=form)
        else:
            # Create new team
            team = Team(name=tname, join_secret_hash=generate_password_hash(tpass))
            db.session.add(team)
            db.session.flush()

        user = User(email=form.email.data.strip().lower(), team_id=team.id)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/challenges', methods=['GET', 'POST'])
@login_required
def challenges():
    # Category list and filter
    categories = [r[0] for r in db.session.query(Challenge.category).filter_by(visible=True).distinct().order_by(Challenge.category.asc()).all()]
    active_cat = request.args.get('cat')

    q = Challenge.query.filter_by(visible=True)
    if active_cat:
        q = q.filter(Challenge.category == active_cat)
    challs = q.order_by(Challenge.category.asc(), Challenge.points.asc()).all()

    # Map: challenge_id -> solved bool for current team
    solved_ids = {s.challenge_id for s in Solve.query.filter_by(team_id=current_user.team_id).all()}

    # Solve counts per challenge
    solve_counts = dict(
        db.session.query(Solve.challenge_id, func.count(Solve.id))
        .join(Challenge, Solve.challenge_id == Challenge.id)
        .group_by(Solve.challenge_id)
        .all()
    )

    # Unsolved first within category, then by points
    challs.sort(key=lambda c: (c.category, (c.id in solved_ids), c.points))

    # Individual forms per challenge id
    forms = {c.id: FlagSubmitForm(prefix=f'chall-{c.id}') for c in challs}

    # Identify which challenge form was submitted (if any)
    submitted_cid = None
    if request.method == 'POST':
        # Prefer explicit hidden cid
        for key, val in request.form.items():
            if key.startswith('chall-') and key.endswith('-cid'):
                try:
                    submitted_cid = int(val)
                except Exception:
                    submitted_cid = None
                break
        # Fallback to submit button name (may be missing if Enter pressed)
        if submitted_cid is None:
            for key in request.form.keys():
                if key.startswith('chall-') and key.endswith('-submit'):
                    try:
                        submitted_cid = int(key.split('-')[1])
                    except Exception:
                        submitted_cid = None
                    break
        # Fallback to flag field name
        if submitted_cid is None:
            for key in request.form.keys():
                if key.startswith('chall-') and key.endswith('-flag'):
                    try:
                        submitted_cid = int(key.split('-')[1])
                    except Exception:
                        submitted_cid = None
                    break

    # Handle submission for the matched challenge only
    if submitted_cid is not None:
        c = next((x for x in challs if x.id == submitted_cid), None)
        if c is not None:
            form = forms[c.id]
            if form.validate_on_submit():
                # Cooldown
                last_ts = session.get('last_submit_ts', 0)
                now = time.time()
                if now - last_ts < 5:
                    flash('Please wait a few seconds before submitting again.', 'error')
                    return redirect(url_for('challenges', cat=active_cat) if active_cat else url_for('challenges'))

                if c.id in solved_ids:
                    flash('You already solved this challenge.', 'info')
                    session['last_submit_ts'] = now
                    return redirect(url_for('challenges', cat=active_cat) if active_cat else url_for('challenges'))

                submitted = form.flag.data.strip()
                if not submitted:
                    flash('Flag cannot be empty.', 'error')
                    session['last_submit_ts'] = now
                    return redirect(url_for('challenges', cat=active_cat) if active_cat else url_for('challenges'))

                if constant_time_equals(hmac_flag(submitted), c.flag_hash):
                    # Record solve if not exists (defensive with unique constraint)
                    try:
                        solve = Solve(user_id=current_user.id, team_id=current_user.team_id, challenge_id=c.id)
                        db.session.add(solve)
                        db.session.commit()
                        flash(f'Correct! +{c.points} points.', 'success')
                    except Exception:
                        db.session.rollback()
                        flash('Already solved or error creating solve.', 'error')
                    session['last_submit_ts'] = now
                    return redirect(url_for('challenges', cat=active_cat) if active_cat else url_for('challenges'))
                else:
                    flash('Incorrect flag.', 'error')
                    session['last_submit_ts'] = now
                    return redirect(url_for('challenges', cat=active_cat) if active_cat else url_for('challenges'))
            else:
                # Surface CSRF or validation errors
                if form.csrf_token.errors:
                    flash('Session expired or CSRF invalid. Please refresh and try again.', 'error')
                elif form.flag.errors:
                    flash('Please enter a flag.', 'error')
                else:
                    # Generic fallback
                    flash('Submission invalid. Please try again.', 'error')
        else:
            flash('Unknown challenge submission.', 'error')

    return render_template('challenges.html', challenges=challs, forms=forms, solved_ids=solved_ids, categories=categories, active_cat=active_cat, solve_counts=solve_counts)


class TeamSettingsForm(FlaskForm):
    name = StringField('Team Name', validators=[DataRequired(), Length(min=2, max=80)])
    current_secret = PasswordField('Current Team Password', validators=[DataRequired(), Length(min=3, max=128)])
    new_secret = PasswordField('New Team Password (optional)', validators=[Length(min=3, max=128)])
    submit = SubmitField('Save Changes')


@app.route('/team', methods=['GET', 'POST'])
@login_required
def team_page():
    team = current_user.team
    members = User.query.filter_by(team_id=team.id).order_by(User.created_at.asc()).all()
    form = TeamSettingsForm()
    if request.method == 'GET':
        form.name.data = team.name
    if form.validate_on_submit():
        # Verify current team password
        if not check_password_hash(team.join_secret_hash, form.current_secret.data):
            flash('Incorrect current team password.', 'error')
            return render_template('team.html', form=form, members=members, team=team)

        # Rename team if changed
        new_name = form.name.data.strip()
        if new_name != team.name:
            if Team.query.filter(Team.name == new_name, Team.id != team.id).first():
                flash('Another team already uses that name.', 'error')
                return render_template('team.html', form=form, members=members, team=team)
            team.name = new_name

        # Change team password if provided
        if form.new_secret.data and form.new_secret.data.strip():
            team.join_secret_hash = generate_password_hash(form.new_secret.data.strip())

        db.session.commit()
        flash('Team settings updated.', 'success')
        return redirect(url_for('team_page'))

    return render_template('team.html', form=form, members=members, team=team)


def admin_required():
    if not (current_user.is_authenticated and current_user.is_admin):
        abort(403)


@app.route('/admin')
@login_required
def admin_panel():
    admin_required()
    challs = Challenge.query.order_by(Challenge.visible.desc(), Challenge.points.asc()).all()
    return render_template('admin.html', challenges=challs)


@app.route('/admin/challenges/new', methods=['GET', 'POST'])
@login_required
def admin_new_challenge():
    admin_required()
    form = ChallengeForm()
    if form.validate_on_submit():
        if Challenge.query.filter_by(title=form.title.data.strip()).first():
            flash('Challenge title must be unique.', 'error')
            return render_template('challenge_form.html', form=form, action='New')
        flag_val = form.flag.data.strip() if form.flag.data else ''
        if not flag_val:
            flash('Flag is required.', 'error')
            return render_template('challenge_form.html', form=form, action='New')
        chall = Challenge(
            title=form.title.data.strip(),
            category=form.category.data.strip(),
            description=form.description.data,
            points=form.points.data,
            flag_hash=hmac_flag(flag_val),
            visible=form.visible.data or False,
        )
        db.session.add(chall)
        db.session.commit()
        # Save attachment if provided
        if form.attachment.data:
            stored, orig = save_attachment(form.attachment.data)
            if stored:
                att = ChallengeAttachment(challenge_id=chall.id, stored_name=stored, orig_name=orig)
                db.session.add(att)
                db.session.commit()
        flash('Challenge created.', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('challenge_form.html', form=form, action='New')


@app.route('/admin/challenges/<int:cid>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_challenge(cid):
    admin_required()
    chall = Challenge.query.get_or_404(cid)
    form = ChallengeForm(obj=chall)
    # Do not prefill flag
    form.flag.data = ''
    if form.validate_on_submit():
        # If title changed ensure uniqueness
        new_title = form.title.data.strip()
        existing = Challenge.query.filter(Challenge.title == new_title, Challenge.id != chall.id).first()
        if existing:
            flash('Another challenge already has that title.', 'error')
            return render_template('challenge_form.html', form=form, action='Edit')

        chall.title = new_title
        chall.category = form.category.data.strip()
        chall.description = form.description.data
        chall.points = form.points.data
        chall.visible = form.visible.data or False
        if form.flag.data and form.flag.data.strip():
            chall.flag_hash = hmac_flag(form.flag.data.strip())
        # Handle attachment removal or replacement
        existing = chall.attachment
        if form.remove_attachment.data and existing:
            delete_attachment_file(existing.stored_name)
            db.session.delete(existing)
        if form.attachment.data:
            # Replace existing if any
            if existing:
                delete_attachment_file(existing.stored_name)
                db.session.delete(existing)
                db.session.flush()
            stored, orig = save_attachment(form.attachment.data)
            if stored:
                att = ChallengeAttachment(challenge_id=chall.id, stored_name=stored, orig_name=orig)
                db.session.add(att)
        db.session.commit()
        flash('Challenge updated.', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('challenge_form.html', form=form, action='Edit')


@app.route('/admin/challenges/<int:cid>/toggle', methods=['POST'])
@login_required
def admin_toggle_challenge(cid):
    admin_required()
    chall = Challenge.query.get_or_404(cid)
    chall.visible = not chall.visible
    db.session.commit()
    flash('Visibility toggled.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/challenges/<int:cid>/delete', methods=['POST'])
@login_required
def admin_delete_challenge(cid):
    admin_required()
    chall = Challenge.query.get_or_404(cid)
    # Delete attachment file if exists
    if chall.attachment:
        delete_attachment_file(chall.attachment.stored_name)
    db.session.delete(chall)
    db.session.commit()
    flash('Challenge deleted.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/download/<int:cid>')
@login_required
def download_attachment(cid):
    chall = Challenge.query.get_or_404(cid)
    # Only allow if visible or admin
    if not chall.visible and not current_user.is_admin:
        abort(403)
    att = chall.attachment
    if not att:
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], att.stored_name, as_attachment=True, download_name=att.orig_name)


@app.route('/scoreboard')
def scoreboard():
    # Aggregate total points per team by summing solved challenge points
    subq = (
        db.session.query(
            Solve.team_id.label('team_id'),
            func.coalesce(func.sum(Challenge.points), 0).label('score'),
            func.max(Solve.timestamp).label('last_solve')
        )
        .join(Challenge, Solve.challenge_id == Challenge.id)
        .group_by(Solve.team_id)
        .subquery()
    )

    rows = (
        db.session.query(
            Team.name.label('team_name'),
            func.coalesce(subq.c.score, 0).label('score'),
            func.coalesce(subq.c.last_solve, datetime(1970, 1, 1)).label('last_solve')
        )
        .outerjoin(subq, subq.c.team_id == Team.id)
        .order_by(func.coalesce(subq.c.score, 0).desc(), func.coalesce(subq.c.last_solve, datetime(1970, 1, 1)).asc())
        .all()
    )

    return render_template('scoreboard.html', rows=rows)


# CLI commands
@app.cli.command('initdb')
def initdb_cmd():
    """Initialize the database."""
    db.create_all()
    print('Initialized the database.')


@app.cli.command('bootstrap')
def bootstrap_cmd():
    """Create default admin user from environment variables."""
    admin_email = app.config['ADMIN_EMAIL']
    admin_password = app.config['ADMIN_PASSWORD']
    admin_team = app.config['ADMIN_TEAM']
    if not admin_email or not admin_password:
        print('ADMIN_EMAIL and ADMIN_PASSWORD must be set in environment or .env')
        return

    # Ensure admin team exists
    team = Team.query.filter_by(name=admin_team).first()
    if not team:
        team = Team(name=admin_team, join_secret_hash=generate_password_hash(admin_password))
        db.session.add(team)
        db.session.flush()

    existing = User.query.filter_by(email=admin_email.strip().lower()).first()
    if existing:
        if not existing.is_admin:
            existing.is_admin = True
            if not existing.team_id:
                existing.team_id = team.id
            db.session.commit()
            print('Upgraded existing user to admin.')
        else:
            print('Admin user already exists.')
        return

    user = User(email=admin_email.strip().lower(), is_admin=True, team_id=team.id)
    user.set_password(admin_password)
    db.session.add(user)
    db.session.commit()
    print('Admin user created.')


if __name__ == '__main__':
    app.run(debug=True)
