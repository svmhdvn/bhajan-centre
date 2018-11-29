import functools

from flask import (
    Blueprint, flash, g, redirect, render_template,
    request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from centre.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if 'POST' == request.method:
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        err = None

        if not username:
            err = 'Username is required.'
        elif not password:
            err = 'Password is required.'
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            err = 'User {} is already registered.'.format(username)

        if err is None:
            db.execute(
                'INSERT INTO user (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for('auth.login'))

        flash(err)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if 'POST' == request.method:
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        err = None
        user = db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            err = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            err = 'Incorrect password.'

        if err is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(err)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
