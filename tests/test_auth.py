import pytest
from flask import g, session
from centre.db import get_db

def test_register(client, app):
    assert 200 == client.get('/auth/register').status_code
    response = client.post(
        '/auth/register',
        data={'username': 'a', 'password': 'a'}
    )
    assert 'http://localhost/auth/login' == response.headers['Location']

    with app.app_context():
        assert get_db().execute(
            "SELECT * FROM user WHERE username = 'a'",
        ).fetchone() is not None

@pytest.mark.parametrize(('username', 'password', 'message'), (
    ('', '', b'Username is required.'),
    ('a', '', b'Password is required.'),
    ('test', 'test', b'already registered'),
))
def test_register_validate_input(client, username, password, message):
    response = client.post(
        '/auth/register',
        data={'username': username, 'password': password},
    )
    assert message in response.data

def test_login(client, auth):
    assert 200 == client.get('/auth/login').status_code
    response = auth.login()
    assert 'http://localhost/' == response.headers['Location']

    with client:
        client.get('/')
        assert 1 == session['user_id']
        assert 'test' == g.user['username']

@pytest.mark.parametrize(('username', 'password', 'message'), (
    ('a', 'test', b'Incorrect username.'),
    ('test', 'a', b'Incorrect password.'),
))
def test_login_validate_input(auth, username, password, message):
    response = auth.login(username, password)
    assert message in response.data

def test_logout(client, auth):
    auth.login()
    with client:
        auth.logout()
        assert 'user_id' not in session
