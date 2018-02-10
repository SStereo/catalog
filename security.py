from flask import request, redirect
from application import login_session
from functools import wraps


def login_required(func):

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if 'username' not in login_session:
            print("Required to login before heading to %s" % request.url)
            return redirect('/login')
        # TODO: return to the intendet page after login or redirect to original URL using request.referrer
        else:
            return func(*args, **kwargs)
    return decorated_view
