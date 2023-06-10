from flask import (
    Blueprint, render_template, request, url_for, redirect, flash, session, g
)

from werkzeug.security import generate_password_hash, check_password_hash

from .models import User
from todor import db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User(username, generate_password_hash(password))

        error = None

        user_name = User.query.filter_by(username=username).first()
        if user_name == None:
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('auth.login'))
        else:
            error = f"""El usuario {username} ya está registrado... Oh, vaya sorpresa. Parece que alguien más se adelantó
            y tomó ese nombre sin sentido que intentabas usar. Supongo que tendrás que conformarte con algo más aburrido
            y menos original. ¿Quién necesita nombres de usuario de todas formas? Sigue adelante, encuentra otro nombre
            y continúa con esta farsa."""

        flash(error)

    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        error = None
        # Validar datos
        user = User.query.filter_by(username=username).first()
        if user == None:
            error = 'Nombre de usuario incorrecto... ¿Sorprendido? Prueba de nuevo, aunque realmente no importa.'
        elif not check_password_hash(user.password, password):
            error = """Contraseña incorrecta... Parece que tus intentos de desbloquear el acceso han fracasado una vez 
                    más. ¿Te sorprende? Inténtalo de nuevo, si te apetece desperdiciar más  
                    tiempo en esta farsa. Pero no te hagas ilusiones, al final, la contraseña es solo un obstáculo 
                    trivial en este mundo de obligaciones insípidas. Sigue intentando, o simplemente ríndete. A nadie 
                    le importa realmente."""

        # Iniciar sesión
        if error is None:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('todo.index'))

        flash(error)
    return render_template('auth/login.html')


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = User.query.get_or_404(user_id)


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


import functools


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)

    return wrapped_view