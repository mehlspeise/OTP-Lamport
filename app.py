from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
from flask_bcrypt import bcrypt, generate_password_hash

from config import DEFAULT_HASH_ROUNDS

# pwd_hash = hashlib.md5(task_pwd.encode('utf-8')).hexdigest() #md5 hashing
# pwd_hash= hashlib.sha256(task_pwd.encode('utf-8')).hexdigest() #sha256 hashing
# pwd_hash = generate_password_hash(task_pwd,rounds=None) #bcrypt hashing


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False)
    pwd = db.Column(db.String(200), nullable=False)
    initial_index = db.Column(db.Integer, default=DEFAULT_HASH_ROUNDS)
    current_index = db.Column(db.Integer, default=DEFAULT_HASH_ROUNDS)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<Task %r>' % self.id


db.create_all()


def hash(text, n_loops):
    print("Hashing {} times".format(n_loops))
    for _ in range(n_loops):
        text = hashlib.md5(text.encode('utf-8')).hexdigest()
    return text


@app.route('/', methods=['POST', 'GET'])
def index():
    if request.method == 'POST':
        user = request.form.get('username', False)
        pwd = request.form.get('hashedPassword', False)
        new_account = Account(username=user, pwd=pwd)

        try:
            db.session.add(new_account)
            db.session.commit()
            return redirect('/')
        except:
            return 'There was an issue adding your task'

    else:
        tasks = Account.query.order_by(Account.date_created).all()
        return render_template('index.html', accounts=tasks, n_loops=DEFAULT_HASH_ROUNDS)


@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Account.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/')
    except:
        return 'There was a problem deleting that user'


@app.route('/current_index', methods=['GET'])
def current_index():
    username = request.args.get('username')
    account = Account.query.filter_by(username=username).first() #first...takes first elemet it finds with specified username, ignores the rest
    if account is None:
        print("WRONG USERNAME")
        return ""

    account.current_index -= 1 #indexwert um 1 reduzieren und persistieren
    db.session.add(account)
    db.session.commit()
    return str(account.current_index)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        # get data from login forms
        username = request.form.get('username', "")
        hashedpw = request.form.get('password', "")

        # get get account from db, to know hash rounds, and hashed pwd in db
        account = Account.query.filter_by(username=username).first()
        if account is None:
            print("WRONG USERNAME")
            return redirect('/login')

        current_index = int(account.current_index)
        initial_index = int(account.initial_index)

        # make the left over rounds to arrive at the fully hashed value in the db
        fully_hashed_pw = hash(hashedpw, initial_index - current_index)

        if fully_hashed_pw == account.pwd:
            print("SUCCESS", fully_hashed_pw, account.pwd, initial_index, current_index)
            return render_template("success.html")
        else:
            print("WRONG PASSWORD", fully_hashed_pw, account.pwd, initial_index, current_index)
            return render_template("denied.html")

    else:
        return render_template('login.html')


if __name__ == "__main__":
    app.run(debug=True)
