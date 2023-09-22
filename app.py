from flask import Flask, render_template, url_for, request, flash, g, redirect, session
import sqlite3
from datetime import date


import random
import string 
import hashlib 
import binascii




app_info = {'db_file' : './data/runners.db'}

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SomethingWhatNo1CanGuess!'

def get_db():
     
     if not hasattr(g, 'sqlite_db'):
          conn = sqlite3.connect(app_info['db_file'])
          conn.row_factory = sqlite3.Row
          g.sqlite_db = conn
     return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
     
     if hasattr(g, 'sqlite3_db'):
          g.sqlite_db.close()

    



class Record_select:

    def __init__(self, destination):
         self.destination = destination

    def __repr__(self):
          return '<Record_select {}>'.format(self.destination)

class World:
     
     def __init__(self, code, name, time, photo, name_pl, time_pl, photo_pl):
          self.code = code 
          self.name = name 
          self.time = time 
          self.photo = photo 
          self.name_pl = name_pl
          self.time_pl = time_pl
          self.photo_pl = photo_pl

     def __repr__(self):
          return '<Record {}>'.format(self.code)
 
     
class Records:
     
     def __init__(self):
          self.world = [] 
          self.desti = []
          self.popup = []
 

     def load_offer(self):
          self.world.append(World('100 m', 'Usain Bolt', '9.58', '100m.jpg', 'Marian Woronin', '10.00', '100m_pl.jpg'))
          self.world.append(World('1 500 m', 'Hicham El Guerrouj', '3:26.00', '1500m.jpg', 'Marcin Lewandowski', '3:30.42', '1500m_pl.png'))
          self.world.append(World('Półmaraton', 'Jacob Kiplimo', '57:31', '21.jpg', 'Krystian Zalewski', '1:01:32', '21_pl.jpg'))
          self.world.append(World('Maraton', 'Eliud Kipchoge', '2:01:09', '42.jpg', 'Henryk Szost', '2:07:39', '42_pl.jpg'))    
          self.desti.append(Record_select('Polski'))
          self.desti.append(Record_select('Świata'))
          self.popup.append('Polski')

     def get_by_code(self, code):
          for i in self.world:
               if i.code == code:
                    return i 


class UserPass:

     def __init__(self, user='', password=''):
          self.user = user 
          self.password = password 
          self.email = ''
          self.is_valid = False
          self.is_admin = False

     def hash_password(self): 
        """Hash a password for storing.""" 
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii') 
        pwdhash = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, 100000) 
        pwdhash = binascii.hexlify(pwdhash) 
        return (salt + pwdhash).decode('ascii')
     
     
     def verify_password(self, stored_password, provided_password): 
        """Verify a stored password against one provided by user""" 
        salt = stored_password[:64] 
        stored_password = stored_password[64:] 
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000) 
        pwdhash = binascii.hexlify(pwdhash).decode('ascii') 
        return pwdhash == stored_password
     

     def get_random_user_pasword(self): 
        random_user = ''.join(random.choice(string.ascii_lowercase)for i in range(3)) 
        self.user = random_user 
        
        password_characters = string.ascii_letters #+ string.digits + string.punctuation 
        random_password = ''.join(random.choice(password_characters)for i in range(3)) 
        self.password = random_password

     def login_user(self): 
        
        db = get_db() 
        sql_statement = 'select id, name, email, password, is_active, is_admin from users where name=?' 
        cur = db.execute(sql_statement, [self.user]) 
        user_record = cur.fetchone() 
        
        if user_record != None and self.verify_password(user_record['password'], self.password): 
             return user_record
        else: 
            self.user = None 
            self.password = None 
            return None
        
     
     def get_user_info(self): 
        db = get_db() 
        sql_statement = 'select name, email, is_active, is_admin from users where name=?' 
        cur = db.execute(sql_statement, [self.user]) 
        db_user = cur.fetchone()

        if db_user == None: 
            self.is_valid = False 
            self.is_admin = False 
            self.email = '' 
        elif db_user['is_active']!=1: 
            self.is_valid = False 
            self.is_admin = False 
            self.email = db_user['email'] 
        else: 
            self.is_valid = True 
            self.is_admin = db_user['is_admin']
            self.email = db_user['email']




@app.route('/init_app') 
def init_app():

    db = get_db() 
    sql_statement = 'select count(*) as cnt from users where is_active and is_admin;' 
    cur = db.execute(sql_statement) 
    active_admins = cur.fetchone()

    if active_admins!=None and active_admins['cnt']>0: 
        flash('Application is already set-up. Nothing to do') 
        return redirect(url_for('content'))
    

    user_pass = UserPass() 
    user_pass.get_random_user_pasword() 
    sql_statement = '''insert into users(name, email, password, is_active, is_admin) values(?,?,?,True, True);''' 
    db.execute(sql_statement, [user_pass.user, 'noone@nowhere.no', user_pass.hash_password()]) 
    db.commit() 
    flash('User {} with password {} has been created'.format(user_pass.user, user_pass.password)) 
    return redirect(url_for('content'))


@app.route('/login', methods=['GET','POST']) 
def login(): 
    login = UserPass(session.get('user'))
    login.get_user_info()
    
    if request.method == 'GET': 
        return render_template('login.html', active_menu='login', login=login) 
    else: 
        user_name = '' if 'user_name' not in request.form else request.form['user_name'] 
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass'] 
        
        login = UserPass(user_name, user_pass) 
        login_record = login.login_user() 
        
        if login_record != None: 
            session['user'] = user_name 
            flash('Logon succesfull, welcome {}'.format(user_name)) 
            return redirect(url_for('content')) 
        else: 
            flash('Logon failed, try again') 
            return render_template('login.html', active_menu='login', login=login)
        

@app.route('/logout') 
def logout(): 
    
    if 'user' in session: 
        session.pop('user', None) 
        flash('You are logged out') 
    return redirect(url_for('login'))


@app.route('/')
def content():
    login = UserPass(session.get('user'))
    login.get_user_info()
    return render_template('content.html', active_menu='home', login=login)


@app.route('/record', methods=['GET', 'POST'])
def record():
    login = UserPass(session.get('user'))
    login.get_user_info()
    
    offer = Records()
    offer.load_offer() 

    if request.method == 'GET':
        return render_template('record.html', active_menu='record', offer=offer, login=login)
    
    else:          
        distans = '100 m'
        if 'distans' in request.form:
            distans = request.form['distans']   
        
        records = 'Świata'
        if 'records' in request.form:
            records = request.form['records']   

        else:
            db = get_db()
            sql_command = 'insert into reserch2(distans, records, user) values(?, ?, ?)'
            db.execute(sql_command, [distans, records, 'admin'])
            db.commit()
            flash('To jest rekord {} '.format(records))

        distans_info = offer.get_by_code(distans)
        records_info = {}  # Inicjalizuj jako pusty słownik

        if records == 'Świata':
            if not login.is_valid:
                # Przekieruj użytkownika na stronę logowania
                return redirect(url_for('login')), flash('Aby zobaczyć rekord {}, zaloguj się lub załóż konto. '.format(records))
                          
            else:
                records_info = {
                    'code': distans_info.code,
                    'name': distans_info.name,
                    'time': distans_info.time,
                    'photo': distans_info.photo
                }
            db = get_db()
            sql_command = 'insert into reserch2(distans, records, user) values(?, ?, ?)'
            db.execute(sql_command, [distans, records, 'admin'])
            db.commit()
            flash('To jest rekord {} '.format(records))
            
        elif records == 'Polski':
            records_info = {
                'code': distans_info.code,
                'name_pl': distans_info.name_pl,
                'time_pl': distans_info.time_pl,
                'photo_pl': distans_info.photo_pl
            }
            db = get_db()
            sql_command = 'insert into reserch2(distans, records, user) values(?, ?, ?)'
            db.execute(sql_command, [distans, records, 'admin'])
            db.commit()
            flash('To jest rekord {} '.format(records))

        return render_template('exchange_results.html', active_menu='record', distans=distans, records=records, records_info=records_info, login=login)


@app.route('/history')
def history():
     login = UserPass(session.get('user'))
     login.get_user_info()
     if not login.is_valid:
        return redirect(url_for('login'))


     db= get_db()
     sql_command = 'select id, distans, records, date_run from reserch2;'
     cur = db.execute(sql_command)
     reserch2 = cur.fetchall()

     return render_template('history.html', active_menu='history', reserch2=reserch2, login=login)



@app.route('/about_us')
def about_us():
    login = UserPass(session.get('user'))
    login.get_user_info()
    return render_template('about_us.html', active_menu='about_us', login=login)


@app.route('/contact')
def contact():
    login = UserPass(session.get('user'))
    login.get_user_info()
    return render_template('contact.html', active_menu='contact', login=login)



@app.route('/delete_reserch/<int:reserch_id>')
def delete_reserch(reserch_id):
     login = UserPass(session.get('user'))
     login.get_user_info()
     if not login.is_valid:
        return redirect(url_for('login'))
     
     db = get_db()
     sql_statement = 'delete from reserch2 where id = ?;'
     db.execute(sql_statement, [reserch_id]) 
     db.commit() 

     return redirect(url_for('history'))


@app.route('/users')
def users():
     login = UserPass(session.get('user'))
     login.get_user_info()
     if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
     
     db = get_db() 
     sql_command = 'select id, name, email, is_admin, is_active from users;' 
     cur = db.execute(sql_command) 
     users = cur.fetchall() 
     
     return render_template('users.html', active_menu='users', users=users, login=login)


@app.route('/user_status_change/<action>/<user_name>')
def user_status_change(action, user_name):
     login = UserPass(session.get('user'))
     login.get_user_info()
     if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
    

     
     db = get_db() 

     if action == 'active': 
         db.execute("""update users set is_active = (is_active + 1) % 2 where name = ? and name <> ?""", 
                    [user_name, login.user]) 
         db.commit() 
     elif action == 'admin': 
         db.execute("""update users set is_admin = (is_admin + 1) % 2 where name = ? and name <> ?""", 
                    [user_name, login.user]) 
         db.commit() 
         
     return redirect(url_for('users'))
          
          




@app.route('/edit_user/<user_name>', methods=['GET', 'POST']) 
def edit_user(user_name): 
     login = UserPass(session.get('user'))
     login.get_user_info()
     if not login.is_valid or not login.is_admin:
        return redirect(url_for('login'))
     
     db = get_db() 
     cur = db.execute('select name, email from users where name = ?', [user_name]) 
     user = cur.fetchone() 
     message = None

     if user == None: 
        flash('No such user') 
        return redirect(url_for('users')) 
     
     if request.method == 'GET': 
        return render_template('edit_user.html', active_menu='users', user=user, login=login) 
     else: 
        new_email = '' if 'email' not in request.form else request.form["email"] 
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass'] 
        
        if new_email != user['email']: 
            sql_statement = "update users set email = ? where name = ?" 
            db.execute(sql_statement, [new_email, user_name]) 
            db.commit() 
            flash('Email was changed') 
            
        if new_password != '': 
            user_pass = UserPass(user_name, new_password) 
            sql_statement = "update users set password = ? where name = ?" 
            db.execute(sql_statement, [user_pass.hash_password(), user_name]) 
            db.commit() 
            flash('Password was changed') 
            
        return redirect(url_for('users'))
        





@app.route('/new_user', methods=['GET', 'POST']) 
def new_user():
     login = UserPass(session.get('user'))
     login.get_user_info()
     if login.is_valid or  login.is_admin:
        return redirect(url_for('login'))


     db = get_db()
     message = None 
     user = {}

     if request.method == 'GET':
          return render_template('new_user.html', active_menu='new_user', user=user, login=login)
     else:
        user['user_name'] = '' if not 'user_name' in request.form else request.form['user_name'] 
        user['email'] = '' if not 'email' in request.form else request.form['email'] 
        user['user_pass'] = '' if not 'user_pass' in request.form else request.form['user_pass']
        
        cursor = db.execute('select count(*) as cnt from users where name = ?', [user['user_name']]) 
        record = cursor.fetchone() 
        is_user_name_unique = (record['cnt'] == 0)

        cursor = db.execute('select count(*) as cnt from users where email = ?', [user['email']]) 
        record = cursor.fetchone() 
        is_user_email_unique = (record['cnt'] == 0) 

        if user['user_name'] == '': 
            message = 'Name cannot be empty' 
        elif user['email'] == '': 
            message = 'email cannot be empty' 
        elif user['user_pass'] == '': 
            message = 'Password cannot be empty' 
        elif not is_user_name_unique: 
            message = 'User with the name {} already exists'.format(user['user_name']) 
        elif not is_user_email_unique: 
            message = 'User with the email {} alresdy exists'.format(user['email']) 

        if not message: 
            user_pass = UserPass(user['user_name'], user['user_pass']) 
            password_hash = user_pass.hash_password() 
            sql_statement = '''insert into users(name, email, password, is_active, is_admin) values(?,?,?, True, False);''' 
            db.execute(sql_statement, [user['user_name'], user['email'], password_hash]) 
            db.commit() 
            flash('User {} created'.format(user['user_name'])) 
            return redirect(url_for('users')) 
        else: 
            flash('Correct error: {}'.format(message)) 
            return render_template('new_user.html', active_menu='new_user', user=user, login=login)



if __name__ == '__main__':
    app.run()