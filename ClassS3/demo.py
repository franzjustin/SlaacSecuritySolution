import flask, flask.views
import os
import functools
import threading
import Sniff
import time
from flask import Markup
import pcapy
from pcapy import findalldevs
from gevent import monkey
monkey.patch_all(thread=False)
import time
from threading import Thread
from flask import Flask, render_template, session, request
from flask.ext.socketio import SocketIO, emit, join_room, leave_room, \
    close_room, disconnect


APP_ROOT = os.path.dirname(os.getcwd())
APP_STATIC = os.path.join(APP_ROOT, 'Logs')
APP_ACC = os.path.join(APP_ROOT, 'Database')
l = Sniff.Forever_Loop()  #the python file class with the function of forever loop / to use as a thread
global running
global learning
global manual
manual = False
learning = False
running = False
app = flask.Flask(__name__)
socketThread = None
app.secret_key = "bacon"
socketio = SocketIO(app)
#users = {'admin': 'admin'}


def background_thread():
    """Example of how to send server generated events to clients."""
    count = 0
    while True:
        time.sleep(3)
        if File_Existence('../Database/Notification') is True:
            try:
                notifcation_database = open('../Database/Notification','r')
                #print "ASsas"
                templine = notifcation_database.readline().split(' ',3 )
                #print templine
                alert_line = templine[3].split(' ')
                if str(alert_line[0]) == "SA001":
                    alert_line[0] = "Last Hop Router Attack"
                elif str(alert_line[0]) == "SA002":
                    alert_line[0] = "NA Spoofing"
                elif str(alert_line[0]) == "SA003":
                    alert_line[0] = "DoS in DAD"
                count += 1
                socketio.emit('my response',
                              {'data': alert_line[0] + " " + alert_line[1] , 'count': count},
                              namespace='/test')
                notifcation_database.close()
                something = open("../Database/Notification", "w")
                something.write(" ")
                something.close()
            except:
                pass

def getfilenames():
    filename_list = []
    filename_list.append("Default")
    for file in os.listdir("../Logs"):
        if file.endswith(".s3"):
            file_temp = file.split('-')
            filename = file_temp[1].split('.')
            filename = filename[0][:4] + " / " + filename[0][4:6] + " / "+ filename[0][-2:]
            filename_list.append(filename)
    return filename_list


def filter( running, attack_list, filename_list, logfile, attack, date):
    if attack == "Defau":
        #print "Pumasok"
        if File_Existence(os.path.join(APP_STATIC, logfile)) is True:
            with open(os.path.join(APP_STATIC, logfile)) as f:
                stat = str(f.read())
                flask.flash(stat)
                return  flask.render_template('status.html', running=running , filename_list = filename_list, attack_list = attack_list)
        else:
            flask.flash("everything is fine :)")
            return  flask.render_template('status.html', running=running, filename_list = filename_list, attack_list = attack_list)

    elif File_Existence(os.path.join(APP_STATIC, logfile)) is True:
        with open(os.path.join(APP_STATIC, logfile)) as f:
            stat = str(f.read())
            entry = stat.split('\n')
            attack_message = []
            x = 0
            for log_entry in entry:
                split_entry = log_entry.split(' ')
                if len(split_entry) > 1:
                    if str(split_entry[2]) == str(attack):
                        flask.flash(log_entry)
                        attack_message.append(log_entry)
                x = x + 1
            return  flask.render_template('status.html', running=running , filename_list = filename_list, attack_list = attack_list)
    else:
        flask.flash("everything is fine :)")
        return  flask.render_template('status.html', running=running, filename_list = filename_list, attack_list = attack_list)


def printlogs(running, attack_list, filename_list, logfile):

    if File_Existence(os.path.join(APP_STATIC, logfile)) is True:
        with open(os.path.join(APP_STATIC, logfile)) as f:
            stat = str(f.read())
            lol = stat.split('\n')
            #number is the start of index for last 5 files
            y = len(lol) - 1
            count = 5
            if y < 5:
                count = y+1
            count = range(int(count))
            for x in count:
                flask.flash(lol[y])
                y=y-1
            return  flask.render_template('status.html', running=running , filename_list = filename_list, attack_list = attack_list)
    else:
        flask.flash("No Attack Detected as of Today")
        return  flask.render_template('status.html', running=running, filename_list = filename_list, attack_list = attack_list)

def parseLogs(rawLogs):
    parse = []
    #2015-02-04 21:59:38.787691 SA002 Attacker:;Victim:88:f0:77:a1:d8:8d
    for x in rawLogs:
           try:
            temp = ''
            split = x.split(' ')
            temp = "Date: " +split[0] + " " + "Time: "+ split[1] +" "
            if split[2] == "SA001":
                temp = temp + "Attack: Last Hop Router Advertisement Attack " + split[3]
            elif split[2] == "SA002":
                temp = temp + "Attack: Neighbor Advertisement Spoofing " + split[3]
            elif split[2] == "SA003":
                temp = temp + "Attack: Denial of Service on Duplicate Address Detection " + split[3]
            parse.append(temp)
           except:
            pass
    return parse


def printIndex(running, logfile):
    allLogs = [f for f in os.listdir("../Logs") if os.path.isfile(os.path.join("../Logs",f))]
    listLastHop = []
    listNeigAdver = []
    listDoSonDaD = []
    thisLen = len(allLogs) - 1
    for xx in allLogs:
        with open(os.path.join(APP_STATIC, allLogs[thisLen])) as f:
                temp = str(f.read())
                arrayTemp = temp.split('\n')
                for x in arrayTemp:
                    splitF = x.split(' ')
                    try:
                        if splitF[2] == "SA001" and len(listLastHop) != 5:
                            listLastHop.append(x)
                        if splitF[2] == "SA002" and len(listNeigAdver) != 5:
                            listNeigAdver.append(x)
                        if splitF[2] == "SA003" and len(listDoSonDaD) != 5:
                            listDoSonDaD.append(x)
                    except:
                        pass
        thisLen = thisLen - 1

    listLastHop = parseLogs(listLastHop)
    listNeigAdver = parseLogs(listNeigAdver)
    listDoSonDaD = parseLogs(listDoSonDaD)

    if File_Existence(os.path.join(APP_STATIC, logfile)) is True:
        with open(os.path.join(APP_STATIC, logfile)) as f:
            stat = str(f.read())
            lol = parseLogs(stat.split('\n'))
            y = len(lol) - 1
            count = 5
            if y < 5:
                count = y+1
            count = range(int(count))
            for x in count:
                flask.flash(lol[y])
                y=y-1
        return flask.render_template('dashboard.html', running=running, listLastHop=listLastHop, listNeigAdver=listNeigAdver,listDoSonDaD=listDoSonDaD)
    else:
        flask.flash("No Attack Detected as of Today")
        return flask.render_template('dashboard.html', running=running, listLastHop=listLastHop, listNeigAdver=listNeigAdver,listDoSonDaD=listDoSonDaD)



@socketio.on('my event', namespace='/test')
def test_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my response',
         {'data': message['data'], 'count': session['receive_count']})


@socketio.on('my broadcast event', namespace='/test')
def test_broadcast_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my response',
         {'data': message['data'], 'count': session['receive_count']},
         broadcast=True)


@socketio.on('join', namespace='/test')
def join(message):
    join_room(message['room'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my response',
         {'data': 'In rooms: ' + ', '.join(request.namespace.rooms),
          'count': session['receive_count']})


@socketio.on('leave', namespace='/test')
def leave(message):
    leave_room(message['room'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my response',
         {'data': 'In rooms: ' + ', '.join(request.namespace.rooms),
          'count': session['receive_count']})


@socketio.on('close room', namespace='/test')
def close(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my response', {'data': 'Room ' + message['room'] + ' is closing.',
                         'count': session['receive_count']},
         room=message['room'])
    close_room(message['room'])


@socketio.on('my room event', namespace='/test')
def send_room_message(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my response',
         {'data': message['data'], 'count': session['receive_count']},
         room=message['room'])


@socketio.on('disconnect request', namespace='/test')
def disconnect_request():
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my response',
         {'data': 'Disconnected!', 'count': session['receive_count']})
    disconnect()


@socketio.on('connect', namespace='/test')
def test_connect():
    #emit('my response', {'data': 'Connected', 'count': 0})
    pass

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    #print('Client disconnected')
    pass

def File_Existence(filepath):
    try:
        f = open(filepath)
    except IOError, OSError:  # Note OSError is for later versions of python
        return False

    return True

class Main(flask.views.MethodView):  # the main page
    def get(self):  # when open, this is the first page it gets
        if File_Existence(os.path.join(APP_ACC, 'Accounts.txt')) is False:
            print "There is No Account Database found"
            return  flask.render_template('signUp.html',running=running)+flask.render_template('popup.html')
        else:
            print "There is an Account Database"
            return  flask.render_template('index.html',running=running)

    def post(self):
        if 'logout' in flask.request.form:
            flask.session.pop('username', None)
            global running
            running = False
            l.stop()
            return flask.redirect(flask.url_for('index'))
        required = ['username', 'password']
        for r in required:
            if r not in flask.request.form:
                flask.flash("Error {0} is required.".format(r))
                return flask.redirect(flask.url_for('index'))
            username = flask.request.form['username']
            password = flask.request.form['password']

            usersDictionary = {}
            f = open('../Database/Accounts.txt', 'r')
            users = f.read()
            f.close()
            users = users.split()
            #users = users.split('\n')

            usersUsername = []
            usersPassword = []
            i = 0
            for user in users:
                if i == 0:
                    usersUsername.append(user)
                    i = 1
                elif i == 1:
                    usersPassword.append(user)
                    i = 0
            usersDictionary = {}
            for i in range(len(usersUsername)):
                usersDictionary[usersUsername[i]] = usersPassword[i]

            if username in usersDictionary and usersDictionary[username] == password:
                flask.session['username'] = username
            else:
                flask.flash("username doesn't exist or incorrect password")
            return flask.redirect(flask.url_for('index'))


def login_required(method):
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        if 'username' in flask.session:
            return method(*args, **kwargs)
        else:
            flask.flash('A login is required to see the page')
            return flask.redirect(flask.url_for('index'))

    return wrapper


class Test(flask.views.MethodView):
    def get(self):
        return flask.render_template('test.html', running=running)


class Stop(flask.views.MethodView):
    @login_required
    def get(self):
        global running
        running = False
        l.stop()
        return  flask.render_template('index.html', running=running)


class Sniffer(flask.views.MethodView):
    @login_required
    def get(self):
        print "went to sniffer, running is"
        print str(running)
        return  flask.render_template('sniffer.html', running=running)

    @login_required
    def post(self):
        global running

        try:
            if l.isRunning == False:  # if the thread has been shut down
                l.isRunning = True  # change it to true, so it could loop again
                running = True
                l.start()  # starts the forever loop / declared from the top to be a global variable
                print str(running)
            else:
                running = True
                print str(running)
                l.start()
        except Exception, e:
            raise e
        return  flask.render_template('test.html', running=running)  #goes to the test.html page


class Notif(flask.views.MethodView):


    @login_required
    def get(self):
        global running
        attack_list = ['Default','SA001 - Last Hop Router Advertisement Attack','SA002 - Neighbor Advertisement Spoofing Attack','SA003 - DoS on Duplicate Address Detection']
        filename_list = getfilenames()
        logfile = "log_report-" + time.strftime('%Y%m%d') + ".s3"
        return printlogs(running, attack_list, filename_list, logfile)

    @login_required
    def post(self):
        attack = str(flask.request.form['attack'])
        date = str(flask.request.form['filename'])
        logfile = "log_report-" + time.strftime('%Y%m%d') + ".s3"
        attack_spec = attack[0:5]
        if  str(date) != "Default":
            logfile = "log_report-" + date[0:4] + date[7:9] + date[12:14] + ".s3"
        print date
        filename_list = getfilenames()
        attack_list = ['Default','SA001 - Last Hop Router Advertisement Attack','SA002 - Neighbor Advertisement Spoofing Attack','SA003 - DoS on Duplicate Address Detection']

        if attack == 'Default' and date == 'Default':
            return flask.redirect(flask.url_for('notif'))
        else:
            return filter(running, attack_list, filename_list, logfile, attack_spec, date)

class Config(flask.views.MethodView):
    @login_required
    def get(self):
        global learning
        global manual
        if File_Existence(os.path.join(APP_ACC, 'Accounts.txt')) is True:
            acc = open(os.path.join(APP_ACC, 'Accounts.txt'))
            user = acc.readline()
            myname = user.partition(' ')[0]
            print flask.session['username']
            if myname == flask.session['username'] and manual is False:
                message = Markup(
                    '<h2>Delete Logs</h2>'
                    '<input type="submit" name="submit" value="Delete Logs" />'
                    '<br></br>'
                    '<h2>Account Mode</h2>'
                    '<input type="submit" name="submit" value="Create Accounts" />'
                    '<input type="submit" name="submit" value="Delete Accounts" />'
                    '<br></br>'
                    '<h2>Manual VLAN Mode</h2>'
                    '<input type="submit" name="submit" value="Edit Router Database*" />'
                    '<br></br>'
                    '<h2>*should be activated if the network contains vlans<br>'
                    'and the network interface card does not support vlan tag layer</h2>'
                    '<br>'
                    '<input type="submit" name="submit" value="Enable manual vlan mitigation**" />'
                    '<br></br>'
                    '<h2>**this would activate the mitigate module that would send<br>'
                    'all mitigate messages that are found in the router database</h2>')
            elif myname == flask.session['username'] and manual is True:
                message = Markup(
                    '<h2>Delete Logs</h2>'
                    '<input type="submit" name="submit" value="Delete Logs" />'
                    '<br></br>'
                    '<h2>Account Mode</h2>'
                    '<input type="submit" name="submit" value="Create Accounts" />'
                    '<input type="submit" name="submit" value="Delete Accounts" />'
                    '<br></br>'
                    '<h2>Manual VLAN Mode</h2>'
                    '<input type="submit" name="submit" value="Edit Router Database*" />'
                    '<br></br>'
                    '<h2>*should be activated if the network contains vlans<br>'
                    'and the network interface card does not support vlan tag layer</h2>'
                    '<br>'
                    '<input type="submit" name="submit" value="Disable manual vlan mitigation**" />'
                    '<br></br>'
                    '<h2>**this would activate the mitigate module that would send<br>'
                    'all mitigate messages that are found in the router database</h2>')
            else:
                message = Markup("<br></br>")
        flask.flash(message)
        print "learning is"
        print learning
        return  flask.render_template('config.html', running=running, learning=learning)

    @login_required
    def post(self):
        global learning
        if flask.request.form['submit'] == 'Start Learning':
            print "hidden is"
            mode = flask.request.form['hidden']
            l.setMode(mode)
            learning = True
            return flask.redirect(flask.url_for('config'))
        elif flask.request.form['submit'] == 'Stop Learning':
            learning = False
            l.setMode(False)
            return flask.redirect(flask.url_for('config'))
        elif flask.request.form['submit'] == 'Select Interface':
            return flask.redirect(flask.url_for('interfaces'))
            pass
        elif flask.request.form['submit'] == 'Delete Logs':
            filenames = next(os.walk("../Logs"))[2]
            for x in filenames:
             if File_Existence(os.path.join(APP_STATIC, x)) is True:
                os.remove(os.path.join(APP_STATIC, x))

            return flask.redirect(flask.url_for('config'))

        elif flask.request.form['submit'] == 'Create Accounts':
            return flask.redirect(flask.url_for('signUp'))
        elif flask.request.form['submit'] == 'Delete Accounts':
            return flask.redirect(flask.url_for('delete'))
        elif flask.request.form['submit'] == 'Edit Router Database*':
            return flask.redirect(flask.url_for('editRDB'))
        elif flask.request.form['submit'] == 'Enable manual vlan mitigation**':
            return flask.redirect(flask.url_for('enableVlan'))
        elif flask.request.form['submit'] == 'Disable manual vlan mitigation**':
            return flask.redirect(flask.url_for('enableVlan'))

class interfaces(flask.views.MethodView):
    def get(self):
        interface_list = self.getInterface()
        return  flask.render_template('interfaces.html', running=running, interface_list=interface_list)

    def getInterface(self):
        return findalldevs()


    def post(self):
        expression = str(flask.request.form['expression'])
        l.setExpression(expression)
        return flask.redirect(flask.url_for('config'))

class deleteAcc(flask.views.MethodView):
    def getAccounts(self):
        names = []
        f = open('../Database/Accounts.txt', 'r')
        users = f.read()
        f.close()
        names = users.split()
        namectr = len(names) - 2
        print namectr#counter for account names and passwords
        passctr = 1                  #counter for passwords to be deleted in the array // to not be shown in the array
        del names[0]                #deletes the first and second index in the array
        del names[0]                   # as it represents the admin account name and password
        while namectr > passctr:             # while there is still account name and password
            del names[passctr]
            passctr += 1
            print names
            namectr = len(names)
        print names
        return names

    def get(self):
        accounts = self.getAccounts()
        return  flask.render_template('deleteAcc.html', running=running, accounts=accounts)

    def post(self):
        acc_no = flask.request.form['acc_no']
        names = []
        f = open('../Database/Accounts.txt', 'r')
        users = f.read()
        f.close()
        names = users.split('\n')
        del names[int(acc_no)]
        f = open('../Database/Accounts.txt', 'w')
        for user in names:
            f.write(user + "\n")
        f.close()


        #delete account here
        return flask.redirect(flask.url_for('delete'))

class signUpUser(flask.views.MethodView):
    def get(self):
        return  flask.render_template('signUp.html', running=running)

    def post(self):
        user = flask.request.form['username'];
        password = flask.request.form['password'];
        f = open('../Database/Accounts.txt', 'a')
        f.write(user + " " + password + "\n")
        f.close()
        return flask.redirect(flask.url_for('index'))
        #return flask.render_template('index.html', running=running)


class EditRDB(flask.views.MethodView):
    def get(self):
        f = open('../Database/Router_Database', 'r')
        message = f.read()
        f.close()
        return  flask.render_template('editRDB.html', running=running, message=message)

    def post(self):
        message = flask.request.form['message']
        f = open('../Database/Router_Database', 'w')
        f.write(message)
        f.close()
        return flask.redirect(flask.url_for('config'))

class dashboard(flask.views.MethodView):
    def get(self):
        global socketThread
        if socketThread is None:
            socketThread = Thread(target=background_thread)
            socketThread.start()
        logfile = "log_report-" + time.strftime('%Y%m%d') + ".s3"
        return printIndex(running,logfile)

    def post(self):
        return flask.redirect(flask.url_for('dashboard'))

class EnableVlan(flask.views.MethodView):
    def get(self):
        global manual
        f = open('../Database/Manual_VLAN', 'w')
        if manual == True:
            manual = False
            f.write('False')
        else:
            manual = True
            f.write('True')
        f.close()
        return flask.redirect(flask.url_for('config'))


app.add_url_rule('/', view_func=Main.as_view('index'), methods=['GET', 'POST'])
app.add_url_rule('/sniffer', view_func=Sniffer.as_view('sniffer'), methods=['GET', 'POST'])
app.add_url_rule('/test', view_func=Test.as_view('test'), methods=['GET'])
app.add_url_rule('/stop', view_func=Stop.as_view('stop'), methods=['GET', 'POST'])
app.add_url_rule('/notification', view_func=Notif.as_view('notif'), methods=['GET', 'POST'])
app.add_url_rule('/config', view_func=Config.as_view('config'), methods=['GET', 'POST'])
app.add_url_rule('/signUpUser', view_func=signUpUser.as_view('signUp'), methods=['GET', 'POST'])
app.add_url_rule('/interfaces', view_func=interfaces.as_view('interfaces'), methods=['GET', 'POST'])
app.add_url_rule('/delete', view_func=deleteAcc.as_view('delete'), methods=['GET', 'POST'])
app.add_url_rule('/editRDB', view_func=EditRDB.as_view('editRDB'), methods=['GET', 'POST'])
app.add_url_rule('/dashboard', view_func=dashboard.as_view('dashboard'), methods=['GET', 'POST'])
app.add_url_rule('/enableVlan', view_func=EnableVlan.as_view('enableVlan'), methods=['GET', 'POST'])

if __name__ == "__main__":
    socketio.run(app)
    app.debug = True

socketio.run(app)
app.debug = True