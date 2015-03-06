import flask, flask.views
import os
import functools
import threading
import Sniff
import time
import pcapy
from pcapy import findalldevs
# from sniffer import StoppableThread

# snifferFile = StoppableThread()

#!/usr/bin/python
#todo working

import thread

APP_ROOT = os.path.dirname(os.getcwd())
APP_STATIC = os.path.join(APP_ROOT, 'Logs')
APP_ACC = os.path.join(APP_ROOT, 'Database')
l = Sniff.Forever_Loop()  #the python file class with the function of forever loop / to use as a thread
global running
running = False
app = flask.Flask(__name__)

app.secret_key = "bacon"
users = {'admin': 'admin'}


def File_Existence(filepath):
    try:
        f = open(filepath)
    except IOError, OSError:  # Note OSError is for later versions of python
        return False

    return True

class Main(flask.views.MethodView):  # the main page
    def get(self):  # when open, this is the first page it gets
        #print File_Existence(os.path.join(APP_ACC, 'Accounts.txt'))

        if File_Existence(os.path.join(APP_ACC, 'Accounts.txt')) is False:
            print "NO Accounts.txt"
            return flask.render_template('signUp.html',running=running)  #flask uses templates of html files for the interface // in this case, the index page
        else:
            print "there is an Accounts.txt"
            return flask.render_template('index.html',running=running)  #flask uses templates of html files for the interface // in this case, the index page

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
            if username in users and users[username] == password:
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
        return flask.render_template('index.html', running=running)


class Sniffer(flask.views.MethodView):
    @login_required
    def get(self):
        print "went to sniffer, running is"
        print str(running)
        interface_list = self.getInterface()
        print interface_list[0]
        return flask.render_template('sniffer.html', running=running, interface_list=interface_list)
    def getInterface(self):
        return findalldevs()

    @login_required
    def post(self):
        global running
        expression = str(flask.request.form['expression'])  # gets the input of the user
        l.setExpression(expression)  # sets the input of the user to know where to sniff
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
        return flask.render_template('test.html', running=running)  #goes to the test.html page


class Notif(flask.views.MethodView):
    @login_required
    def get(self):

        logfile = "log_report-" + time.strftime('%Y%m%d') + ".s3"  # creates the string filename of the current log file used
        #print logfile
        global running

        if File_Existence(os.path.join(APP_STATIC, logfile)) is True:
            with open(os.path.join(APP_STATIC, logfile)) as f:
                stat = str(f.read())
                flask.flash(stat)
                return flask.render_template('status.html', running=running)
        else:
            flask.flash("everything is fine :)")
            return flask.render_template('status.html', running=running)


class Learn(flask.views.MethodView):
    @login_required
    def get(self):
        return 0

    @login_required
    def post(self):
        return 0


class signUpUser(flask.views.MethodView):
    def get(self):
        return flask.render_template('signUp.html', running=running)

    def post(self):
        user = flask.request.form['username'];
        password = flask.request.form['password'];
        f = open('../Database/Accounts.txt', 'a')
        f.write(user + " " + password)
        print "Check1"
        f.close()
        print "Check2"
        return flask.redirect(flask.url_for('index'))
        #return flask.render_template('index.html', running=running)


app.add_url_rule('/', view_func=Main.as_view('index'), methods=['GET', 'POST'])
app.add_url_rule('/sniffer', view_func=Sniffer.as_view('sniffer'), methods=['GET', 'POST'])
app.add_url_rule('/test', view_func=Test.as_view('test'), methods=['GET'])
app.add_url_rule('/stop', view_func=Stop.as_view('stop'), methods=['GET', 'POST'])
app.add_url_rule('/notification', view_func=Notif.as_view('notif'), methods=['GET', 'POST'])
app.add_url_rule('/learn', view_func=Learn.as_view('learn'), methods=['GET', 'POST'])
app.add_url_rule('/signUpUser', view_func=signUpUser.as_view('signUp'), methods=['GET', 'POST'])

if __name__ == "__main__":
    app.run()

app.debug = True
app.run()
