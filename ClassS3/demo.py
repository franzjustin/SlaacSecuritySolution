import flask, flask.views
import os
import functools
import threading
import Sniff
import time
from flask import Markup
import pcapy
from pcapy import findalldevs

# from sniffer import StoppableThread

# snifferFile = StoppableThread()

#!/usr/bin/python

import thread
#todo lollololol
APP_ROOT = os.path.dirname(os.getcwd())
APP_STATIC = os.path.join(APP_ROOT, 'Logs')
APP_ACC = os.path.join(APP_ROOT, 'Database')
l = Sniff.Forever_Loop()  #the python file class with the function of forever loop / to use as a thread
global running
global learning
learning = False
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
		return flask.render_template('index.html', running=running)


class Sniffer(flask.views.MethodView):
	@login_required
	def get(self):
		print "went to sniffer, running is"
		print str(running)
		return flask.render_template('sniffer.html', running=running)

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
		return flask.render_template('test.html', running=running)  #goes to the test.html page


class Notif(flask.views.MethodView):

	def getfilenames(self):
		filename_list = []
		filename_list.append("Default")
		for file in os.listdir("../Logs"):
			if file.endswith(".s3"):
				file_temp = file.split('-')
				filename = file_temp[1].split('.')
				filename = filename[0][:4] + " / " + filename[0][4:6] + " / "+ filename[0][-2:]
				filename_list.append(filename)
		return filename_list

	def filter(self, running, attack_list, filename_list, logfile, attack, date):
		if attack == "Defau":
			#print "Pumasok"
			if File_Existence(os.path.join(APP_STATIC, logfile)) is True:
				with open(os.path.join(APP_STATIC, logfile)) as f:
					stat = str(f.read())
					flask.flash(stat)
					return flask.render_template('status.html', running=running , filename_list = filename_list, attack_list = attack_list)
			else:
				flask.flash("everything is fine :)")
				return flask.render_template('status.html', running=running, filename_list = filename_list, attack_list = attack_list)

		elif File_Existence(os.path.join(APP_STATIC, logfile)) is True:
			with open(os.path.join(APP_STATIC, logfile)) as f:
				stat = str(f.read())
				entry = stat.split('\n')
				#print "-----"
				#print len(entry)
				#print "-----"
				attack_message = []
				x = 0
				for log_entry in entry:
					split_entry = log_entry.split(' ')
					#print "x is "+ str(x)
					#print "split_entry is" + str(len(split_entry))
					if len(split_entry) > 1:
						if str(split_entry[2]) == str(attack):
							flask.flash(log_entry)
							attack_message.append(log_entry)
					#print "attack message length "+ str(len(attack_message))
					x = x + 1

				#print "lolol is"
				#print troll
				#print "lolo was"
				#print lolol
				#flask.flash(attack_message)
				return flask.render_template('status.html', running=running , filename_list = filename_list, attack_list = attack_list)
		else:
			flask.flash("everything is fine :)")
			return flask.render_template('status.html', running=running, filename_list = filename_list, attack_list = attack_list)


	def printlogs(self, running, attack_list, filename_list, logfile):
		if File_Existence(os.path.join(APP_STATIC, logfile)) is True:
			with open(os.path.join(APP_STATIC, logfile)) as f:
				stat = str(f.read())
				lol = stat.split('\n')
				#number is the start of index for last 5 files
				number = len(lol) - 6
				stat = lol[number:]
				y = 4
				for x in range(5):
					flask.flash(stat[y])
					y=y-1
				return flask.render_template('status.html', running=running , filename_list = filename_list, attack_list = attack_list)
		else:
			flask.flash("everything is fine :)")
			return flask.render_template('status.html', running=running, filename_list = filename_list, attack_list = attack_list)

	@login_required
	def get(self):
		global running
		attack_list = ['Default','SA001 - Last Hop Router Advertisement Attack','SA002 - Neighbor Advertisement Spoofing Attack','SA003 - DoS on Duplicate Address Detection']
		filename_list = self.getfilenames()
		logfile = "log_report-" + time.strftime('%Y%m%d') + ".s3"
		return self.printlogs(running, attack_list, filename_list, logfile)

	@login_required
	def post(self):
		attack = str(flask.request.form['attack'])
		date = str(flask.request.form['filename'])
		logfile = "log_report-" + time.strftime('%Y%m%d') + ".s3"

		attack_spec = attack[0:5]

		if  str(date) != "Default":
			logfile = "log_report-" + date[0:4] + date[7:9] + date[12:14] + ".s3"
		print date
		filename_list = self.getfilenames()
		attack_list = ['Default','SA001 - Last Hop Router Advertisement Attack','SA002 - Neighbor Advertisement Spoofing Attack','SA003 - DoS on Duplicate Address Detection']

		if attack == 'Default' and date == 'Default':
			return flask.redirect(flask.url_for('notif'))
		else:
			return self.filter(running, attack_list, filename_list, logfile, attack_spec, date)

class Config(flask.views.MethodView):
	@login_required
	def get(self):
		global learning
		if File_Existence(os.path.join(APP_ACC, 'Accounts.txt')) is True:
			acc = open(os.path.join(APP_ACC, 'Accounts.txt'))
			user = acc.readline()
			myname = user.partition(' ')[0]
			print flask.session['username']
			if myname == flask.session['username']:
				message = Markup(
					'<h2>Delete Logs</h2>'
					'<input type="submit" name="submit" value="Delete Logs" />'
					'<br></br>'
					'<h2>Account Mode</h2>'
					'<input type="submit" name="submit" value="Create Accounts" />'
					'<input type="submit" name="submit" value="Delete Accounts" />')
			else:
				message = Markup("<br></br>")
		flask.flash(message)
		print "learning is"
		print learning
		return flask.render_template('config.html', running=running, learning=learning)

	@login_required
	def post(self):
		global learning
		if flask.request.form['submit'] == 'Start Learning':
			print "hidden is"
			mode = flask.request.form['hidden']
			l.setMode(mode)
			# run learning code
			#learn.activateLearningMode()
			learning = True
			return flask.redirect(flask.url_for('config'))
		elif flask.request.form['submit'] == 'Stop Learning':
			learning = False
			# learning mode stop
			l.setMode(False)
			return flask.redirect(flask.url_for('config'))
		elif flask.request.form['submit'] == 'Select Interface':
			return flask.redirect(flask.url_for('interfaces'))
			pass # learning mode stop
		elif flask.request.form['submit'] == 'Delete Logs':
			filenames = next(os.walk("../Logs"))[2]

			#logfile = "log_report-" + time.strftime('%Y%m%d') + ".s3"

			for x in filenames:
			 if File_Existence(os.path.join(APP_STATIC, x)) is True:
				os.remove(os.path.join(APP_STATIC, x))

			return flask.redirect(flask.url_for('config'))

		elif flask.request.form['submit'] == 'Create Accounts':
			return flask.redirect(flask.url_for('signUp'))
		elif flask.request.form['submit'] == 'Delete Accounts':
			return flask.redirect(flask.url_for('delete'))

class interfaces(flask.views.MethodView):
	def get(self):
		interface_list = self.getInterface()
		#print interface_list[0]
		return flask.render_template('interfaces.html', running=running, interface_list=interface_list)

	def getInterface(self):
		return findalldevs()


	def post(self):
		expression = str(flask.request.form['expression'])  # gets the input of the user
		#print expression
		l.setExpression(expression)
		return flask.redirect(flask.url_for('config'))
		#return flask.render_template('index.html', running=running)

class deleteAcc(flask.views.MethodView):
	def getAccounts(self):
		names = []
		f = open('../Database/Accounts.txt', 'r')
		users = f.read()
		f.close()
		names = users.split('\n')
		del names[0]
		del names[len(names)-1]
		print names
		return names

	def get(self):
		accounts = self.getAccounts()
		return flask.render_template('deleteAcc.html', running=running, accounts=accounts)
	def post(self):
		acc_no = flask.request.form['acc_no']
		names = []
		f = open('../Database/Accounts.txt', 'r')
		users = f.read()
		f.close()
		names = users.split('\n')
		del names[int(acc_no)]
		del names[len(names)-1]
		f = open('../Database/Accounts.txt', 'w')
		for user in names:
			f.write(user + "\n")
		f.close()


		#delete account here
		return flask.redirect(flask.url_for('delete'))

class signUpUser(flask.views.MethodView):
	def get(self):
		return flask.render_template('signUp.html', running=running)

	def post(self):
		user = flask.request.form['username'];
		password = flask.request.form['password'];
		f = open('../Database/Accounts.txt', 'a')
		f.write(user + " " + password + "\n")
		f.close()
		return flask.redirect(flask.url_for('index'))
		#return flask.render_template('index.html', running=running)


app.add_url_rule('/', view_func=Main.as_view('index'), methods=['GET', 'POST'])
app.add_url_rule('/sniffer', view_func=Sniffer.as_view('sniffer'), methods=['GET', 'POST'])
app.add_url_rule('/test', view_func=Test.as_view('test'), methods=['GET'])
app.add_url_rule('/stop', view_func=Stop.as_view('stop'), methods=['GET', 'POST'])
app.add_url_rule('/notification', view_func=Notif.as_view('notif'), methods=['GET', 'POST'])
app.add_url_rule('/config', view_func=Config.as_view('config'), methods=['GET', 'POST'])
app.add_url_rule('/signUpUser', view_func=signUpUser.as_view('signUp'), methods=['GET', 'POST'])
app.add_url_rule('/interfaces', view_func=interfaces.as_view('interfaces'), methods=['GET', 'POST'])
app.add_url_rule('/delete', view_func=deleteAcc.as_view('delete'), methods=['GET', 'POST'])

if __name__ == "__main__":
	app.run()

app.debug = True
app.run()
