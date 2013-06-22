import web
from json import dumps, loads

from webpy_mongodb_sessions.session import MongoStore
from pymongo import Connection

import os
from jinja2 import Environment,FileSystemLoader

MONGODB_CONNECTION = Connection()
DB = Connection()['lunchbox']

APP_SECRET = '/]\xbf\xe2f\xb0\x11\x89\xd5\xe8\xfdA\xd2j_\x8aww!\x11~r\xc2\x9b'

urls = (
	'/', 'index',
	'/login', 'login',
)

app = web.application(urls, globals())
session = web.session.Session(app, MongoStore(MONGODB_CONNECTION['lunchbox'], 'sessions'))

def render_template(template_name, **context):
    extensions = context.pop('extensions', [])
    globals = context.pop('globals', {})

    jinja_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')),
            extensions=extensions,
            )
    jinja_env.globals.update(globals)

    #jinja_env.update_template_context(context)
    return jinja_env.get_template(template_name).render(context)


def json_resp(data):
	web.header('Content-Type', 'application/json')
	return dumps(data)


def load_json():
	try:
		return loads(web.data())
	except Exception, e:
		return None


def gen_password(password):
	from md5 import md5
	m = md5()
	m.update(APP_SECRET + password + APP_SECRET)
	return m.hexdigest()


class index:
	def GET(self):
		if not 'userid' in session:
			raise web.seeother('/login')
		else:
			return render_template("app.html")


class login:
	def GET(self):
		return render_template("login.html")

	def POST(self):
		result = {
			"result": False,
			"msg" : None,
			"data": None,
		}

		try:
			data = load_json()
			assert data, "bad POST data"
			username = data.get('username').trim()
			password = data.get('password').trim()
			assert username, "no username found"
			assert password in data, "no password found"
			assert username.endswith('hopebaytech.com') or username.endswith('happygorgi.com'), "bad username"

			user_collection = DB['user']
			user = user_collection.find_one({'_id': username}, {'_id': 1, 'password': 1}):
			if user:
				# old user, verify password
				assert gen_password(password) == password, "bad password"
			else:
				# new user, add it
				user = {
					'_id': username,
					'username': username.split('@')[0],
					'password': gen_password(password)
				}
				user_collection.save(user)

			session['userid'] = username
			result["result"] = True
		except Exception, e:
			result["msg"] = str(e)

		return json_resp(result)


if __name__ == "__main__":
	app.debug = True
	app.run()