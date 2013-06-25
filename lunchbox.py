import web
from bson.json_util import dumps, loads

from webpy_mongodb_sessions.session import MongoStore
from pymongo import Connection

import os
from jinja2 import Environment,FileSystemLoader

MONGODB_CONNECTION = Connection()
DB = Connection()['lunchbox']

APP_SECRET = u'e18ec3fb1fb059fa06a0e25fc8e95397'

urls = (
	'/', 'index',
	'/login', 'login',
	'/logout', 'logout',
	'/hbapp/(.+)', 'hbapp',
	'/order/active', 'active_order',
	'/new_order', 'new_order',
	'/save_shop', 'save_shop',
	'/shop/simple', 'simple_shop',
	'/401', 'Unauthorized',
	'/403', 'Forbidden',
)

app = web.application(urls, globals())

if web.config.get('_session') is None:
    session = web.session.Session(app, MongoStore(MONGODB_CONNECTION['lunchbox'], 'sessions'))
    web.config._session = session
else:
    session = web.config._session

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


def get_user(find_filter=None):
	userid = session.get('userid')
	if not userid:
		return None

	return DB['user'].find_one({'_id': userid}, find_filter)


def gen_password(password):
	from md5 import md5
	m = md5()
	m.update(APP_SECRET + password + APP_SECRET)
	return m.hexdigest()


class index:
	def GET(self):
		user = get_user({'username': 1})

		if not user:
			raise web.seeother('/login')
		else:
			user['email'] = user['_id']
			return render_template("app.html", user=user)

class logout:
	def GET(self):
		session.kill()
		raise web.seeother('/')

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
			username = data.get('username').strip()
			password = data.get('password').strip()
			assert username, "no username found"
			assert password, "no password found"
			assert username.endswith('hopebaytech.com') or username.endswith('happygorgi.com'), "bad username"

			user_collection = DB['user']
			user = user_collection.find_one({'_id': username}, {'_id': 1, 'password': 1})

			if user:
				# old user, verify password
				assert gen_password(password) == user.get('password'), "bad password"
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

class new_order:
	def POST(self):
		return ""

class save_shop:
	def POST(self):
		result = {
			"result": False,
			"msg" : None,
			"data": None,
		}

		try:
			data = load_json()
			assert data, "bad POST data"
			DB['shop'].save(data)
			result["result"] = True
		except Exception, e:
			result["msg"] = str(e)

		return json_resp(result)


class active_order:
	def GET(self):
		return json_resp(list(DB['order'].find({'active': True})))

class simple_shop:
	def GET(self):
		return json_resp(list(DB['shop'].find({}, {'name': 1, 'description': 1})))

class hbapp:
	def GET(self, name):
		return render_template("%s.html" % name)

class Unauthorized:
	def GET(self):
		raise web.Unauthorized()

class Forbidden:
	def GET(self):
		raise web.Forbidden()

if __name__ == "__main__":
	app.debug = True
	app.run()
