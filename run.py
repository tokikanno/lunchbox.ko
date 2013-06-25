from gevent.wsgi import WSGIServer
from lunchbox import app

server = WSGIServer(('0.0.0.0', 5252), app)
server.serve_forever()