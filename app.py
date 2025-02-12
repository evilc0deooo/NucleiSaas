# -*- coding: utf-8 -*-

from views.view import app
from waitress import serve

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=63335, connection_limit=1000, channel_timeout=3600, threads=8)
