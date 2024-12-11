# -*- coding: utf-8 -*-

from views.view import app

if __name__ == '__main__':
    app.run(threaded=True, host='0.0.0.0', port=63335, debug=False)
