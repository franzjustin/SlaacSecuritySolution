#!/usr/bin/env python
import threading
from threading import Thread
import gevent
import gevent.monkey
from gevent.pywsgi import WSGIServer
gevent.monkey.patch_all()

from flask import Flask, request, Response, render_template

app = Flask(__name__)


class Forever_SSE(threading.Thread):

    def __init__(self):
        Thread.__init__(self)

    def start(self):
        Thread.__init__(self)
        Thread.start(self)

    def stop(self):
        self.isRunning = False

    def run(self):
        Thread.__init__(self)

        def event_stream():
            count = 0
            while True:
                gevent.sleep(2)
                yield 'data: %s\n\n' % count
                count += 1

        @app.route('/my_event_source')
        def sse_request():
            return Response(
                    event_stream(),
                    mimetype='text/event-stream')

        @app.route('/')
        def page():
            return render_template('sniffer.html')

        if __name__ == '__main__':
            http_server = WSGIServer(('127.0.0.1', 5000), app)
            http_server.serve_forever()