import io
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.httpclient
import tornado.escape
from tornado.options import define, options
from neo4j.v1 import GraphDatabase
import logging
import sys
import aiohttp
import json
from db_wrapper import DBCallsWrapper
from db_session import mysql_engine_path
from tornado_sqlalchemy import as_future, make_session_factory, SessionMixin
from google.cloud import storage
from dynaconf import settings
import coloredlogs
import requests

define("port", default=5888, help="run on the given port", type=int)

tornado_logger = logging.getLogger('MoneyVigilReceipts')
tornado_logger.propagate = False
tornado_logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(u"%(levelname)-8s %(name)-4s %(asctime)s,%(msecs)d %(module)s-%(funcName)s: %(message)s")

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)

stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.ERROR)
stderr_handler.setFormatter(formatter)

null_handler = logging.NullHandler(level=logging.DEBUG)
neo_log = logging.getLogger('neo4j')
neo_log.addHandler(null_handler)
neo_log.propagate = False

tornado_logger.addHandler(stdout_handler)
tornado_logger.addHandler(stderr_handler)

hn = logging.NullHandler()
hn.setLevel(logging.DEBUG)
logging.getLogger("tornado.access").addHandler(hn)
logging.getLogger("tornado.access").propagate = False

coloredlogs.install(level='DEBUG', logger=tornado_logger)


class MainHandler(SessionMixin, tornado.web.RequestHandler):
    async def get(self, filehash):
        try:
            r = requests.get(
                url=f'http://localhost:9980/renter/stream/{filehash}',
                headers={'user-agent': 'Sia-Agent'},
                stream=True
            )
        except Exception as e:
            tornado_logger.error('Error accessing Sia file')
            tornado_logger.error(e)
            self.set_status(status_code=404)
            return None
        else:
            # binary_stream = io.BytesIO()
            self.set_header('Content-Type', 'application/octet-stream')
            tornado_logger.debug('Streaming file download...')
            for chunk in r.iter_content(chunk_size=1024 * 50):  # 50 kB chunks
                # tornado_logger.debug('Writing chunk to bytes stream')
                self.write(chunk)
            await self.flush()

    def compute_etag(self):
        return None

def main():
    tornado.options.parse_command_line()
    application = tornado.web.Application([
        (r"/receipt/(.*)", MainHandler),

    ], session_factory=make_session_factory(mysql_engine_path))
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(options.port)
    try:
        tornado.ioloop.IOLoop.current().start()
    except KeyboardInterrupt:
        tornado_logger.debug('Shutting down...')
        tornado.ioloop.IOLoop.current().stop()


if __name__ == "__main__":
    graph = GraphDatabase.driver(
        settings['NEO4J']['URL'],
        auth=(settings['NEO4J']['USERNAME'], settings['NEO4J']['PASSWORD']),
        encrypted=settings['NEO4J']['ENCRYPTED_CONNECTION']
    )

    main()