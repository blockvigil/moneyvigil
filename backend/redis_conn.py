import aioredis
from functools import wraps
import contextlib
import json
import tenacity
import redis.exceptions as redis_exc
import redis
import decorator
from dynaconf import settings as settings_conf

REDIS_CONN_CONF = {
    "host": settings_conf['REDIS']['HOST'],
    "port": settings_conf['REDIS']['PORT'],
    "password": settings_conf['REDIS']['PASSWORD'],
    "db": settings_conf['REDIS']['DB']
}
redis_pool = redis.BlockingConnectionPool(**REDIS_CONN_CONF)


@contextlib.contextmanager
def create_redis_conn(connection_pool: redis.BlockingConnectionPool):
    """
    Contextmanager that will create and teardown a session.
    """
    try:
        redis_conn = redis.Redis(connection_pool=connection_pool)
        yield redis_conn
    except redis_exc.RedisError:
        raise
    except KeyboardInterrupt:
        pass


@tenacity.retry(
    stop=tenacity.stop_after_delay(60),
    wait=tenacity.wait_random_exponential(multiplier=1, max=60),
    retry=tenacity.retry_if_exception_type(redis_exc.RedisError),
    reraise=True
)
def provide_redis_conn(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        arg_conn = 'redis_conn'
        func_params = fn.__code__.co_varnames
        conn_in_args = arg_conn in func_params and func_params.index(arg_conn) < len(args)
        conn_in_kwargs = arg_conn in kwargs
        if conn_in_args or conn_in_kwargs:
            return fn(*args, **kwargs)
        else:
            connection_pool = redis.BlockingConnectionPool(**REDIS_CONN_CONF)
            with create_redis_conn(connection_pool) as redis_obj:
                kwargs[arg_conn] = redis_obj
                return fn(*args, **kwargs)
    return wrapper

@decorator.decorator
async def provide_async_redis_conn(coro, *args, **kwargs):
    arg_conn = 'redis_conn'

    connection_pool = await aioredis.create_redis_pool(
        address=(REDIS_CONN_CONF['host'], REDIS_CONN_CONF['port']),
        db=REDIS_CONN_CONF['db'],
        password=REDIS_CONN_CONF['password']
    )
    kwargs[arg_conn] = connection_pool
    await coro(*args, **kwargs)
