import json
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import create_engine
from dynaconf import settings

mysql_host = settings['MYSQL']['HOST']
mysql_user = settings['MYSQL']['USER']
mysql_password = settings['MYSQL']['PASSWORD']
mysql_db = settings['MYSQL']['DB']

mysql_engine_path = f'mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}/{mysql_db}'

engine = create_engine(mysql_engine_path, echo=False)
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)
