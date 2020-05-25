import configparser
import json
from dynaconf import settings


def main():
    config = configparser.ConfigParser()
    config.read('alembic.ini')
    config['alembic']['DB_USER'] = settings['MYSQL']['USER']
    config['alembic']['DB_PASSWORD'] = settings['MYSQL']['PASSWORD']
    config['alembic']['DB_HOST'] = settings['MYSQL']['HOST']
    config['alembic']['DB_NAME'] = settings['MYSQL']['DB']
    config['alembic']['sqlalchemy.url'] = 'mysql+pymysql://%(db_user)s:%(db_password)s@%(db_host)s/%(db_name)s'
    with open('alembic.ini', 'w') as configfile:
        config.write(configfile)


if __name__ == '__main__':
    main()
