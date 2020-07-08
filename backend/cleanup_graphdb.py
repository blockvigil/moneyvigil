import json
from neo4j.v1 import GraphDatabase
from dynaconf import settings

driver = GraphDatabase.driver(
    settings['NEO4J']['URL'],
    auth=(settings['NEO4J']['USERNAME'], settings['NEO4J']['PASSWORD']),
    encrypted=False
)

with driver.session() as session:
    session.run('MATCH r=()-->() delete r')
    session.run('match (n:User) delete n')
    session.run('match (g:Group) delete g')
