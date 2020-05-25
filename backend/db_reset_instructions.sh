#!/bin/sh
python cleanup_graphdb.py
alembic downgrade base
alembic upgrade head
python init_graphdb.py
python init_reldb.py