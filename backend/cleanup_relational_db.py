from db_session import engine
from db_models import *

Base.metadata.drop_all(engine)
