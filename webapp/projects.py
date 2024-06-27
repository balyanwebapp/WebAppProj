import sqlalchemy as sa
import sqlalchemy.orm as so
from app import app, db
from app.models import User

#Configures the flask shell so that you can work with database entites without having to import them
@app.shell_context_processor
def make_shell_context():
    return {'sa': sa, 'so': so, 'db': db, 'User': User}