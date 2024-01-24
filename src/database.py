from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class user(db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.String(80), primary_key=True)
    challenge = db.Column(db.String(80), nullable=False)
    credentials = db.Column(db.String(120),nullable=False)

    # def __init__(self, id, challenge, credentials):
    #     self.id = id
    #     self.challenge = challenge
    #     self.credentials = credentials

if __name__ == '__main__':
    with app.app_context():
        db.create_all()