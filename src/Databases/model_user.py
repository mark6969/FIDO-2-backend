from flask import Flask
#  from flask.ext.sqlalchemy import SQLAlchemy<--新版取消了
from flask_sqlalchemy import SQLAlchemy
import os

#  取得目前文件資料夾路徑
pjdir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
#  新版本的部份預設為none，會有異常，再設置True即可。
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# #  設置sqlite檔案路徑
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
#     os.path.join(pjdir, 'data.sqlite')

db = SQLAlchemy(app)
class User(db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __init__(self, username, email):
        self.username = username
        self.email = email

    def __repr__(self):
        return '<User %r>' % self.username

if __name__ == "__main__":
    app = Flask(__name__)
    # 配置数据库
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(pjdir, 'data.sqlite')
    # 如果设置成 True (默认情况)，Flask-SQLAlchemy 将会追踪对象的修改并且发送信号。
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    # 绑定app至SQLAlchemy
    db = SQLAlchemy(app)
    db.create_all()