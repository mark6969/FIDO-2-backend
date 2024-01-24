import os

project_dir = os.path.abspath(os.path.dirname(__file__))  # 取得目前資料夾的路徑


class Config:
    TESTING = False


class ProductionConfig(Config):
    FLASK_ENV = "production"
    DEBUG = False


class DevelopmentConfig(Config):
    ENV = "development"
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + \
        os.path.join(project_dir, "user.db")  # 設定 db 的路徑
    SQLALCHEMY_TRACK_MODIFICATIONS = True

class TestingConfig(Config):
    TESTING = True
