import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = 'your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'database.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static/uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


