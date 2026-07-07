from app.db import Database


class UserService:
    def __init__(self):
        self.db = Database()

    def create_user(self, email):
        self.db.write("users", {"email": email})
