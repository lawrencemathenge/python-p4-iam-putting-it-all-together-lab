from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    
 __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String, nullable=True)
    bio = db.Column(db.String, nullable=True)

    # Relationship with recipes
    recipes = db.relationship('Recipe', back_populates='user', cascade="all, delete-orphan")

    # Serialization rules
    serialize_rules = ('-recipes.user',)

    # Validate unique username
    @validates('username')
    def validate_username(self, key, value):
        if not value:
            raise ValueError("Username is required")
        return value

    # Password setter (hashing)
    def set_password(self, password):
        self._password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Password checker
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self._password_hash.encode('utf-8'))

    # Prevent direct access to _password_hash
    @property
    def password_hash(self):
        raise AttributeError("Password hash is not accessible.")

    @password_hash.setter
    def password_hash(self, password):
        self.set_password(password)

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Relationship with User
    user = db.relationship('User', back_populates='recipes')

    # Serialization rules
    serialize_rules = ('-user.recipes',)

    # Validations
    @validates('title')
    def validate_title(self, key, value):
        if not value:
            raise ValueError("Title is required")
        return value

    @validates('instructions')
    def validate_instructions(self, key, value):
        if not value or len(value) < 10:
            raise ValueError("Instructions must be at least 10 characters long")
        return value
    