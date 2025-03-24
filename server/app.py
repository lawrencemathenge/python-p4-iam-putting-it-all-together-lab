#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url', '')
        bio = data.get('bio', '')

        errors = {}

        # Validate presence of username
        if not username:
            errors['username'] = "Username is required."

        # Validate presence of password
        if not password:
            errors['password'] = "Password is required."

        # Check if username is unique
        if User.query.filter_by(username=username).first():
            errors['username'] = "Username is already taken."

        if errors:
            return jsonify({"errors": errors}), 422  

        # Create new user
        new_user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )
        new_user.set_password(password)  # Hash password
        db.session.add(new_user)
        db.session.commit()

        # Store user ID in session
        session['user_id'] = new_user.id

        return jsonify({
            "id": new_user.id,
            "username": new_user.username,
            "image_url": new_user.image_url,
            "bio": new_user.bio
        }), 201 
api.add_resource(Signup, '/signup')

if __name__ == '__main__':
    app.run(debug=True)
    
class CheckSession(Resource):
  def get(self):
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401  # Unauthorized

        user = User.query.get(user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404 

        return jsonify({
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }), 200
          
    
    class Login(Resource):
        def post(self):
            data = request.get_json()

        username = data.get('username')
        password = data.get('password')

        # Find user by username
        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            return jsonify({"error": "Invalid username or password"}), 401  # Unauthorized

        # Store user ID in session
        session['user_id'] = user.id

        return jsonify({
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }), 200 


class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)  # Remove user from session
        return jsonify({"message": "Logged out successfully"}), 200 

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401  # Unauthorized

        user = User.query.get(user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404  # Not Found

        return jsonify({
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }), 200 
    
class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')

        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401  # Unauthorized

        recipes = Recipe.query.all()

        recipe_list = [{
            "id": recipe.id,
            "title": recipe.title,
            "instructions": recipe.instructions,
            "minutes_to_complete": recipe.minutes_to_complete,
            "user": {
                "id": recipe.user.id,
                "username": recipe.user.username,
                "image_url": recipe.user.image_url
            }
        } for recipe in recipes]

        return jsonify(recipe_list), 200 

api.add_resource(RecipeIndex, '/recipes')
    
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)