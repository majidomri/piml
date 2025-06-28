import unittest
import os
# Add project root to sys.path to allow importing 'app'
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db, User
from werkzeug.security import generate_password_hash

class AuthTestCase(unittest.TestCase):

    def setUp(self):
        """Set up test variables."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for testing forms
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:' # Use in-memory SQLite
        self.app = app.test_client()
        with app.app_context():
            db.create_all()

        # Create a test user
        self.test_user_username = 'testuser'
        self.test_user_password = 'password123'
        hashed_password = generate_password_hash(self.test_user_password)
        user = User(username=self.test_user_username, password_hash=hashed_password)
        with app.app_context():
            db.session.add(user)
            db.session.commit()


    def tearDown(self):
        """Executed after each test."""
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def register(self, username, password, confirm_password):
        """Helper function to register a user."""
        return self.app.post('/register', data=dict(
            username=username,
            password=password,
            confirm_password=confirm_password
        ), follow_redirects=True)

    def login(self, username, password):
        """Helper function to login a user."""
        return self.app.post('/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)

    def logout(self):
        """Helper function to logout a user."""
        return self.app.get('/logout', follow_redirects=True)

    # --- Test Cases ---

    def test_01_register_page_loads(self):
        """Test that the registration page loads correctly."""
        response = self.app.get('/register')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Create Account', response.data)

    def test_02_successful_registration(self):
        """Test user registration with valid data."""
        response = self.register('newuser', 'newpassword', 'newpassword')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Your account has been created!', response.data) # Flash message
        self.assertIn(b'Welcome Back!', response.data) # Should be on login page
        with app.app_context():
            user = User.query.filter_by(username='newuser').first()
            self.assertIsNotNone(user)

    def test_03_registration_username_taken(self):
        """Test registration with an already taken username."""
        response = self.register(self.test_user_username, 'password123', 'password123')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'That username is taken.', response.data)
        self.assertIn(b'Create Account', response.data) # Should stay on register page

    def test_04_registration_password_mismatch(self):
        """Test registration with mismatched passwords."""
        response = self.register('anotheruser', 'password123', 'password456')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Field must be equal to password.', response.data) # WTForms default message
        self.assertIn(b'Create Account', response.data)

    def test_05_login_page_loads(self):
        """Test that the login page loads correctly."""
        response = self.app.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome Back!', response.data)

    def test_06_successful_login(self):
        """Test user login with correct credentials."""
        response = self.login(self.test_user_username, self.test_user_password)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Logged in successfully!', response.data)
        self.assertIn(f'Welcome, {self.test_user_username}!'.encode(), response.data) # On index page
        self.assertIn(b'Unlock Your Potential', response.data) # Some content from index

    def test_07_login_invalid_username(self):
        """Test user login with an invalid username."""
        response = self.login('wronguser', self.test_user_password)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login Unsuccessful.', response.data)
        self.assertIn(b'Welcome Back!', response.data) # Should stay on login page

    def test_08_login_invalid_password(self):
        """Test user login with an invalid password."""
        response = self.login(self.test_user_username, 'wrongpassword')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login Unsuccessful.', response.data)
        self.assertIn(b'Welcome Back!', response.data)

    def test_09_logout(self):
        """Test user logout."""
        self.login(self.test_user_username, self.test_user_password) # Login first
        response = self.logout()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'You have been logged out.', response.data)
        self.assertIn(b'Welcome Back!', response.data) # Should be on login page

    def test_10_access_protected_page_unauthenticated(self):
        """Test accessing a protected page when not logged in."""
        response = self.app.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome Back!', response.data) # Should be redirected to login
        self.assertNotIn(b'Unlock Your Potential', response.data)

    def test_11_access_protected_page_authenticated(self):
        """Test accessing a protected page when logged in."""
        self.login(self.test_user_username, self.test_user_password)
        response = self.app.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(f'Welcome, {self.test_user_username}!'.encode(), response.data)
        self.assertIn(b'Unlock Your Potential', response.data)

if __name__ == '__main__':
    unittest.main()
