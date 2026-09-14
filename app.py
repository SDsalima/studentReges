import os
from flask import (
    Flask,
    redirect,
    render_template,
    flash,
    request,
    url_for,
    make_response,
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import check_password_hash, generate_password_hash
from email_validator import EmailNotValidError, validate_email
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)

app = Flask(__name__)

# --- Database & Config ---
# Reads DATABASE_URL from cloud environment if available; falls back to local PostgreSQL
db_url = os.environ.get(
    "DATABASE_URL", 
    "postgresql://postgres:root@localhost:5432/student_db"
)

# Render / Heroku database URLs start with 'postgres://', but SQLAlchemy requires 'postgresql://'
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- Secret Keys ---
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "secret_salima_key_student")
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "salima_super_key")

# --- JWT Cookie Settings ---
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

# --- Extensions Initialization ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# --- JWT Error Callbacks (Prevents Raw JSON on Unauthorized Access) ---
@jwt.unauthorized_loader
def missing_token_callback(error):
    flash("Please log in first to access this page.", "danger")
    return redirect(url_for("login"))

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    flash("Your session has expired. Please log in again.", "info")
    return redirect(url_for("login"))

class Student(db.Model):
    __tablename__ = "students"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(180), unique=True, nullable=False)
    password_hash = db.Column(db.String(288), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# ----routes----
@app.route("/")
def home():
    return render_template("index.html", title="Home page")


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        try:
            valid = validate_email(email, check_deliverability=False)
            email = valid.normalized

        except EmailNotValidError as e:
            flash(f"Invalid email: {str(e)}", "danger")
            return redirect(url_for("register"))

        if Student.query.filter_by(email=email).first():
            flash("Email already registered!!", "danger")
            return redirect(url_for("register"))

        hashed_pwd = generate_password_hash(password)
        new_student = Student(name=name, email=email)
        new_student.set_password(password)

        db.session.add(new_student)
        db.session.commit()

        flash("Registration successfully!!", "success")
        return redirect(url_for("login"))

    return render_template("register.html", title="Register page")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        student = Student.query.filter_by(email=email).first()

        if not student or not check_password_hash(student.password_hash, password):
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

        # Generate JWT token using student id
        access_token = create_access_token(identity=str(student.id))

        # Redirect to dashboard and attach JWT cookie
        response = make_response(redirect(url_for("dashboard")))
        response.set_cookie("access_token_cookie", access_token)
        return response

    return render_template("login.html", title="Login page")


# protect dashboard route
@app.route("/dashboard")
@jwt_required(locations=["cookies"])
def dashboard():
    current_student_id = get_jwt_identity()
    student = db.session.get(Student, int(current_student_id))

    if not student:
        flash("Student record not found!.", "danger")
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html", student=student, title=f"{student.name}'s dashboard"
    )


@app.route("/logout")
def logout():
    response = make_response(redirect(url_for("login")))
    response.delete_cookie("access_token_cookie")
    flash("LogOut successfully!!", "info")
    return response


if __name__ == "__main__":
    app.run(debug=True)
