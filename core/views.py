from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from .forms import SignupForm
import psycopg2
from psycopg2 import pool
import random
import time
import pickle
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

# ---------- PostgreSQL ---------- #
try:
    connection_pool = pool.SimpleConnectionPool(
        1, 20,
        "postgresql://neondb_owner:npg_U7qWy5IHYgQn@ep-proud-dust-a4v4yjro-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require"
    )
    
    # Create users table if it doesn't exist
    conn = connection_pool.getconn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cur.close()
    connection_pool.putconn(conn)
    print("Successfully connected to PostgreSQL!")
except Exception as e:
    print(f"PostgreSQL Connection Error: {e}")
    connection_pool = None

# ---------- Model ---------- #
try:
    model = load_model("core/phishing_model.h5")
    with open("core/tokenizer.pickle", "rb") as f:
        data = pickle.load(f)
        tokenizer = Tokenizer()
        tokenizer.word_index = data["tokenizer"].word_index
        MAX_LENGTH = data["max_length"]
except Exception as e:
    print(f"Error loading model: {e}")
    model = None
    tokenizer = None
    MAX_LENGTH = 100

# ---------- Utils ---------- #
def generate_otp():
    return str(random.randint(100000, 999999))

def send_email_confirmation(email, otp):
    try:
        subject = 'Your OTP for Signup'
        message = f'Your OTP for signup is: {otp}'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]
        send_mail(subject, message, from_email, recipient_list)
        return True
    except Exception as e:
        print("Email Error:", e)
        return False

# ---------- Views ---------- #
def signup_view(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data

            try:
                conn = connection_pool.getconn()
                cur = conn.cursor()
                
                # Check if email exists
                cur.execute("SELECT email FROM users WHERE email = %s", (data["email"],))
                if cur.fetchone():
                    form.add_error('email', 'This email is already registered. Please use a different email or try logging in.')
                    return render(request, "signup.html", {"form": form})

                # Remove confirm_password before storing
                confirm_password = data.pop('confirm_password', None)
                
                # Encrypt the password before storing
                data["password"] = make_password(data["password"])
                
                request.session["signup_data"] = data
                request.session["resend_count"] = 0
                request.session["otp"] = None
                request.session["otp_time"] = 0

                cur.close()
                connection_pool.putconn(conn)
                return redirect("verify_otp")
            except Exception as e:
                print(f"Database Error: {e}")
                form.add_error(None, "An error occurred. Please try again.")
                return render(request, "signup.html", {"form": form})
    else:
        form = SignupForm()

    return render(request, "signup.html", {"form": form})

def verify_otp_view(request):
    if "signup_data" not in request.session:
        return redirect("signup")

    signup_data = request.session["signup_data"]
    resend_count = request.session.get("resend_count", 0)
    session_otp = request.session.get("otp")
    otp_time = request.session.get("otp_time", 0)

    context = {
        "resend_available": False,
        "resend_count": resend_count,
        "max_resends": 3,
        "error": "",
        "otp_sent": bool(session_otp)
    }

    now = time.time()
    expired = session_otp and now - otp_time > 45
    context["resend_available"] = expired and resend_count < 3

    # First-time visit → Send OTP
    if not session_otp:
        otp = generate_otp()
        request.session["otp"] = otp
        request.session["otp_time"] = now
        if send_email_confirmation(signup_data["email"], otp):
            context["otp_sent"] = True
        else:
            context["error"] = "Failed to send OTP. Please try again."

    if request.method == "POST":
        # Handle resend action
        if "resend" in request.POST:
            if resend_count < 3:
                # Enforce 45s wait before resending
                if now - otp_time < 45:
                    context["error"] = f"Please wait {int(45 - (now - otp_time))} seconds before resending OTP."
                else:
                    otp = generate_otp()
                    request.session["otp"] = otp
                    request.session["otp_time"] = now
                    request.session["resend_count"] += 1
                    if send_email_confirmation(signup_data["email"], otp):
                        context["message"] = "New OTP sent!"
                        context["otp_sent"] = True
                    else:
                        context["error"] = "Failed to send OTP. Please try again."
            else:
                context["error"] = "Maximum resend attempts reached. Try again later."
            return render(request, "verify_otp.html", context)

        # Handle OTP verification
        user_otp = request.POST.get("otp", "").strip()
        if not user_otp:
            context["error"] = "Please enter the OTP."
            return render(request, "verify_otp.html", context)

        if not session_otp or expired:
            context["error"] = "OTP expired. Please resend."
        elif user_otp == session_otp:
            try:
                conn = connection_pool.getconn()
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO users (email, password) VALUES (%s, %s)",
                    (signup_data["email"], signup_data["password"])
                )
                conn.commit()
                cur.close()
                connection_pool.putconn(conn)
                request.session.flush()
                return redirect("login")
            except Exception as e:
                print(f"Database Error: {e}")
                context["error"] = "An error occurred. Please try again."
        else:
            context["error"] = "Invalid OTP."

    return render(request, "verify_otp.html", context)

def login_view(request):
    error = None
    if request.method == "POST":
        try:
            email = request.POST["email"]
            password = request.POST["password"]
            
            conn = connection_pool.getconn()
            cur = conn.cursor()
            cur.execute("SELECT email, password FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()
            connection_pool.putconn(conn)
            
            if user and check_password(password, user[1]):
                request.session["user"] = user[0]
                request.session["is_authenticated"] = True
                return redirect("dashboard")
            else:
                error = "Invalid email or password. Please try again."
        except Exception as e:
            print(f"Database Error: {e}")
            error = "An error occurred. Please try again."
    return render(request, "login.html", {"error": error})

def dashboard(request):
    if not request.session.get("is_authenticated"):
        return redirect("login")
        
    result = None
    if request.method == "POST":
        url = request.POST.get("url")
        if url and model is not None and tokenizer is not None:
            try:
                sequence = tokenizer.texts_to_sequences([url])
                padded = pad_sequences(sequence, maxlen=MAX_LENGTH, padding='post', truncating='post')
                prediction = model.predict(padded)[0][0]
                print(url, prediction)
                result = "Phishing URL ❌" if prediction >= 0.5 else "Safe URL ✅"
            except Exception as e:
                result = f"Error analyzing URL: {str(e)}"
        else:
            result = "Model not available. Please contact administrator."
    return render(request, "dashboard.html", {"result": result})

def logout_view(request):
    request.session.flush()
    return redirect("login")
