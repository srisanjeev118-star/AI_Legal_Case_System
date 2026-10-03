from flask import Flask, render_template, request, redirect, url_for, session

import os
import time
import random
import smtplib

from datetime import datetime, timedelta
from email.message import EmailMessage

from dotenv import load_dotenv


from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error

load_dotenv()


app = Flask(__name__)
UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# ==================================================
# SESSION SECURITY
# ==================================================

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.permanent_session_lifetime = timedelta(minutes=30)


# ==================================================
# FLASK CONFIG
# ==================================================

app.secret_key = os.getenv("SECRET_KEY")


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db_connection():
    try:
        db = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Sanjeev@2007",
            database="legal_case_system"
        )

        if db.is_connected():
            return db

        return None

    except Error as e:
        print("DATABASE CONNECTION ERROR:", e)
        return None


# ==================================================
# LOGIN CHECK
# ==================================================

def is_logged_in():
    return "user_id" in session


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    if is_logged_in():
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))

# ==================================================
# LOGIN WITH 2FA
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if is_logged_in():
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not email or not password:
            return render_template(
                "login.html",
                error="Please enter email and password."
            )

        db = get_db_connection()

        if db is None:
            return render_template(
                "login.html",
                error="Database connection failed."
            )

        cursor = None

        try:

            cursor = db.cursor(dictionary=True)

            cursor.execute("""
                SELECT id, name, email, password, role
                FROM users
                WHERE email = %s
                LIMIT 1
            """, (email,))

            user = cursor.fetchone()

            if user:

                stored_password = user["password"]

                # Check hashed password
                password_valid = False

                try:
                    password_valid = check_password_hash(
                        stored_password,
                        password
                    )
                except Exception:
                    password_valid = False

                # Support old plaintext password once
                if not password_valid and stored_password == password:

                    password_valid = True

                    # Convert old password to secure hash
                    new_hash = generate_password_hash(password)

                    cursor.execute("""
                        UPDATE users
                        SET password = %s
                        WHERE id = %s
                    """, (
                        new_hash,
                        user["id"]
                    ))

                    db.commit()

                if password_valid:

                    # Generate 6 digit OTP
                    otp = str(
                        random.randint(100000, 999999)
                    )

                    expiry = (
                        datetime.now()
                        + timedelta(minutes=5)
                    )

                    session["2fa_user_id"] = user["id"]
                    session["2fa_user_name"] = user["name"]
                    session["2fa_user_email"] = user["email"]
                    session["2fa_user_role"] = user["role"]
                    session["2fa_otp"] = otp
                    session["2fa_otp_expiry"] = expiry.isoformat()

                    sender_email = os.getenv("MAIL_USERNAME")
                    sender_password = os.getenv("MAIL_PASSWORD")

                    if not sender_email or not sender_password:
                        return render_template(
                            "login.html",
                            error="Email settings are missing in .env"
                        )

                    msg = EmailMessage()

                    msg["Subject"] = (
                        "Login OTP - AI Legal Case Management System"
                    )

                    msg["From"] = sender_email
                    msg["To"] = email

                    msg.set_content(
                        f"""Your Login OTP is:

{otp}

This OTP is valid for 5 minutes.

Do not share this OTP with anyone.
"""
                    )

                    with smtplib.SMTP(
                        "smtp.gmail.com",
                        587
                    ) as smtp:

                        smtp.starttls()

                        smtp.login(
                            sender_email,
                            sender_password
                        )

                        smtp.send_message(msg)

                    return redirect(
                        url_for("verify_2fa")
                    )

            return render_template(
                "login.html",
                error="Invalid email or password."
            )

        except Exception as e:

            print("LOGIN ERROR:", e)

            return render_template(
                "login.html",
                error="Login failed. Please try again."
            )

        finally:

            if cursor:
                cursor.close()

            db.close()

    return render_template("login.html")


# ==================================================
# VERIFY 2FA OTP
# ==================================================

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():

    if "2fa_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        entered_otp = request.form.get(
            "otp",
            ""
        ).strip()

        saved_otp = session.get("2fa_otp")
        expiry_string = session.get("2fa_otp_expiry")

        if not saved_otp or not expiry_string:
            return render_template(
                "verify_2fa.html",
                error="OTP expired. Please login again."
            )

        try:
            expiry = datetime.fromisoformat(
                expiry_string
            )
        except ValueError:
            return render_template(
                "verify_2fa.html",
                error="Invalid OTP session."
            )

        if datetime.now() > expiry:

            session.pop("2fa_otp", None)
            session.pop("2fa_otp_expiry", None)

            return render_template(
                "verify_2fa.html",
                error="OTP expired. Please login again."
            )

        if entered_otp != saved_otp:
            return render_template(
                "verify_2fa.html",
                error="Invalid OTP."
            )

        # Complete login
        session["user_id"] = session["2fa_user_id"]
        session["user_name"] = session["2fa_user_name"]
        session["user_email"] = session["2fa_user_email"]
        session["user_role"] = session["2fa_user_role"]

        # Clear temporary 2FA data
        session.pop("2fa_user_id", None)
        session.pop("2fa_user_name", None)
        session.pop("2fa_user_email", None)
        session.pop("2fa_user_role", None)
        session.pop("2fa_otp", None)
        session.pop("2fa_otp_expiry", None)

        return redirect(
            url_for("dashboard")
        )

    return render_template("verify_2fa.html")


# ==================================================
# FORGOT PASSWORD
# ==================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if is_logged_in():
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip()

        if not email:
            return render_template(
                "forgot_password.html",
                error="Please enter your email address."
            )

        db = get_db_connection()

        if db is None:
            return render_template(
                "forgot_password.html",
                error="Database connection failed."
            )

        cursor = None

        try:

            cursor = db.cursor(dictionary=True)

            cursor.execute("""
                SELECT id, name, email
                FROM users
                WHERE email = %s
                LIMIT 1
            """, (email,))

            user = cursor.fetchone()

            if not user:
                return render_template(
                    "forgot_password.html",
                    error="No account found with this email."
                )

            otp = str(
                random.randint(100000, 999999)
            )

            expiry = (
                datetime.now()
                + timedelta(minutes=5)
            )

            session["reset_user_id"] = user["id"]
            session["reset_email"] = user["email"]
            session["reset_otp"] = otp
            session["reset_otp_expiry"] = expiry.isoformat()

            sender_email = os.getenv("MAIL_USERNAME")
            sender_password = os.getenv("MAIL_PASSWORD")

            if not sender_email or not sender_password:
                return render_template(
                    "forgot_password.html",
                    error="Email settings are missing in .env"
                )

            msg = EmailMessage()

            msg["Subject"] = (
                "Password Reset OTP - "
                "AI Legal Case Management System"
            )

            msg["From"] = sender_email
            msg["To"] = user["email"]

            msg.set_content(
                f"""Hello {user["name"]},

Your password reset OTP is:

{otp}

This OTP is valid for 5 minutes.

If you did not request this password reset,
please ignore this email.
"""
            )

            with smtplib.SMTP(
                "smtp.gmail.com",
                587
            ) as smtp:

                smtp.starttls()

                smtp.login(
                    sender_email,
                    sender_password
                )

                smtp.send_message(msg)

            return redirect(
                url_for("verify_reset_otp")
            )

        except Exception as e:

            print("FORGOT PASSWORD ERROR:", e)

            return render_template(
                "forgot_password.html",
                error="Unable to send OTP email."
            )

        finally:

            if cursor:
                cursor.close()

            db.close()

    return render_template("forgot_password.html")


# ==================================================
# VERIFY RESET OTP
# ==================================================

@app.route("/verify-reset-otp", methods=["GET", "POST"])
def verify_reset_otp():

    if "reset_user_id" not in session:
        return redirect(
            url_for("forgot_password")
        )

    if request.method == "POST":

        entered_otp = request.form.get(
            "otp",
            ""
        ).strip()

        saved_otp = session.get("reset_otp")
        expiry_string = session.get(
            "reset_otp_expiry"
        )

        if not saved_otp or not expiry_string:
            return render_template(
                "verify_reset_otp.html",
                error="OTP session expired."
            )

        try:

            expiry = datetime.fromisoformat(
                expiry_string
            )

        except ValueError:

            return render_template(
                "verify_reset_otp.html",
                error="Invalid OTP session."
            )

        if datetime.now() > expiry:

            session.pop("reset_otp", None)
            session.pop("reset_otp_expiry", None)

            return render_template(
                "verify_reset_otp.html",
                error="OTP expired. Please try again."
            )

        if entered_otp != saved_otp:

            return render_template(
                "verify_reset_otp.html",
                error="Invalid OTP."
            )

        session["reset_verified"] = True

        session.pop("reset_otp", None)
        session.pop("reset_otp_expiry", None)

        return redirect(
            url_for("reset_password")
        )

    return render_template(
        "verify_reset_otp.html"
    )
# ==================================================
# REGISTER
# ==================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if is_logged_in():
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not name or not email or not password:
            return render_template(
                "register.html",
                error="Please fill all fields."
            )

        if len(password) < 6:
            return render_template(
                "register.html",
                error="Password must contain at least 6 characters."
            )

        db = get_db_connection()

        if db is None:
            return render_template(
                "register.html",
                error="Database connection failed."
            )

        cursor = None

        try:
            cursor = db.cursor(dictionary=True)

            # Check existing email
            cursor.execute("""
                SELECT id
                FROM users
                WHERE email = %s
                LIMIT 1
            """, (email,))

            existing_user = cursor.fetchone()

            if existing_user:
                return render_template(
                    "register.html",
                    error="Email already registered."
                )

            # Secure password hash
            hashed_password = generate_password_hash(password)

            cursor.execute("""
                INSERT INTO users
                (name, email, password, role)
                VALUES (%s, %s, %s, %s)
            """, (
                name,
                email,
                hashed_password,
                "User"
            ))

            db.commit()

            return redirect(
                url_for("login")
            )

        except Error as e:

            db.rollback()

            print("REGISTER ERROR:", e)

            return render_template(
                "register.html",
                error="Registration failed."
            )

        finally:

            if cursor:
                cursor.close()

            db.close()

    return render_template("register.html")

# ==================================================
# CHANGE PASSWORD
# ==================================================

@app.route("/change-password", methods=["GET", "POST"])
def change_password():

    if not is_logged_in():
        return redirect(url_for("login"))

    if request.method == "POST":

        current_password = request.form.get(
            "current_password",
            ""
        ).strip()

        new_password = request.form.get(
            "new_password",
            ""
        ).strip()

        confirm_password = request.form.get(
            "confirm_password",
            ""
        ).strip()

        # Required fields
        if not current_password or not new_password or not confirm_password:

            return render_template(
                "change_password.html",
                error="Please fill all password fields."
            )

        # Minimum password length
        if len(new_password) < 6:

            return render_template(
                "change_password.html",
                error="New password must contain at least 6 characters."
            )

        # Confirm password
        if new_password != confirm_password:

            return render_template(
                "change_password.html",
                error="New passwords do not match."
            )

        # Prevent same password
        if current_password == new_password:

            return render_template(
                "change_password.html",
                error="New password must be different from current password."
            )

        db = get_db_connection()

        if db is None:

            return render_template(
                "change_password.html",
                error="Database connection failed."
            )

        cursor = None

        try:

            cursor = db.cursor(dictionary=True)

            # Get logged-in user
            cursor.execute("""
                SELECT id, password
                FROM users
                WHERE id = %s
                LIMIT 1
            """, (
                session.get("user_id"),
            ))

            user = cursor.fetchone()

            if not user:

                return render_template(
                    "change_password.html",
                    error="User account not found."
                )

            # Verify current password
            try:

                password_valid = check_password_hash(
                    user["password"],
                    current_password
                )

            except Exception:

                password_valid = False

            if not password_valid:

                return render_template(
                    "change_password.html",
                    error="Current password is incorrect."
                )

            # Generate new secure hash
            hashed_password = generate_password_hash(
                new_password
            )

            # Update password
            cursor.execute("""
                UPDATE users
                SET password = %s
                WHERE id = %s
            """, (
                hashed_password,
                session.get("user_id")
            ))

            db.commit()

            # Audit Log
            add_audit_log(
                "Change Password",
                f"Password changed by {session.get('user_name')}"
            )

            return render_template(
                "change_password.html",
                success="Password changed successfully."
            )

        except Error as e:

            db.rollback()

            print("CHANGE PASSWORD ERROR:", e)

            return render_template(
                "change_password.html",
                error="Password change failed. Please try again."
            )

        finally:

            if cursor:
                cursor.close()

            db.close()

    return render_template("change_password.html")
# ==================================================
# RESET PASSWORD
# ==================================================

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    if "reset_user_id" not in session:
        return redirect(url_for("forgot_password"))

    if not session.get("reset_verified"):
        return redirect(url_for("verify_reset_otp"))

    if request.method == "POST":

        password = request.form.get("password", "").strip()

        confirm_password = request.form.get(
            "confirm_password",
            ""
        ).strip()

        if not password or not confirm_password:
            return render_template(
                "reset_password.html",
                error="Please enter both password fields."
            )

        if len(password) < 6:
            return render_template(
                "reset_password.html",
                error="Password must contain at least 6 characters."
            )

        if password != confirm_password:
            return render_template(
                "reset_password.html",
                error="Passwords do not match."
            )

        db = get_db_connection()

        if db is None:
            return render_template(
                "reset_password.html",
                error="Database connection failed."
            )

        cursor = None

        try:

            cursor = db.cursor()

            # Generate secure password hash
            hashed_password = generate_password_hash(password)

            cursor.execute("""
                UPDATE users
                SET password = %s
                WHERE id = %s
            """, (
                hashed_password,
                session["reset_user_id"]
            ))

            db.commit()

            # Clear reset session
            session.pop("reset_user_id", None)
            session.pop("reset_email", None)
            session.pop("reset_verified", None)

            return redirect(
                url_for(
                    "login",
                    reset="success"
                )
            )

        except Error as e:

            db.rollback()

            print("RESET PASSWORD ERROR:", e)

            return render_template(
                "reset_password.html",
                error="Password reset failed: " + str(e)
            )

        finally:

            if cursor:
                cursor.close()

            db.close()

    return render_template("reset_password.html")


# AI DASHBOARD INSIGHTS
# ==================================================

@app.route("/ai-dashboard-insights")
def ai_dashboard_insights():

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        # TOTAL CASES
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM cases
        """)

        total_cases = cursor.fetchone()["total"]

        # TOTAL HEARINGS
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM hearings
        """)

        total_hearings = cursor.fetchone()["total"]

        # TOTAL NOTES
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM case_notes
        """)

        total_notes = cursor.fetchone()["total"]

        # TOTAL DOCUMENTS
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM documents
        """)

        total_documents = cursor.fetchone()["total"]

        # CASE STATUS
        cursor.execute("""
            SELECT
                COALESCE(status, 'Unknown') AS status,
                COUNT(*) AS total
            FROM cases
            GROUP BY status
            ORDER BY total DESC
        """)

        status_data = cursor.fetchall()

        # CASE TYPES
        cursor.execute("""
            SELECT
                COALESCE(case_type, 'Unknown') AS case_type,
                COUNT(*) AS total
            FROM cases
            GROUP BY case_type
            ORDER BY total DESC
        """)

        type_data = cursor.fetchall()

        # CASES WITHOUT DESCRIPTION
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM cases
            WHERE description IS NULL
               OR TRIM(description) = ''
        """)

        missing_descriptions = cursor.fetchone()["total"]

        # CASES WITHOUT HEARINGS
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM cases c
            WHERE NOT EXISTS (
                SELECT 1
                FROM hearings h
                WHERE h.case_id = c.case_id
            )
        """)

        cases_without_hearings = cursor.fetchone()["total"]

        # CASES WITHOUT DOCUMENTS
        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM cases c
            WHERE NOT EXISTS (
                SELECT 1
                FROM documents d
                WHERE d.case_id = c.case_id
            )
        """)

        cases_without_documents = cursor.fetchone()["total"]

        # BUILD LOCAL AI INSIGHTS

        insights = []

        if total_cases == 0:

            insights.append(
                "No cases are currently recorded in the system."
            )

        else:

            insights.append(
                f"The system currently contains {total_cases} case(s)."
            )

        insights.append(
            f"{total_hearings} hearing record(s), "
            f"{total_notes} case note(s), and "
            f"{total_documents} document(s) are recorded."
        )

        if missing_descriptions > 0:

            insights.append(
                f"{missing_descriptions} case(s) do not have "
                "a detailed description."
            )

        if cases_without_hearings > 0:

            insights.append(
                f"{cases_without_hearings} case(s) do not have "
                "any hearing records."
            )

        if cases_without_documents > 0:

            insights.append(
                f"{cases_without_documents} case(s) do not have "
                "associated documents."
            )

        # FOLLOW-UP

        follow_up = [
            "Review cases with missing descriptions.",
            "Check cases without hearing records.",
            "Upload relevant documents where required.",
            "Keep case notes updated after important developments.",
            "Review case status information regularly."
        ]

        # SUMMARY

        summary = f"""
LOCAL AI DASHBOARD INSIGHTS

===========================

SYSTEM OVERVIEW

Total Cases: {total_cases}

Total Hearings: {total_hearings}

Total Case Notes: {total_notes}

Total Documents: {total_documents}


DATA QUALITY

Cases Without Description: {missing_descriptions}

Cases Without Hearings: {cases_without_hearings}

Cases Without Documents: {cases_without_documents}


KEY INSIGHTS

"""

        for item in insights:
            summary += f"• {item}\n"

        summary += """

SUGGESTED FOLLOW-UP

"""

        for item in follow_up:
            summary += f"• {item}\n"

        summary += """

ANALYSIS NOTE

This is a local case-management dashboard analysis.
It does not use an external AI API and is not legal advice.
"""

        return render_template(
            "ai_dashboard_insights.html",
            total_cases=total_cases,
            total_hearings=total_hearings,
            total_notes=total_notes,
            total_documents=total_documents,
            missing_descriptions=missing_descriptions,
            cases_without_hearings=cases_without_hearings,
            cases_without_documents=cases_without_documents,
            status_data=status_data,
            type_data=type_data,
            summary=summary
        )

    except Error as e:

        print("AI DASHBOARD INSIGHTS ERROR:", e)

        return f"AI dashboard insights failed: {e}"

    finally:

        cursor.close()
        db.close()

# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
def dashboard():

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = None

    try:

        cursor = db.cursor(dictionary=True)

        # ------------------------------------------
        # TOTAL USERS
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM users
        """)

        users_count = cursor.fetchone()["total"]


        # ------------------------------------------
        # TOTAL CASES
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM cases
        """)

        cases_count = cursor.fetchone()["total"]


        # ------------------------------------------
        # TOTAL CLIENTS
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM clients
        """)

        clients_count = cursor.fetchone()["total"]


        # ------------------------------------------
        # TOTAL LAWYERS
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM lawyers
        """)

        lawyers_count = cursor.fetchone()["total"]


        # ------------------------------------------
        # TOTAL HEARINGS
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM hearings
        """)

        hearings_count = cursor.fetchone()["total"]


        # ------------------------------------------
        # TOTAL DOCUMENTS
        # ------------------------------------------

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM documents
        """)

        documents_count = cursor.fetchone()["total"]


        # ------------------------------------------
        # RECENT CASES
        # ------------------------------------------

        cursor.execute("""
            SELECT
                c.case_id,
                c.case_number,
                c.title,
                c.description,
                c.case_type,
                c.status,
                c.filing_date,

                COALESCE(cl.name, 'N/A') AS client_name,

                COALESCE(l.name, 'N/A') AS lawyer_name

            FROM cases AS c

            LEFT JOIN clients AS cl
                ON c.client_id = cl.client_id

            LEFT JOIN lawyers AS l
                ON c.lawyer_id = l.lawyer_id

            ORDER BY c.case_id DESC

            LIMIT 10
        """)

        recent_cases = cursor.fetchall()
                # ------------------------------------------
        # UPCOMING HEARINGS
        # ------------------------------------------

        cursor.execute("""
            SELECT
                h.hearing_id,
                h.case_id,
                h.hearing_date,
                h.hearing_time,
                h.court_name,
                h.judge_name,
                c.case_number,
                c.title AS case_title
            FROM hearings h
            LEFT JOIN cases c
                ON h.case_id = c.case_id
            WHERE h.hearing_date >= CURDATE()
            ORDER BY h.hearing_date ASC,
                     h.hearing_time ASC
            LIMIT 5
        """)

        upcoming_hearings = cursor.fetchall()
                # ------------------------------------------
        # CASE STATUS CHART
        # ------------------------------------------

        cursor.execute("""
            SELECT
                status,
                COUNT(*) AS total
            FROM cases
            GROUP BY status
            ORDER BY total DESC
        """)

        status_data = cursor.fetchall()


        # ------------------------------------------
        # CASE TYPE CHART
        # ------------------------------------------

        cursor.execute("""
            SELECT
                case_type,
                COUNT(*) AS total
            FROM cases
            GROUP BY case_type
            ORDER BY total DESC
        """)

        type_data = cursor.fetchall()


        # ------------------------------------------
        # SEND DATA TO DASHBOARD
        # ------------------------------------------

        return render_template(
            "dashboard.html",

            users_count=users_count,
            cases_count=cases_count,
            clients_count=clients_count,
            lawyers_count=lawyers_count,
            hearings_count=hearings_count,
            documents_count=documents_count,

            recent_cases=recent_cases,
            upcoming_hearings=upcoming_hearings,
            status_data=status_data,
            type_data=type_data
        )

    except Error as e:

        print("DASHBOARD ERROR:", e)

        return f"""
        <h2>Dashboard Database Error</h2>
        <p>{e}</p>
        <br>
        <a href="/login">Back to Login</a>
        """

    finally:

        if cursor:
            cursor.close()

        db.close()


# ==================================================
# CASES
# ==================================================

@app.route("/cases")
def cases():

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = None

    try:

        cursor = db.cursor(dictionary=True)

        # -----------------------------
        # SEARCH & FILTER VALUES
        # -----------------------------

        search = request.args.get("search", "").strip()
        case_type = request.args.get("case_type", "").strip()
        selected_status = request.args.get("status", "").strip()
        sort = request.args.get("sort", "newest").strip()

        # -----------------------------
        # GET CASE TYPES
        # -----------------------------

        cursor.execute("""
            SELECT DISTINCT case_type
            FROM cases
            WHERE case_type IS NOT NULL
              AND case_type != ''
            ORDER BY case_type
        """)

        case_types = [
            row["case_type"]
            for row in cursor.fetchall()
        ]

        # -----------------------------
        # GET STATUSES
        # -----------------------------

        cursor.execute("""
            SELECT DISTINCT status
            FROM cases
            WHERE status IS NOT NULL
              AND status != ''
            ORDER BY status
        """)

        statuses = [
            row["status"]
            for row in cursor.fetchall()
        ]
        

        # -----------------------------
        # MAIN CASE QUERY
        # -----------------------------

        query = """
            SELECT
                c.case_id,
                c.case_number,
                c.title,
                c.description,
                c.case_type,
                c.status,
                c.client_id,
                c.lawyer_id,
                c.filing_date,

                COALESCE(cl.name, 'N/A') AS client_name,
                COALESCE(cl.email, 'N/A') AS client_email,
                COALESCE(cl.phone, 'N/A') AS client_phone,

                COALESCE(l.name, 'N/A') AS lawyer_name,
                COALESCE(l.email, 'N/A') AS lawyer_email,
                COALESCE(l.specialization, 'N/A')
                    AS lawyer_specialization

            FROM cases AS c

            LEFT JOIN clients AS cl
                ON c.client_id = cl.client_id

            LEFT JOIN lawyers AS l
                ON c.lawyer_id = l.lawyer_id

            WHERE 1=1
        """

        params = []

        # -----------------------------
        # SEARCH
        # -----------------------------

        if search:
            query += """
                AND (
                    c.case_number LIKE %s
                    OR c.title LIKE %s
                )
            """

            search_value = f"%{search}%"

            params.extend([
                search_value,
                search_value
            ])

        # -----------------------------
        # CASE TYPE FILTER
        # -----------------------------

        if case_type:
            query += """
                AND c.case_type = %s
            """

            params.append(case_type)

        # -----------------------------
        # STATUS FILTER
        # -----------------------------

        if selected_status:
            query += """
                AND c.status = %s
            """

            params.append(selected_status)

        # -----------------------------
        # SORTING
        # -----------------------------

        if sort == "oldest":

            query += """
                ORDER BY c.filing_date ASC, c.case_id ASC
            """

        else:

            query += """
                ORDER BY c.filing_date DESC, c.case_id DESC
            """

        # -----------------------------
        # EXECUTE
        # -----------------------------

        cursor.execute(query, tuple(params))

        cases_data = cursor.fetchall()

        # -----------------------------
        # SEND DATA TO TEMPLATE
        # -----------------------------

        return render_template(
            "cases.html",
            cases=cases_data,
            case_types=case_types,
            statuses=statuses,
            search=search,
            case_type=case_type,
            selected_status=selected_status,
            sort=sort,
            error=None
        )

    except Error as e:

        print("CASES ERROR:", e)

        return render_template(
            "cases.html",
            cases=[],
            case_types=[],
            statuses=[],
            search=search,
            case_type=case_type,
            selected_status=selected_status,
            sort=sort,
            error=str(e)
        )

    finally:

        if cursor:
            cursor.close()

        db.close()

# ==================================================
# ADD CASE
# ==================================================

@app.route("/add-case", methods=["GET", "POST"])
def add_case():

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        # Get clients
        cursor.execute("""
            SELECT client_id, name
            FROM clients
            ORDER BY name
        """)

        clients = cursor.fetchall()

        # Get lawyers
        cursor.execute("""
            SELECT lawyer_id, name
            FROM lawyers
            ORDER BY name
        """)

        lawyers = cursor.fetchall()

        # When Add Case form is submitted
        if request.method == "POST":

            # --------------------------------------
            # GET FORM DATA
            # --------------------------------------

            case_number = request.form.get(
                "case_number", ""
            ).strip()

            title = request.form.get(
                "title", ""
            ).strip()

            description = request.form.get(
                "description", ""
            ).strip()

            case_type = request.form.get(
                "case_type", ""
            ).strip()

            status = request.form.get(
                "status", ""
            ).strip()

            client_id = request.form.get(
                "client_id", ""
            ).strip()

            lawyer_id = request.form.get(
                "lawyer_id", ""
            ).strip()

            filing_date = request.form.get(
                "filing_date", ""
            ).strip()

            # --------------------------------------
            # REQUIRED FIELD VALIDATION
            # --------------------------------------

            if not case_number:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Case number is required."
                )

            if not title:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Case title is required."
                )

            if not case_type:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Case type is required."
                )

            if not status:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Case status is required."
                )

            if not client_id:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Please select a client."
                )

            if not lawyer_id:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Please select a lawyer."
                )

            if not filing_date:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Filing date is required."
                )

            # --------------------------------------
            # LENGTH VALIDATION
            # --------------------------------------

            if len(case_number) > 50:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Case number is too long."
                )

            if len(title) > 255:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Case title is too long."
                )

            if len(description) > 5000:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Description is too long."
                )

            if len(case_type) > 100:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Case type is too long."
                )

            if len(status) > 50:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Status is too long."
                )

            # --------------------------------------
            # VALIDATE CLIENT ID
            # --------------------------------------

            if not client_id.isdigit():
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Invalid client selected."
                )

            # --------------------------------------
            # VALIDATE LAWYER ID
            # --------------------------------------

            if not lawyer_id.isdigit():
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Invalid lawyer selected."
                )

            # --------------------------------------
            # CHECK CLIENT EXISTS
            # --------------------------------------

            cursor.execute("""
                SELECT client_id
                FROM clients
                WHERE client_id = %s
                LIMIT 1
            """, (client_id,))

            client_exists = cursor.fetchone()

            if not client_exists:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Selected client does not exist."
                )

            # --------------------------------------
            # CHECK LAWYER EXISTS
            # --------------------------------------

            cursor.execute("""
                SELECT lawyer_id
                FROM lawyers
                WHERE lawyer_id = %s
                LIMIT 1
            """, (lawyer_id,))

            lawyer_exists = cursor.fetchone()

            if not lawyer_exists:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Selected lawyer does not exist."
                )

            # --------------------------------------
            # CHECK DUPLICATE CASE NUMBER
            # --------------------------------------

            cursor.execute("""
                SELECT case_id
                FROM cases
                WHERE case_number = %s
                LIMIT 1
            """, (case_number,))

            existing_case = cursor.fetchone()

            if existing_case:
                return render_template(
                    "add_case.html",
                    clients=clients,
                    lawyers=lawyers,
                    error="Case number already exists."
                )

            # --------------------------------------
            # INSERT NEW CASE
            # --------------------------------------

            cursor.execute("""
                INSERT INTO cases
                (
                    case_number,
                    title,
                    description,
                    case_type,
                    status,
                    client_id,
                    lawyer_id,
                    filing_date
                )
                VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                case_number,
                title,
                description,
                case_type,
                status,
                client_id,
                lawyer_id,
                filing_date
            ))

            db.commit()

            # --------------------------------------
            # AUDIT LOG
            # --------------------------------------

            add_audit_log(
                "Add Case",
                f"Case {case_number} added by "
                f"{session.get('user_name')}"
            )

            return redirect(
                url_for("cases")
            )

        # ------------------------------------------
        # SHOW ADD CASE PAGE
        # ------------------------------------------

        return render_template(
            "add_case.html",
            clients=clients,
            lawyers=lawyers
        )

    except Error as e:

        db.rollback()

        print(
            "ADD CASE ERROR:",
            e
        )

        return render_template(
            "add_case.html",
            clients=clients,
            lawyers=lawyers,
            error="Unable to add case. Please try again."
        )

    finally:

        cursor.close()
        db.close()


# ==================================================
# AUDIT LOG FUNCTION
# ==================================================

def add_audit_log(action, details):

    if "user_id" not in session:
        return

    db = get_db_connection()

    if db is None:
        return

    cursor = db.cursor()

    try:

        cursor.execute("""
            INSERT INTO audit_logs
            (
                user_id,
                action,
                details
            )
            VALUES
            (%s, %s, %s)
        """, (
            session.get("user_id"),
            action,
            details
        ))

        db.commit()

    except Error as e:

        db.rollback()

        print("AUDIT LOG ERROR:", e)

    finally:

        cursor.close()
        db.close()


# ==================================================
# EDIT CASE
# ==================================================

@app.route("/edit-case/<int:case_id>", methods=["GET", "POST"])
def edit_case(case_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        # Get case
        cursor.execute("""
            SELECT *
            FROM cases
            WHERE case_id = %s
        """, (case_id,))

        case = cursor.fetchone()

        if not case:
            return "Case not found", 404

        # Get clients
        cursor.execute("""
            SELECT client_id, name
            FROM clients
            ORDER BY name
        """)

        clients = cursor.fetchall()

        # Get lawyers
        cursor.execute("""
            SELECT lawyer_id, name
            FROM lawyers
            ORDER BY name
        """)

        lawyers = cursor.fetchall()

        # When Edit form is submitted
        if request.method == "POST":

            case_number = request.form.get("case_number")
            title = request.form.get("title")
            description = request.form.get("description")
            case_type = request.form.get("case_type")
            status = request.form.get("status")
            client_id = request.form.get("client_id")
            lawyer_id = request.form.get("lawyer_id")
            filing_date = request.form.get("filing_date")

            # Update case
            cursor.execute("""
                UPDATE cases
                SET
                    case_number = %s,
                    title = %s,
                    description = %s,
                    case_type = %s,
                    status = %s,
                    client_id = %s,
                    lawyer_id = %s,
                    filing_date = %s
                WHERE case_id = %s
            """, (
                case_number,
                title,
                description,
                case_type,
                status,
                client_id,
                lawyer_id,
                filing_date,
                case_id
            ))

            db.commit()

            # Audit log - Edit Case
            add_audit_log(
                "Edit Case",
                f"Case ID {case_id} edited by {session.get('user_name')}"
            )

            return redirect(url_for("cases"))

        # Open edit page
        return render_template(
            "edit_case.html",
            case=case,
            clients=clients,
            lawyers=lawyers
        )

    except Error as e:

        db.rollback()

        return render_template(
            "edit_case.html",
            case=case,
            clients=clients,
            lawyers=lawyers,
            error=str(e)
        )

    finally:

        cursor.close()
        db.close()


# ==================================================
# DELETE CASE
# ==================================================

@app.route("/delete-case/<int:case_id>", methods=["POST"])
def delete_case(case_id):

    # Check login
    if not is_logged_in():
        return redirect(url_for("login"))

    # Admin only permission
    if session.get("user_role") != "Admin":
        return "Access denied. Admin permission required.", 403

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor()

    try:

        # Delete related case notes
        cursor.execute("""
            DELETE FROM case_notes
            WHERE case_id = %s
        """, (case_id,))

        # Delete related documents
        cursor.execute("""
            DELETE FROM documents
            WHERE case_id = %s
        """, (case_id,))

        # Delete related hearings
        cursor.execute("""
            DELETE FROM hearings
            WHERE case_id = %s
        """, (case_id,))

        # Delete the case
        cursor.execute("""
            DELETE FROM cases
            WHERE case_id = %s
        """, (case_id,))

        # Save changes
        db.commit()

        # Audit log - Delete Case
        add_audit_log(
            "Delete Case",
            f"Case ID {case_id} deleted by {session.get('user_name')}"
        )

        return redirect(url_for("cases"))

    except Error as e:

        db.rollback()

        print("DELETE CASE ERROR:", e)

        return f"Delete case failed: {e}"

    finally:

        cursor.close()
        db.close()
        # ==================================================
# AUDIT LOGS
# ==================================================

@app.route("/audit-logs")
def audit_logs():

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        cursor.execute("""
            SELECT
                audit_logs.id,
                audit_logs.action,
                audit_logs.details,
                audit_logs.created_at,
                users.name AS user_name,
                users.email AS user_email,
                users.role AS user_role
            FROM audit_logs
            LEFT JOIN users
                ON audit_logs.user_id = users.id
            ORDER BY audit_logs.created_at DESC
        """)

        logs = cursor.fetchall()

        return render_template(
            "audit_logs.html",
            logs=logs
        )

    except Error as e:

        print("AUDIT LOGS ERROR:", e)

        return f"Audit logs error: {e}"

    finally:

        cursor.close()
        db.close()
        # ==================================================
# LOCAL AI CASE ANALYSIS
# ==================================================
@app.route("/ai-analyze-case/<int:case_id>")
def ai_analyze_case(case_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

   
        # ------------------------------------------
        # GET CASE INFORMATION
        # ------------------------------------------

        cursor.execute("""
            SELECT
                case_id,
                case_number,
                title,
                description,
                case_type,
                status
            FROM cases
            WHERE case_id = %s
        """, (case_id,))

        case = cursor.fetchone()

        if not case:
            return "Case not found.", 404


        # ------------------------------------------
        # CASE DATA
        # ------------------------------------------

        case_number = case["case_number"] or "N/A"
        title = case["title"] or "Untitled Case"
        description = case["description"] or ""
        case_type = case["case_type"] or "N/A"
        status = case["status"] or "Pending"


        # ------------------------------------------
        # LOCAL CASE SUMMARY
        # ------------------------------------------

        if description.strip():

            short_description = description.strip()

            if len(short_description) > 500:
                short_description = short_description[:500] + "..."

            case_summary = (
                f"This case is identified as {case_number}, titled "
                f"'{title}'. It is classified as {case_type} and is "
                f"currently marked as {status}. Based on the available "
                f"case description: {short_description}"
            )

        else:

            case_summary = (
                f"This case is identified as {case_number}, titled "
                f"'{title}'. The case type is {case_type} and the current "
                f"status is {status}. A detailed case description is not "
                f"available in the database."
            )


        # ------------------------------------------
        # KEY ISSUES
        # ------------------------------------------

        key_issues = []

        if case_type != "N/A":
            key_issues.append(
                f"Case classification: {case_type}"
            )

        if status:
            key_issues.append(
                f"Current case status: {status}"
            )

        if description.strip():
            key_issues.append(
                "Review the facts and information provided in the case description."
            )
        else:
            key_issues.append(
                "Detailed case description is missing."
            )


        # ------------------------------------------
        # IMPORTANT FACTS
        # ------------------------------------------

        important_facts = []

        important_facts.append(
            f"Case Number: {case_number}"
        )

        important_facts.append(
            f"Case Title: {title}"
        )

        important_facts.append(
            f"Case Type: {case_type}"
        )

        important_facts.append(
            f"Current Status: {status}"
        )

        if description.strip():
            important_facts.append(
                f"Available Description: {description.strip()}"
            )
        else:
            important_facts.append(
                "No case description is currently available."
            )


        # ------------------------------------------
        # SUGGESTED NEXT STEPS
        # ------------------------------------------

        next_steps = []

        next_steps.append(
            "Review the case description and verify that the recorded "
            "information is complete."
        )

        next_steps.append(
            "Check whether the relevant case documents have been uploaded "
            "and associated with this case."
        )

        next_steps.append(
            "Review upcoming hearings and update hearing information when necessary."
        )

        next_steps.append(
            "Keep the case status and case notes updated as the case progresses."
        )


        # ------------------------------------------
        # BUILD RESULT
        # ------------------------------------------

        ai_result = f"""
LOCAL AI CASE ANALYSIS
======================

CASE SUMMARY:

{case_summary}


KEY ISSUES:

"""

        for issue in key_issues:
            ai_result += f"• {issue}\n"


        ai_result += """

IMPORTANT FACTS:

"""

        for fact in important_facts:
            ai_result += f"• {fact}\n"


        ai_result += """

SUGGESTED NEXT STEPS:

"""

        for step in next_steps:
            ai_result += f"• {step}\n"


        ai_result += """

ANALYSIS NOTE:

This is a local case-management analysis generated from the information
stored in the system. It does not use an external AI API and should not
be treated as legal advice.

Missing information has not been assumed or invented.
"""


        # ------------------------------------------
        # SHOW ANALYSIS PAGE
        # ------------------------------------------

        return render_template(
            "ai_case_analysis.html",
            case=case,
            ai_result=ai_result
        )


    except Error as e:

        print("LOCAL AI ANALYSIS ERROR:", e)

        return f"AI analysis failed: {e}"


    finally:

        cursor.close()
        db.close()
    # ==================================================
# AI CASE NOTES SUMMARY
# ==================================================

@app.route("/ai-notes-summary/<int:case_id>")
def ai_notes_summary(case_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        cursor.execute("""
            SELECT
                case_id,
                case_number,
                title,
                case_type,
                status
            FROM cases
            WHERE case_id = %s
        """, (case_id,))

        case = cursor.fetchone()

        if not case:
            return "Case not found.", 404

        cursor.execute("""
            SELECT
                note_id,
                note,
                created_at
            FROM case_notes
            WHERE case_id = %s
            ORDER BY created_at DESC
        """, (case_id,))

        notes = cursor.fetchall()

        if not notes:

            summary = """NO CASE NOTES AVAILABLE

There are currently no case notes recorded for this case.

Suggested action:
• Add case notes to maintain important case information.
• Record important developments after hearings or document reviews.
• Keep the notes updated as the case progresses.
"""

        else:

            summary = f"""LOCAL AI CASE NOTES SUMMARY
============================

CASE INFORMATION

Case Number: {case["case_number"] or "N/A"}
Case Title: {case["title"] or "N/A"}
Case Type: {case["case_type"] or "N/A"}
Current Status: {case["status"] or "N/A"}

NOTES OVERVIEW

Total Notes Recorded: {len(notes)}

IMPORTANT NOTES

"""

            for index, item in enumerate(notes, start=1):

                note_text = item["note"] or "No note content available."

                summary += (
                    f"{index}. {note_text}\n"
                    f"   Date: {item['created_at'] or 'N/A'}\n\n"
                )

            summary += """KEY OBSERVATIONS

• Information is based only on notes stored in the system.
• Recent notes are displayed first.
• Important developments should continue to be recorded.

SUGGESTED FOLLOW-UP

• Review the latest case notes.
• Add missing developments or important updates.
• Check related hearings and documents.
• Keep the case status updated.

ANALYSIS NOTE

This is a local case-management summary.
It does not use an external AI API and is not legal advice.
"""

        return render_template(
            "ai_notes_summary.html",
            case=case,
            notes=notes,
            summary=summary
        )

    except Error as e:

        print("AI NOTES SUMMARY ERROR:", e)

        return f"AI notes summary failed: {e}"

    finally:

        cursor.close()
        db.close()
        # ==================================================
# AI HEARING SUMMARY
# ==================================================

@app.route("/ai-hearing-summary/<int:case_id>")
def ai_hearing_summary(case_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        # GET CASE INFORMATION
        cursor.execute("""
            SELECT
                case_id,
                case_number,
                title,
                case_type,
                status
            FROM cases
            WHERE case_id = %s
        """, (case_id,))

        case = cursor.fetchone()

        if not case:
            return "Case not found.", 404


        # GET HEARING INFORMATION
        cursor.execute("""
            SELECT
                hearing_id,
                hearing_date,
                hearing_time,
                court_name,
                judge_name,
                notes
            FROM hearings
            WHERE case_id = %s
            ORDER BY hearing_date DESC, hearing_time DESC
        """, (case_id,))

        hearings = cursor.fetchall()


        # NO HEARINGS
        if not hearings:

            summary = """
NO HEARINGS AVAILABLE

There are currently no hearings recorded for this case.

Suggested action:

• Add the upcoming hearing details.
• Keep court and judge information updated.
• Record important hearing notes after each hearing.
"""


        else:

            total_hearings = len(hearings)

            summary = f"""
LOCAL AI HEARING SUMMARY
========================

CASE INFORMATION

Case Number: {case["case_number"] or "N/A"}
Case Title: {case["title"] or "N/A"}
Case Type: {case["case_type"] or "N/A"}
Current Status: {case["status"] or "N/A"}


HEARING OVERVIEW

Total Hearings Recorded: {total_hearings}


HEARING DETAILS

"""

            for index, hearing in enumerate(hearings, start=1):

                hearing_date = hearing["hearing_date"] or "N/A"
                hearing_time = hearing["hearing_time"] or "N/A"
                court_name = hearing["court_name"] or "N/A"
                judge_name = hearing["judge_name"] or "N/A"
                notes = hearing["notes"] or "No hearing notes available."

                summary += (
                    f"{index}. Hearing Date: {hearing_date}\n"
                    f"   Time: {hearing_time}\n"
                    f"   Court: {court_name}\n"
                    f"   Judge: {judge_name}\n"
                    f"   Notes: {notes}\n\n"
                )


            summary += """
KEY OBSERVATIONS

• Hearing information is based only on records stored in the system.
• Hearings are displayed from most recent to oldest.
• Missing information is shown as N/A.
• Important hearing developments should be recorded in the notes.


SUGGESTED FOLLOW-UP

• Review the latest hearing information.
• Check the next scheduled hearing date.
• Keep court and judge details updated.
• Add important developments to the hearing notes.
• Review related case documents and case notes.


ANALYSIS NOTE

This is a local case-management summary.
It does not use an external AI API and is not legal advice.
"""


        return render_template(
            "ai_hearing_summary.html",
            case=case,
            hearings=hearings,
            summary=summary
        )


    except Error as e:

        print("AI HEARING SUMMARY ERROR:", e)

        return f"AI hearing summary failed: {e}"


    finally:

        cursor.close()
        db.close()
        # ==================================================
# AI CASE TIMELINE
# ==================================================

@app.route("/ai-case-timeline/<int:case_id>")
def ai_case_timeline(case_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        # GET CASE INFORMATION
        cursor.execute("""
            SELECT
                case_id,
                case_number,
                title,
                case_type,
                status,
                filing_date
            FROM cases
            WHERE case_id = %s
        """, (case_id,))

        case = cursor.fetchone()

        if not case:
            return "Case not found.", 404

        # GET CASE NOTES
        cursor.execute("""
            SELECT
                note_id,
                note,
                created_at
            FROM case_notes
            WHERE case_id = %s
            ORDER BY created_at ASC
        """, (case_id,))

        notes = cursor.fetchall()

        # GET HEARINGS
        cursor.execute("""
            SELECT
                hearing_id,
                hearing_date,
                hearing_time,
                court_name,
                judge_name,
                notes
            FROM hearings
            WHERE case_id = %s
            ORDER BY hearing_date ASC, hearing_time ASC
        """, (case_id,))

        hearings = cursor.fetchall()

        # GET DOCUMENTS
        cursor.execute("""
            SELECT
                document_id,
                document_name,
                document_type,
                uploaded_at
            FROM documents
            WHERE case_id = %s
            ORDER BY uploaded_at ASC
        """, (case_id,))

        documents = cursor.fetchall()

        # BUILD TIMELINE
        timeline = []

        # CASE FILING
        if case["filing_date"]:
            timeline.append({
                "date": case["filing_date"],
                "type": "Case Filed",
                "title": "Case Registered",
                "description": (
                    f"Case {case['case_number'] or 'N/A'} "
                    f"was recorded in the system."
                ),
                "icon": "📁"
            })

        # HEARINGS
        for hearing in hearings:

            timeline.append({
                "date": hearing["hearing_date"],
                "type": "Hearing",
                "title": "Court Hearing",
                "description": (
                    f"Court: {hearing['court_name'] or 'N/A'}\n"
                    f"Judge: {hearing['judge_name'] or 'N/A'}\n"
                    f"Time: {hearing['hearing_time'] or 'N/A'}\n"
                    f"Notes: {hearing['notes'] or 'No notes available.'}"
                ),
                "icon": "⚖️"
            })

        # CASE NOTES
        for note in notes:

            timeline.append({
                "date": note["created_at"],
                "type": "Case Note",
                "title": "Case Note Added",
                "description": note["note"] or "No note content available.",
                "icon": "📝"
            })

        # DOCUMENTS
        for document in documents:

            timeline.append({
                "date": document["uploaded_at"],
                "type": "Document",
                "title": "Document Uploaded",
                "description": (
                    f"Document: {document['document_name'] or 'N/A'}\n"
                    f"Type: {document['document_type'] or 'N/A'}"
                ),
                "icon": "📄"
            })

        # SORT TIMELINE
        timeline.sort(
            key=lambda item: str(item["date"] or "")
        )

        # SUMMARY
        total_events = len(timeline)

        summary = f"""
LOCAL AI CASE TIMELINE

======================

CASE INFORMATION

Case Number: {case["case_number"] or "N/A"}
Case Title: {case["title"] or "N/A"}
Case Type: {case["case_type"] or "N/A"}
Current Status: {case["status"] or "N/A"}

TIMELINE OVERVIEW

Total Timeline Events: {total_events}

Case Filing Date: {case["filing_date"] or "N/A"}

Recorded Hearings: {len(hearings)}

Case Notes: {len(notes)}

Documents: {len(documents)}

KEY OBSERVATIONS

• Timeline is generated only from information stored in the system.
• Events are arranged chronologically.
• Missing information is displayed as N/A.
• Case notes, hearings and documents are included when available.

SUGGESTED FOLLOW-UP

• Review the latest timeline event.
• Keep hearing information updated.
• Record important case developments in case notes.
• Upload relevant case documents.
• Keep the case status updated.

ANALYSIS NOTE

This is a local case-management timeline.
It does not use an external AI API and is not legal advice.
"""

        return render_template(
            "ai_case_timeline.html",
            case=case,
            timeline=timeline,
            summary=summary
        )

    except Error as e:

        print("AI CASE TIMELINE ERROR:", e)

        return f"AI case timeline failed: {e}"

    finally:

        cursor.close()
        db.close()
        

       # ==================================================
# CASE DETAILS
# ==================================================

@app.route("/case-details/<int:case_id>")
def case_details(case_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        # -----------------------------
        # CASE DETAILS
        # -----------------------------
        cursor.execute("""
            SELECT
                c.case_id,
                c.case_number,
                c.title,
                c.description,
                c.case_type,
                c.status,
                c.filing_date,

                cl.name AS client_name,
                cl.email AS client_email,
                cl.phone AS client_phone,

                l.name AS lawyer_name,
                l.specialization AS specialization

            FROM cases c

            LEFT JOIN clients cl
                ON c.client_id = cl.client_id

            LEFT JOIN lawyers l
                ON c.lawyer_id = l.lawyer_id

            WHERE c.case_id = %s
        """, (case_id,))

        case = cursor.fetchone()

        if case is None:
            return "Case not found.", 404


        # -----------------------------
        # CASE NOTES
        # -----------------------------
        cursor.execute("""
            SELECT
                note_id,
                case_id,
                note,
                created_at

            FROM case_notes

            WHERE case_id = %s

            ORDER BY created_at DESC
        """, (case_id,))

        notes = cursor.fetchall()
        


        # -----------------------------
        # HEARINGS
        # -----------------------------
        cursor.execute("""
            SELECT
                hearing_id,
                hearing_date,
                hearing_time,
                court_name,
                judge_name,
                notes

            FROM hearings

            WHERE case_id = %s

            ORDER BY hearing_date DESC,
                     hearing_time DESC
        """, (case_id,))

        hearings_data = cursor.fetchall()


        # -----------------------------
        # DOCUMENTS
        # -----------------------------
        cursor.execute("""
            SELECT
                document_id,
                document_name,
                document_type,
                file_path,
                uploaded_at

            FROM documents

            WHERE case_id = %s

            ORDER BY uploaded_at DESC
        """, (case_id,))

        documents_data = cursor.fetchall()


        return render_template(
            "case_details.html",
            case=case,
            notes=notes,
            hearings=hearings_data,
            documents=documents_data
        )


    except Error as e:

        print("CASE DETAILS ERROR:", e)

        return f"Error loading case details: {e}"


    finally:

        cursor.close()
        db.close() 
        # ==================================================
# ADD CASE NOTE
# ==================================================

@app.route("/add-note/<int:case_id>", methods=["POST"])
def add_note(case_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    note = request.form.get("note", "").strip()

    if not note:
        return redirect(url_for(
            "case_details",
            case_id=case_id
        ))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor()

    try:

        cursor.execute("""
            INSERT INTO case_notes
            (
                case_id,
                note
            )
            VALUES (%s, %s)
        """, (
            case_id,
            note
        ))

        db.commit()

        return redirect(url_for(
            "case_details",
            case_id=case_id
        ))

    except Error as e:

        db.rollback()

        print("ADD NOTE ERROR:", e)

        return f"Add note failed: {e}"

    finally:

        cursor.close()
        db.close()
        # ==================================================
# EDIT CASE NOTE
# ==================================================

@app.route("/edit-note/<int:note_id>", methods=["POST"])
def edit_note(note_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    note = request.form.get("note", "").strip()

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        cursor.execute("""
            SELECT case_id
            FROM case_notes
            WHERE note_id = %s
        """, (note_id,))

        existing_note = cursor.fetchone()

        if existing_note is None:
            return "Note not found.", 404

        case_id = existing_note["case_id"]

        cursor.execute("""
            UPDATE case_notes
            SET note = %s
            WHERE note_id = %s
        """, (
            note,
            note_id
        ))

        db.commit()

        return redirect(url_for(
            "case_details",
            case_id=case_id
        ))

    except Error as e:

        db.rollback()

        print("EDIT NOTE ERROR:", e)

        return f"Edit note failed: {e}"

    finally:

        cursor.close()
        db.close()
        # ==================================================
# DELETE CASE NOTE
# ==================================================

@app.route("/delete-note/<int:note_id>", methods=["POST"])
def delete_note(note_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        cursor.execute("""
            SELECT case_id
            FROM case_notes
            WHERE note_id = %s
        """, (note_id,))

        existing_note = cursor.fetchone()

        if existing_note is None:
            return "Note not found.", 404

        case_id = existing_note["case_id"]

        cursor.execute("""
            DELETE FROM case_notes
            WHERE note_id = %s
        """, (note_id,))

        db.commit()

        return redirect(url_for(
            "case_details",
            case_id=case_id
        ))

    except Error as e:

        db.rollback()

        print("DELETE NOTE ERROR:", e)

        return f"Delete note failed: {e}"

    finally:

        cursor.close()
        db.close()

        # ==================================================
# ADD HEARING
# ==================================================

@app.route("/add-hearing", methods=["GET", "POST"])
def add_hearing():

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        # Load cases for dropdown
        cursor.execute("""
            SELECT case_id, case_number, title
            FROM cases
            ORDER BY case_id DESC
        """)

        cases = cursor.fetchall()

        # Save hearing
        if request.method == "POST":

            case_id = request.form.get("case_id")
            hearing_date = request.form.get("hearing_date")
            hearing_time = request.form.get("hearing_time")
            court_name = request.form.get("court_name")
            judge_name = request.form.get("judge_name")
            notes = request.form.get("notes")

            cursor.execute("""
                INSERT INTO hearings
                (
                    case_id,
                    hearing_date,
                    hearing_time,
                    court_name,
                    judge_name,
                    notes
                )
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                case_id,
                hearing_date,
                hearing_time,
                court_name,
                judge_name,
                notes
            ))

            db.commit()

            return redirect(url_for(
                "case_details",
                case_id=case_id
            ))

        return render_template(
            "add_hearing.html",
            cases=cases
        )

    except Error as e:

        db.rollback()

        print("ADD HEARING ERROR:", e)

        return f"Add hearing failed: {e}"

    finally:

        cursor.close()
        db.close()
        # ==================================================
# HEARINGS
# ==================================================

@app.route("/hearings")
def hearings():

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        cursor.execute("""
            SELECT
                h.hearing_id,
                h.case_id,
                h.hearing_date,
                h.hearing_time,
                h.court_name,
                h.judge_name,
                h.notes,

                c.case_number,
                c.title AS case_title

            FROM hearings h

            LEFT JOIN cases c
                ON h.case_id = c.case_id

            ORDER BY
                h.hearing_date DESC,
                h.hearing_time DESC
        """)

        hearings = cursor.fetchall()

        return render_template(
            "hearings.html",
            hearings=hearings
        )

    except Error as e:

        print("HEARINGS ERROR:", e)

        return f"Error loading hearings: {e}"

    finally:

        cursor.close()
        db.close()
        # ==================================================
# EDIT HEARING
# ==================================================

@app.route("/edit-hearing/<int:hearing_id>", methods=["GET", "POST"])
def edit_hearing(hearing_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    # ADMIN + NORMAL USER CAN EDIT
    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        # Get hearing
        cursor.execute("""
            SELECT *
            FROM hearings
            WHERE hearing_id = %s
        """, (hearing_id,))

        hearing = cursor.fetchone()

        if hearing is None:
            return "Hearing not found.", 404

        # Get cases
        cursor.execute("""
            SELECT
                case_id,
                case_number,
                title
            FROM cases
            ORDER BY case_id DESC
        """)

        cases = cursor.fetchall()

        # Update hearing
        if request.method == "POST":

            case_id = request.form.get("case_id")
            hearing_date = request.form.get("hearing_date")
            hearing_time = request.form.get("hearing_time")
            court_name = request.form.get("court_name")
            judge_name = request.form.get("judge_name")
            notes = request.form.get("notes")

            cursor.execute("""
                UPDATE hearings
                SET
                    case_id = %s,
                    hearing_date = %s,
                    hearing_time = %s,
                    court_name = %s,
                    judge_name = %s,
                    notes = %s
                WHERE hearing_id = %s
            """, (
                case_id,
                hearing_date,
                hearing_time,
                court_name,
                judge_name,
                notes,
                hearing_id
            ))

            db.commit()

            # Audit Log
            add_audit_log(
                "Edit Hearing",
                f"Hearing ID {hearing_id} edited by {session.get('user_name')}"
            )

            return redirect(url_for("hearings"))

        return render_template(
            "edit_hearing.html",
            hearing=hearing,
            cases=cases
        )

    except Error as e:

        db.rollback()

        print("EDIT HEARING ERROR:", e)

        return f"Edit hearing failed: {e}"

    finally:

        cursor.close()
        db.close()


# ==================================================
# DELETE HEARING
# ==================================================

@app.route("/delete-hearing/<int:hearing_id>", methods=["POST"])
def delete_hearing(hearing_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    # ADMIN ONLY
    if session.get("user_role") != "Admin":
        return "Access denied. Admin permission required.", 403

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor()

    try:

        cursor.execute("""
            DELETE FROM hearings
            WHERE hearing_id = %s
        """, (hearing_id,))

        db.commit()

        # Audit Log
        add_audit_log(
            "Delete Hearing",
            f"Hearing ID {hearing_id} deleted by {session.get('user_name')}"
        )

        return redirect(url_for("hearings"))

    except Error as e:

        db.rollback()

        print("DELETE HEARING ERROR:", e)

        return f"Delete hearing failed: {e}"

    finally:

        cursor.close()
        db.close()
        # ==================================================


    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        # Get all cases
        cursor.execute("""
            SELECT case_id, case_number, title
            FROM cases
            ORDER BY case_id DESC
        """)

        cases_data = cursor.fetchall()

        if request.method == "POST":

            case_id = request.form.get("case_id")
            hearing_date = request.form.get("hearing_date")
            hearing_time = request.form.get("hearing_time")
            court_name = request.form.get("court_name")
            judge_name = request.form.get("judge_name")
            notes = request.form.get("notes")

            cursor.execute("""
                INSERT INTO hearings
                (
                    case_id,
                    hearing_date,
                    hearing_time,
                    court_name,
                    judge_name,
                    notes
                )
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                case_id,
                hearing_date,
                hearing_time,
                court_name,
                judge_name,
                notes
            ))

            db.commit()

            return redirect(url_for("hearings"))

        return render_template(
            "add_hearing.html",
            cases=cases_data
        )

    except Error as e:

        db.rollback()

        print("ADD HEARING ERROR:", e)

        return f"Add hearing failed: {e}"

    finally:

        cursor.close()
        db.close()
    
# ==================================================
# DOCUMENTS
# ==================================================

@app.route("/documents")
def documents():

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = None

    try:

        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                d.document_id,
                d.case_id,
                d.document_name,
                d.document_type,
                d.file_path,
                d.uploaded_at,

                c.case_number,
                c.title AS case_title

            FROM documents AS d

            LEFT JOIN cases AS c
                ON d.case_id = c.case_id

            ORDER BY d.document_id DESC
        """)

        documents_data = cursor.fetchall()

        return render_template(
            "documents.html",
            documents=documents_data,
            error=None
        )

    except Error as e:

        print("DOCUMENTS ERROR:", e)

        return render_template(
            "documents.html",
            documents=[],
            error=str(e)
        )

    finally:

        if cursor:
            cursor.close()

        db.close()
        # ==================================================
# UPLOAD DOCUMENT
# ==================================================

@app.route("/upload-document", methods=["GET", "POST"])
def upload_document():

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        # ------------------------------------------
        # GET CASE LIST
        # ------------------------------------------

        cursor.execute("""
            SELECT case_id, case_number, title
            FROM cases
            ORDER BY case_id DESC
        """)

        cases = cursor.fetchall()

        # ------------------------------------------
        # UPLOAD DOCUMENT
        # ------------------------------------------

        if request.method == "POST":

            case_id = request.form.get("case_id", "").strip()
            document_name = request.form.get(
                "document_name",
                ""
            ).strip()
            document_type = request.form.get(
                "document_type",
                ""
            ).strip()

            file = request.files.get("file")

            # --------------------------------------
            # BASIC VALIDATION
            # --------------------------------------

            if not case_id:
                return "Please select a case."

            if not document_name:
                return "Please enter document name."

            if not file or file.filename == "":
                return "Please select a file."

            # --------------------------------------
            # ALLOWED FILE TYPES
            # --------------------------------------

            allowed_extensions = {
                "pdf",
                "doc",
                "docx",
                "txt",
                "jpg",
                "jpeg",
                "png"
            }

            original_filename = file.filename or ""

            if "." not in original_filename:
                return "File type not allowed."

            file_extension = (
                original_filename
                .rsplit(".", 1)[1]
                .lower()
            )

            if file_extension not in allowed_extensions:
                return (
                    "File type not allowed. "
                    "Allowed: PDF, DOC, DOCX, TXT, "
                    "JPG, JPEG, PNG."
                )

            # --------------------------------------
            # FILE SIZE LIMIT - 10 MB
            # --------------------------------------

            file.seek(0, os.SEEK_END)

            file_size = file.tell()

            file.seek(0)

            max_file_size = 10 * 1024 * 1024

            if file_size > max_file_size:
                return (
                    "File too large. "
                    "Maximum allowed size is 10 MB."
                )

            # --------------------------------------
            # SECURE FILE NAME
            # --------------------------------------

            filename = secure_filename(original_filename)

            if not filename:
                return "Invalid file name."

            # --------------------------------------
            # UNIQUE FILE NAME
            # --------------------------------------

            unique_filename = (
                str(int(time.time()))
                + "_"
                + filename
            )

            # --------------------------------------
            # UPLOAD PATH
            # --------------------------------------

            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                unique_filename
            )

            # --------------------------------------
            # SAVE FILE
            # --------------------------------------

            file.save(file_path)

            # --------------------------------------
            # SAVE DOCUMENT DETAILS
            # --------------------------------------

            cursor.execute("""
                INSERT INTO documents
                (
                    case_id,
                    document_name,
                    document_type,
                    file_path
                )
                VALUES (%s, %s, %s, %s)
            """, (
                case_id,
                document_name,
                document_type,
                file_path
            ))

            db.commit()

            # --------------------------------------
            # AUDIT LOG
            # --------------------------------------

            add_audit_log(
                "Upload Document",
                f"Document '{document_name}' uploaded "
                f"for Case ID {case_id} "
                f"by {session.get('user_name')}"
            )

            # --------------------------------------
            # SUCCESS
            # --------------------------------------

            return redirect(
                url_for("documents")
            )

        # ------------------------------------------
        # SHOW UPLOAD PAGE
        # ------------------------------------------

        return render_template(
            "upload_document.html",
            cases=cases
        )

    except Error as e:

        db.rollback()

        print(
            "UPLOAD DOCUMENT ERROR:",
            e
        )

        return (
            f"Upload document failed: {e}"
        )

    except Exception as e:

        db.rollback()

        print(
            "UPLOAD DOCUMENT SECURITY ERROR:",
            e
        )

        return (
            "An error occurred while uploading "
            "the document."
        )

    finally:

        cursor.close()
        db.close()
# ==================================================
# DOWNLOAD / OPEN DOCUMENT
# ==================================================

@app.route("/document/<int:document_id>")
def view_document(document_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        cursor.execute("""
            SELECT file_path
            FROM documents
            WHERE document_id = %s
        """, (document_id,))

        document = cursor.fetchone()

        if document is None:
            return "Document not found."

        file_path = document["file_path"]

        if not os.path.exists(file_path):
            return "File not found on server."

        from flask import send_file

        return send_file(
            file_path,
            as_attachment=False
        )

    except Error as e:

        print("VIEW DOCUMENT ERROR:", e)

        return f"Document error: {e}"

    finally:

        cursor.close()
        db.close()


# ==================================================
# DELETE DOCUMENT
# ==================================================

@app.route("/delete-document/<int:document_id>", methods=["POST"])
def delete_document(document_id):

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        cursor.execute("""
            SELECT file_path
            FROM documents
            WHERE document_id = %s
        """, (document_id,))

        document = cursor.fetchone()

        if document is None:
            return "Document not found."

        file_path = document["file_path"]

        cursor.execute("""
            DELETE FROM documents
            WHERE document_id = %s
        """, (document_id,))

        db.commit()

        if file_path and os.path.exists(file_path):
            os.remove(file_path)

        return redirect(url_for("documents"))

    except Error as e:

        db.rollback()

        print("DELETE DOCUMENT ERROR:", e)

        return f"Delete document failed: {e}"

    finally:

        cursor.close()
        db.close()


# ==================================================
# USERS
# ==================================================

@app.route("/users")
def users():

    if not is_logged_in():
        return redirect(url_for("login"))

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = None

    try:

        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id,
                name,
                email,
                role,
                created_at
            FROM users
            ORDER BY id DESC
        """)

        users_data = cursor.fetchall()

        return render_template(
            "users.html",
            users=users_data,
            error=None
        )

    except Error as e:

        print("USERS ERROR:", e)

        return render_template(
            "users.html",
            users=[],
            error=str(e)
        )

    finally:

        if cursor:
            cursor.close()

        db.close()

# ==================================================
# DATABASE PAGE
# ==================================================

@app.route("/database")
def database():

    if not is_logged_in():
        return redirect(url_for("login"))

    # ADMIN ONLY
    if session.get("user_role") != "Admin":
        return redirect(url_for("dashboard"))

    db = get_db_connection()

    if db is None:
        return render_template(
            "database.html",
            database_name="legal_case_system",
            tables=[],
            error="Database connection failed."
        )

    cursor = None

    try:

        cursor = db.cursor()

        # DATABASE NAME
        cursor.execute("SELECT DATABASE()")

        result = cursor.fetchone()

        database_name = (
            result[0]
            if result
            else "Unknown"
        )

        # TABLES
        cursor.execute("""
            SHOW TABLES
        """)

        rows = cursor.fetchall()

        tables = []

        for row in rows:
            tables.append(row[0])

        return render_template(
            "database.html",
            database_name=database_name,
            tables=tables,
            error=None
        )

    except Error as e:

        print("DATABASE PAGE ERROR:", e)

        return render_template(
            "database.html",
            database_name="legal_case_system",
            tables=[],
            error=str(e)
        )

    finally:

        if cursor:
            cursor.close()

        db.close()


# ==================================================
# DATABASE TABLE VIEW
# ==================================================

@app.route("/database/table/<table_name>")
def view_database_table(table_name):

    if not is_logged_in():
        return redirect(url_for("login"))

    # ADMIN ONLY
    if session.get("user_role") != "Admin":
        return redirect(url_for("dashboard"))

    allowed_tables = [
        "users",
        "clients",
        "lawyers",
        "cases",
        "hearings",
        "documents",
        "case_notes"
    ]

    if table_name not in allowed_tables:
        return "Invalid table name", 404

    db = get_db_connection()

    if db is None:
        return "Database connection failed."

    cursor = db.cursor(dictionary=True)

    try:

        cursor.execute(
            f"SELECT * FROM `{table_name}`"
        )

        rows = cursor.fetchall()

        return render_template(
            "database_table.html",
            table_name=table_name,
            rows=rows
        )

    except Error as e:

        return f"Database error: {e}"

    finally:

        cursor.close()
        db.close()


# ==================================================
# DATABASE TEST
# ==================================================

@app.route("/db-test")
def db_test():

    if not is_logged_in():
        return redirect(url_for("login"))

    # ADMIN ONLY
    if session.get("user_role") != "Admin":
        return redirect(url_for("dashboard"))

    db = get_db_connection()

    if db is None:
        return render_template(
            "db_test.html",
            database_name="Unknown",
            table_count=0,
            error="Database connection failed."
        )

    cursor = None

    try:

        cursor = db.cursor()

        # DATABASE NAME
        cursor.execute("""
            SELECT DATABASE()
        """)

        result = cursor.fetchone()

        database_name = (
            result[0]
            if result
            else "Unknown"
        )

        # TABLE COUNT
        cursor.execute("""
            SHOW TABLES
        """)

        tables = cursor.fetchall()

        table_count = len(tables)

        return render_template(
            "db_test.html",
            database_name=database_name,
            table_count=table_count,
            error=None
        )

    except Error as e:

        print("DATABASE TEST ERROR:", e)

        return render_template(
            "db_test.html",
            database_name="Unknown",
            table_count=0,
            error=str(e)
        )

    finally:

        if cursor:
            cursor.close()

        db.close()


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )