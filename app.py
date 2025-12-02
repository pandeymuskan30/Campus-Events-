import os
from flask import Flask, render_template, Response, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
from fuzzywuzzy import fuzz
from mysql.connector import pooling
import bcrypt
import re 
import smtplib
from email.message import EmailMessage
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from functools import wraps
from flask import abort
from datetime import date, datetime


app = Flask(__name__)
app.secret_key = "mysupersecretkey123"

# ==============================
# File Upload Config
# ==============================
UPLOAD_FOLDER = os.path.join("static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
# Folder to store generated certificates
CERT_FOLDER = os.path.join("static", "certificates")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure folder exists

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ==============================
# Database Connection Pool
# ==============================
dbconfig = {
    "host": "localhost",
    "user": "root",        # adjust if needed
    "password": "",        # adjust if needed
    "database": "campus_events"
}

connection_pool = pooling.MySQLConnectionPool(pool_name="mypool", pool_size=10, **dbconfig)

def get_db_connection():
    return connection_pool.get_connection()

# ==============================
# Routes
# ==============================

@app.route("/")
def index():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, title, category, description, date, image FROM events ORDER BY date ASC")
    events = cursor.fetchall()
    # Fetch gallery
    cursor.execute("SELECT id, name, image FROM gallery ORDER BY id DESC")
    gallery = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("index.html", events=events, gallery=gallery)

# ------------------ REGISTRATION ------------------
# ------------------ REGISTER ------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Default role
        role = "user"

        # If the registering email is the main admin → assign admin
        if email == "pandeymuskancs232401@gmail.com":
            role = "admin"

        # -------- Hash the password before storing --------
        password_bytes = password.encode("utf-8")
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")

        # -------- Store in DB --------
        conn = get_db_connection()
        cursor = conn.cursor()

        # ✅ Check if email already exists
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("❌ Email already registered! Please use another email or login.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for("register"))

        # ✅ If not exists → insert new user
        cursor.execute(
            "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_password, role)
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("✅ Registered successfully!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")



# ------------------ LOGIN ------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password").encode("utf-8")  # user input

        # Fetch user from DB
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            stored_hash = user["password"].encode("utf-8")  # stored hash
            if bcrypt.checkpw(password, stored_hash):
                # store user info including role in session
                session["user"] = {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"],
                    "role": user["role"]
                }

                flash(f"✅ Welcome back, {user['username']}!", "success")

                # redirect based on role
                if user["role"] == "admin":
                    return redirect(url_for("index"))
                else:
                    return redirect(url_for("index"))
            else:
                flash("❌ Password is incorrect", "error")
        else:
            flash("❌ Email not found", "error")

    return render_template("login.html")




# ------------------ RESET PASSWORD ------------------
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form["email"]
        new_password = request.form["new_password"].encode("utf-8")

        # Hash new password
        hashed = bcrypt.hashpw(new_password, bcrypt.gensalt()).decode("utf-8")

        # Update password directly
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed, email))
        conn.commit()

        if cursor.rowcount > 0:
            flash("✅ Password reset successfully! Please login.", "success")
            cursor.close()
            conn.close()
            return redirect(url_for("login"))
        else:
            flash("❌ Email not found!", "error")

        cursor.close()
        conn.close()

    return render_template("reset_password.html")

# ---------------- ADMIN ----------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session or session["user"]["role"] != "admin":
            flash("❌ You are not authorized to access this page.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/admin/dashboard", endpoint="admin")
@admin_required
def admin_dashboard():
    return render_template("admin_dashboard.html")

@app.route("/admin/allusers")
@admin_required
def all_users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, email, role FROM users ORDER BY id ASC")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("all_users.html", users=users)


@app.route("/update_role/<int:user_id>", methods=["POST"])
@admin_required  # only admins can change roles
def update_role(user_id):
    new_role = request.form.get("role")
    if new_role not in ["user", "admin"]:
        flash("❌ Invalid role!", "error")
        return redirect(url_for("all_users"))

    # Prevent demoting self
    if session['user']['id'] == user_id and new_role == 'user':
        flash("❌ You cannot demote yourself!", "error")
        return redirect(url_for("all_users"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role=%s WHERE id=%s", (new_role, user_id))
    conn.commit()
    cursor.close()
    conn.close()

    flash(f"✅ User role updated to {new_role}!", "success")
    return redirect(url_for("all_users"))
@app.route("/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    # Prevent admin from deleting self
    if session['user']['id'] == user_id:
        flash("❌ You cannot delete yourself!", "error")
        return redirect(url_for("all_users"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash("✅ User deleted successfully!", "success")
    return redirect(url_for("all_users"))


# ---------------- GET REGISTRATIONS ----------------
@app.route("/get_event_registrations/<int:event_id>")
def get_event_registrations(event_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT id, full_name, email, phone, college, class, registration_date, attendance
        FROM event_registrations
        WHERE event_id = %s
    """
    cursor.execute(query, (event_id,))
    registrations = cursor.fetchall()

    cursor.close()
    conn.close()
    return jsonify(registrations)


# ---------------- UPDATE ATTENDANCE ----------------
@app.route("/update_attendance/<int:registration_id>/<status>", methods=["POST"])
def update_attendance(registration_id, status):
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        UPDATE event_registrations
        SET attendance = %s
        WHERE id = %s
    """
    cursor.execute(query, (status, registration_id))
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({"success": True, "attendance": status})

@app.route("/save_attendance", methods=["POST"])
def save_attendance():
    data = request.json.get("updates", [])

    conn = get_db_connection()
    cursor = conn.cursor()

    for entry in data:
        registration_id = entry["id"]
        status = entry["attendance"]
        cursor.execute(
            "UPDATE event_registrations SET attendance = %s WHERE id = %s",
            (status, registration_id)
        )

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"success": True})



# ---------------- register_event ----------------
# Show registration form
@app.route("/register_event/<int:event_id>/form", methods=["GET"])
def register_event_form(event_id):
    return render_template("register_event.html", event_id=event_id)

@app.route("/register_event/<int:event_id>", methods=["POST"])
def register_event(event_id):
    if "user" not in session:
        flash("❌ Please login first to register for events.", "error")
        return redirect(url_for("login"))

    user_id = session["user"]["id"]

    # Get form data
    full_name = request.form["full_name"]
    phone = request.form["phone"]
    college = request.form["college"]
    email = request.form["email"]
    class_year = request.form["class_year"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO event_registrations (user_id, event_id, full_name, phone, college, email, class)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (user_id, event_id, full_name, phone, college, email, class_year))
    
    conn.commit()
    cursor.close()
    conn.close()

    flash("✅ You have successfully registered for this event!", "success")
    return redirect(url_for("index"))
# ---------------- Certificate ----------------
@app.route("/generate_certificates/<int:event_id>", methods=["POST"])
def generate_certificates(event_id):
    os.makedirs(CERT_FOLDER, exist_ok=True)  # Ensure folder exists
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch event info
    cursor.execute("SELECT title FROM events WHERE id=%s", (event_id,))
    event = cursor.fetchone()
    if not event:
        cursor.close()
        conn.close()
        return jsonify({"error": "Event not found"}), 404

    # Fetch attendees who attended
    cursor.execute("SELECT * FROM event_registrations WHERE event_id=%s AND attendance=1", (event_id,))
    attendees = cursor.fetchall()
    cursor.close()
    conn.close()

    sent_emails = []
    for user in attendees:
        # Generate PDF
        pdf_path = os.path.join(CERT_FOLDER, f"{user['full_name'].replace(' ','_')}_{event['title'].replace(' ','_')}.pdf")
        c = canvas.Canvas(pdf_path, pagesize=A4)
        width, height = A4

        # Draw outer border
        margin = 50
        c.setStrokeColor(colors.darkblue)
        c.setLineWidth(4)
        c.rect(margin, margin, width - 2*margin, height - 2*margin)

        # Draw inner decorative border
        c.setStrokeColor(colors.lightblue)
        c.setLineWidth(2)
        c.rect(margin+10, margin+10, width - 2*(margin+10), height - 2*(margin+10))

        # Add Logo
        logo_path = os.path.join("static", "logo.png")  # adjust path if needed
        if os.path.exists(logo_path):
            logo_width = 200
            logo_height = 52  # keeps 808x209 ratio ≈ 3.86
            c.drawImage(
        logo_path,
        width/2 - logo_width/2,   # center horizontally
        height - 150,             # move vertically (adjust as needed)
        width=logo_width,
        height=logo_height,
        mask='auto'
    )

        # Certificate Title
        c.setFont("Helvetica-Bold", 28)
        c.setFillColor(colors.darkblue)
        c.drawCentredString(width/2, height-180, "Certificate of Participation")

        # Recipient Name
        c.setFont("Helvetica-Bold", 22)
        c.setFillColor(colors.black)
        c.drawCentredString(width/2, height-250, "Awarded to")
        c.setFont("Helvetica-BoldOblique", 26)
        c.setFillColor(colors.red)
        c.drawCentredString(width/2, height-290, user['full_name'])

        # Event Name
        c.setFont("Helvetica", 18)
        c.setFillColor(colors.black)
        c.drawCentredString(width/2, height-350, "For participating in")
        c.setFont("Helvetica-Bold", 20)
        c.setFillColor(colors.darkgreen)
        c.drawCentredString(width/2, height-380, event['title'])

        # Footer / Signatures
        c.setFont("Helvetica", 14)
        c.setFillColor(colors.black)
        c.drawString(100, 100, "___________________")
        c.drawString(width-250, 100, "___________________")
        c.drawString(120, 80, "Organizer Signature")
        c.drawString(width-240, 80, "Principal / Head Signature")

        c.save()


        # Send email
        try:
            msg = EmailMessage()
            msg['Subject'] = f"Certificate for {event['title']}"
            msg['From'] = "pandeymuskancs232401@gmail.com"
            msg['To'] = user['email']
            msg.set_content(f"Hi {user['full_name']},\n\nPlease find your participation certificate attached.")

            with open(pdf_path, "rb") as f:
                msg.add_attachment(f.read(), maintype='application', subtype='pdf', filename=os.path.basename(pdf_path))

            # Gmail SMTP
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login("pandeymuskancs232401@gmail.com", " ")
                smtp.send_message(msg)

            sent_emails.append(user['email'])
        except Exception as e:
            print("Failed to send email to", user['email'], e)

    return jsonify({"message": f"Certificates sent to {len(sent_emails)} participants."})





# ---------------- feedback ----------------
@app.route("/submit_feedback", methods=["POST"])
def submit_feedback():
    if "user" not in session:
        flash("❌ Please login to submit feedback.", "error")
        return redirect(url_for("login"))

    user_id = session["user"]["id"]
    event_id = request.form.get("event_id")
    message = request.form.get("message")

    if not event_id or not message:
        flash("❌ Please select an event and write feedback.", "error")
        return redirect(url_for("index"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO feedback (user_id, event_id, message) VALUES (%s, %s, %s)",
        (user_id, event_id, message)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("✅ Thank you for your feedback!", "success")
    return redirect(url_for("index"))


# ---------------- organizers ----------------
@app.route("/organizers")
def organizers():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch gallery
    cursor.execute("SELECT * FROM gallery ORDER BY id DESC")
    gallery = cursor.fetchall()

    # Fetch feedback with user and event titles
    cursor.execute("""
        SELECT f.id, f.message, u.username, e.title AS event_name
        FROM feedback f
        JOIN users u ON f.user_id = u.id
        JOIN events e ON f.event_id = e.id
        ORDER BY f.id DESC
    """)
    feedback_data = cursor.fetchall()

    # Pass a unique event list to template for dropdown
    event_list = list({f['event_name'] for f in feedback_data})

    cursor.close()
    conn.close()
    return render_template("organizers.html", gallery=gallery, feedback_data=feedback_data, event_list=event_list)

@app.route("/delete_feedback/<int:id>", methods=["DELETE"])
def delete_feedback(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM feedback WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"success": True})


# ---------------- Add Gallery ----------------
@app.route("/add_gallery", methods=["POST"])
@admin_required
def add_gallery():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    name = request.form.get("name", "")
    image = request.files.get("image")

    if image and image.filename != "":
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        cursor.execute(
            "INSERT INTO gallery (name, image) VALUES (%s, %s)",
            (name, filename),
        )
        conn.commit()
        flash("✅ Gallery image uploaded successfully!", "success")
    else:
        flash("❌ Please select an image.", "danger")

    # Fetch updated gallery items
    cursor.execute("SELECT * FROM gallery ORDER BY id DESC")
    gallery = cursor.fetchall()

    # Fetch feedback with user and event titles
    cursor.execute("""
        SELECT f.id, f.message, u.username, e.title AS event_name
        FROM feedback f
        JOIN users u ON f.user_id = u.id
        JOIN events e ON f.event_id = e.id
        ORDER BY f.id DESC
    """)
    feedback_data = cursor.fetchall()

    # Unique event list for dropdown
    event_list = list({f['event_name'] for f in feedback_data})

    cursor.close()
    conn.close()

    return render_template(
        "organizers.html",
        gallery=gallery,
        feedback_data=feedback_data,
        event_list=event_list
    )

# ---------------- Delete Gallery ----------------
@app.route("/delete_gallery/<int:id>", methods=["POST"])
@admin_required
def delete_gallery(id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get filename to delete from static/uploads
    cursor.execute("SELECT image FROM gallery WHERE id = %s", (id,))
    gallery_item = cursor.fetchone()

    if gallery_item:
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], gallery_item["image"])
        if os.path.exists(image_path):
            os.remove(image_path)

        cursor.execute("DELETE FROM gallery WHERE id = %s", (id,))
        conn.commit()
        flash("✅ Gallery image deleted successfully!", "success")
    else:
        flash("❌ Gallery item not found!", "danger")

    # Fetch updated gallery items
    cursor.execute("SELECT * FROM gallery ORDER BY id DESC")
    gallery = cursor.fetchall()

    # Fetch feedback with user and event titles
    cursor.execute("""
        SELECT f.id, f.message, u.username, e.title AS event_name
        FROM feedback f
        JOIN users u ON f.user_id = u.id
        JOIN events e ON f.event_id = e.id
        ORDER BY f.id DESC
    """)
    feedback_data = cursor.fetchall()

    # Unique event list for dropdown
    event_list = list({f['event_name'] for f in feedback_data})

    cursor.close()
    conn.close()

    return render_template(
        "organizers.html",
        gallery=gallery,
        feedback_data=feedback_data,
        event_list=event_list
    )



# ---------------- EVENTS ----------------

@app.route("/get_events")
def get_events():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM events ORDER BY date ASC")
    events = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(events)

@app.route("/add_event", methods=["POST"])
def add_event():
    title = request.form["title"]
    category = request.form["category"]
    description = request.form["description"]
    date = request.form["date"]

    image_file = request.files.get("image")
    image_path = None

    if image_file and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        image_file.save(save_path)
        image_path = url_for("static", filename=f"uploads/{filename}")

    conn = get_db_connection()
    cursor = conn.cursor()
    query = "INSERT INTO events (title, category, description, date, image) VALUES (%s, %s, %s, %s, %s)"
    values = (title, category, description, date, image_path)
    cursor.execute(query, values)
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Event added successfully!"})

@app.route("/delete_event/<int:event_id>", methods=["DELETE"])
def delete_event(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Delete feedback related to this event
    cursor.execute("DELETE FROM feedback WHERE event_id=%s", (event_id,))
    # Delete registrations related to this event (if you have a table like event_registrations)
    cursor.execute("DELETE FROM event_registrations WHERE event_id=%s", (event_id,))
    
    # Now delete the event itself
    cursor.execute("DELETE FROM events WHERE id=%s", (event_id,))
    
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "Event deleted successfully!"})

# ---------------- Report Event ----------------
@app.route("/admin/event-report")
@admin_required
def event_report():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT e.title, e.date,
               COUNT(r.id) AS total_registrations,
               SUM(CASE WHEN TRIM(LOWER(r.attendance))='present' THEN 1 ELSE 0 END) AS present_count
        FROM events e
        LEFT JOIN event_registrations r ON e.id = r.event_id
        GROUP BY e.id
        ORDER BY e.date DESC
    """)
    event_reports = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("event_report.html", event_reports=event_reports)


# CSV download
@app.route("/admin/event-report/csv")
@admin_required
def download_event_report_csv():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT e.title, e.date,
               COUNT(r.id) AS total_registrations,
               SUM(CASE WHEN TRIM(LOWER(r.attendance))='present' THEN 1 ELSE 0 END) AS present_count
        FROM events e
        LEFT JOIN event_registrations r ON e.id = r.event_id
        GROUP BY e.id
        ORDER BY e.date DESC
    """)
    reports = cursor.fetchall()
    cursor.close()
    conn.close()

    def generate():
        yield ','.join(['Event Title', 'Date', 'Total Registrations', 'Present', 'Attendance %']) + '\n'
        for r in reports:
            attendance_percent = (r['present_count'] / r['total_registrations'] * 100) if r['total_registrations'] > 0 else 0
            yield ','.join([
                r['title'],
                str(r['date']),
                str(r['total_registrations']),
                str(r['present_count']),
                f"{attendance_percent:.1f}%"
            ]) + '\n'

    return Response(
        generate(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=event_report.csv"}
    )


# ---------------- Update Event ----------------
@app.route("/update_event/<int:event_id>", methods=["POST"])
def update_event(event_id):
    title = request.form.get("title")
    category = request.form.get("category")
    description = request.form.get("description")
    date = request.form.get("date")

    image_file = request.files.get("image")
    image_path = None

    if image_file and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        image_file.save(save_path)
        image_path = url_for("static", filename=f"uploads/{filename}")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Update event
    if image_path:
        query = """
            UPDATE events 
            SET title=%s, category=%s, description=%s, date=%s, image=%s 
            WHERE id=%s
        """
        values = (title, category, description, date, image_path, event_id)
    else:
        query = """
            UPDATE events 
            SET title=%s, category=%s, description=%s, date=%s 
            WHERE id=%s
        """
        values = (title, category, description, date, event_id)

    cursor.execute(query, values)
    conn.commit()

    # ---------------- Notify Registered Users ----------------
    cursor.execute("""
    SELECT u.email, u.username AS full_name
    FROM event_registrations r
    JOIN users u ON r.user_id = u.id
    WHERE r.event_id = %s
""", (event_id,))

    users = cursor.fetchall()

    cursor.close()
    conn.close()

    # Configure sender email (⚠️ replace with your credentials)
    sender_email = "pandeymuskancs232401@gmail.com"
    sender_pass = " "  # Gmail App Password or SMTP creds

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender_email, sender_pass)
            for user in users:
                msg = EmailMessage()
                msg["From"] = sender_email
                msg["To"] = user["email"]
                msg["Subject"] = f"Update: {title}"
                msg.set_content(f"""
Hello {user['full_name']},

The event you registered for has been updated.

📌 Event: {title}
📅 Date: {date}
📖 Description: {description}

Thank you,
Campus Events Team
                """)
                smtp.send_message(msg)

        return jsonify({"message": f"Event updated and notifications sent to {len(users)} users."})

    except Exception as e:
        return jsonify({"error": f"Event updated, but failed to send notifications: {str(e)}"}), 500



@app.route("/get_stats")
def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total FROM events")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(DISTINCT category) AS categories FROM events")
    categories = cursor.fetchone()["categories"]

    cursor.execute("SELECT COUNT(*) AS upcoming FROM events WHERE date >= CURDATE()")
    upcoming = cursor.fetchone()["upcoming"]

    cursor.close()
    conn.close()

    return jsonify({
        "total": total,
        "categories": categories,
        "upcoming": upcoming
    })


# ==============================
# Chatbot
# ==============================

def is_similar(user_message, keywords, threshold=85):
    for word in keywords:
        if fuzz.partial_ratio(user_message, word) >= threshold:
            return True
    return False

@app.route("/chatbot", methods=["POST"])
def chatbot():
    user_message = request.json.get("message", "").lower().strip()
    reply = "❓ Sorry, I don’t understand. Please try asking about an event."

    greetings = ["hi", "hello", "hey", "good morning", "good evening"]
    if user_message in greetings:
        return jsonify({"reply": "👋 Hello! I’m your Campus Bot. You can ask about upcoming, past, or specific events."})

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    today_str = date.today().strftime("%Y-%m-%d")

    # ----------- UPCOMING EVENTS -----------
    upcoming_keywords = ["upcoming event", "upcoming events", "future event", "future events", "next event", "next events"]
    if is_similar(user_message, upcoming_keywords):
        cursor.execute(
            "SELECT title, date FROM events WHERE date >= %s ORDER BY date ASC",
            (today_str,)
        )
        events = cursor.fetchall()
        if events:
            reply = "📅 Here are the upcoming events:\n"
            for e in events:
                event_date = e['date']
                if isinstance(event_date, datetime):
                    event_date = event_date.date().strftime("%Y-%m-%d")
                reply += f"- {e['title']} on {event_date}\n"
        else:
            reply = "⚠️ No upcoming events found."

    # ----------- PAST EVENTS -----------
    past_keywords = ["past event", "past events", "previous event", "previous events", "old event", "old events", "completed event", "completed events"]
    if is_similar(user_message, past_keywords):
        cursor.execute(
            "SELECT title, date FROM events WHERE date < %s ORDER BY date DESC",
            (today_str,)
        )
        events = cursor.fetchall()
        if events:
            reply = "🕓 Here are the past events:\n"
            for e in events:
                event_date = e['date']
                if isinstance(event_date, datetime):
                    event_date = event_date.date().strftime("%Y-%m-%d")
                reply += f"- {e['title']} on {event_date}\n"
        else:
            reply = "⚠️ No past events found."

    # ----------- ALL EVENTS -----------
    all_keywords = ["all events", "list", "show events", "what are the events"]
    if is_similar(user_message, all_keywords):
        cursor.execute("SELECT title, date FROM events ORDER BY date ASC")
        events = cursor.fetchall()
        if events:
            reply = "📋 Here’s the list of all events:\n"
            for e in events:
                event_date = e['date']
                if isinstance(event_date, datetime):
                    event_date = event_date.date().strftime("%Y-%m-%d")
                reply += f"- {e['title']} on {event_date}\n"
        else:
            reply = "⚠️ No events found."

    # ----------- CATEGORY-WISE EVENTS -----------
    elif "cultural" in user_message or "academic" in user_message or "sports" in user_message:
        if "cultural" in user_message:
            category = "Cultural"
        elif "academic" in user_message:
            category = "Academic"
        elif "sports" in user_message:
            category = "Sports"
        else:
            category = None

        if category:
            cursor.execute(
                "SELECT title, date FROM events WHERE category=%s ORDER BY date ASC",
                (category,)
            )
            events = cursor.fetchall()
            if events:
                reply = f"🎭 {category} Events:\n"
                for e in events:
                    event_date = e['date']
                    if isinstance(event_date, datetime):
                        event_date = event_date.date().strftime("%Y-%m-%d")
                    reply += f"- {e['title']} on {event_date}\n"
            else:
                reply = f"❌ No {category} events found."

    # ----------- EVENT ON SPECIFIC DATE -----------
    elif "event" in user_message and "on" in user_message:
        try:
            date_str = user_message.split("on")[-1].strip()
            cursor.execute(
                "SELECT title, description FROM events WHERE date=%s",
                (date_str,)
            )
            events = cursor.fetchall()
            if events:
                reply = f"📌 Events on {date_str}:\n"
                for e in events:
                    reply += f"- {e['title']}: {e['description']}\n"
            else:
                reply = f"❌ No events found on {date_str}."
        except:
            reply = "⚠️ Please use format: 'events on YYYY-MM-DD'."

    # ----------- SEARCH BY EVENT TITLE (FUZZY MATCH) -----------
    else:
        cursor.execute("SELECT title, date, description FROM events")
        events = cursor.fetchall()
        for e in events:
            if fuzz.partial_ratio(user_message, e['title'].lower()) >= 80:
                event_date = e['date']
                if isinstance(event_date, datetime):
                    event_date = event_date.date().strftime("%Y-%m-%d")
                reply = f"✅ {e['title']} on {event_date}\n📖 Details: {e['description']}"
                break

    cursor.close()
    conn.close()
    return jsonify({"reply": reply})


# ---------------- AUTH ----------------

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

# ==============================
# Run App
# ==============================
if __name__ == "__main__":
    app.run(debug=True)