from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import date
from pathlib import Path
from werkzeug.utils import secure_filename
import calendar
import os
from openai import OpenAI

app = Flask(__name__)

ADMIN_EMAIL = "khushvendrasingh2006@gmail.com"
app.secret_key = "change-this-secret-key"
DATABASE = "database.db"
UPLOAD_FOLDER = Path("static/uploads")
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
MONTH_NAMES = ["January","February","March","April","May","June","July","August","September","October","November","December"]

CATEGORIES = ["Food","Transportation","Shopping","Education","Rent","Bills","Entertainment","Healthcare","Travel","Other"]
PAYMENT_METHODS = ["Cash","UPI","Debit Card","Credit Card","Net Banking","Other"]

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function

def admin_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        if session.get("user_email") != ADMIN_EMAIL:
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))

        return f(*args, **kwargs)

    return decorated_function

def init_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            profile_photo TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cols = [
        r["name"]
        for r in conn.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    # Add profile_photo column to old databases
    if "profile_photo" not in cols:
        conn.execute(
            "ALTER TABLE users ADD COLUMN profile_photo TEXT"
        )

    # Add username column to old databases
    if "username" not in cols:
        conn.execute(
            "ALTER TABLE users ADD COLUMN username TEXT"
        )

    # Generate usernames for existing users
    users = conn.execute(
        """
        SELECT id, name
        FROM users
        WHERE username IS NULL OR username = ''
        """
    ).fetchall()

    for user in users:

        base_username = (
            user["name"]
            .lower()
            .replace(" ", "")
        )

        if not base_username:
            base_username = f"user{user['id']}"

        username = base_username
        counter = 1

        while conn.execute(
            "SELECT id FROM users WHERE username=?",
            (username,)
        ).fetchone():

            username = f"{base_username}{counter}"
            counter += 1

        conn.execute(
            "UPDATE users SET username=? WHERE id=?",
            (username, user["id"])
        )

    conn.commit()
    conn.close()


def login():

    if request.method == "POST":

        identifier = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE LOWER(email)=?
            OR LOWER(username)=?
            """,
            (identifier, identifier)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):

            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]
            session["username"] = user["username"]

            return redirect(url_for("dashboard"))

        flash("Invalid username/email or password.", "error")

    return render_template("login.html")

def totals(uid, month, year):
    conn=get_db()
    r=conn.execute("""SELECT
    COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE 0 END),0) income,
    COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END),0) expense
    FROM transactions WHERE user_id=? AND strftime('%m',transaction_date)=?
    AND strftime('%Y',transaction_date)=?""",(uid,f"{month:02d}",str(year))).fetchone()
    conn.close()
    return float(r["income"]),float(r["expense"])

def user_categories(uid):
    if not uid: return CATEGORIES
    conn=get_db(); rows=conn.execute("SELECT name FROM categories WHERE user_id=? ORDER BY name",(uid,)).fetchall(); conn.close()
    return [r["name"] for r in rows] or CATEGORIES

@app.context_processor
def globals():
    return {"categories":user_categories(session.get("user_id")),"payment_methods":PAYMENT_METHODS,"month_names":MONTH_NAMES,"logged_in":"user_id" in session}

@app.route("/")
def home(): return redirect(url_for("dashboard" if "user_id" in session else "login"))

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()

        username = request.form.get(
            "username",
            ""
        ).strip().lower()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm = request.form.get(
            "confirm_password",
            ""
        )

        # Check required fields
        if not name or not username or not email or not password:

            flash(
                "Please fill all required fields.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        # Username length
        if len(username) < 3:

            flash(
                "Username must be at least 3 characters.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        # Username cannot contain spaces
        if " " in username:

            flash(
                "Username cannot contain spaces.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        # Check password confirmation
        if password != confirm:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        # Check password length
        if len(password) < 6:

            flash(
                "Password must be at least 6 characters.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        # Connect to database
        conn = get_db()

        # Check whether username or email already exists
        existing = conn.execute(
            """
            SELECT id
            FROM users
            WHERE email = ?
            OR username = ?
            """,
            (
                email,
                username
            )
        ).fetchone()

        if existing:

            conn.close()

            flash(
                "Email or username is already registered.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        # Create new user
        conn.execute(
            """
            INSERT INTO users
            (name, username, email, password)
            VALUES (?, ?, ?, ?)
            """,
            (
                name,
                username,
                email,
                generate_password_hash(password)
            )
        )

        conn.commit()
        conn.close()

        flash(
            "Account created successfully. Please login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])


@app.route("/logout")
def logout(): session.clear(); flash("Logged out successfully.","success"); return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():

    m, y = date.today().month, date.today().year

    income, expense = totals(
        session["user_id"],
        m,
        y
    )

    conn = get_db()

    b = conn.execute("""
        SELECT amount
        FROM budgets
        WHERE user_id = ?
        AND month = ?
        AND year = ?
    """, (
        session["user_id"],
        m,
        y
    )).fetchone()

    recent = conn.execute("""
        SELECT *
        FROM transactions
        WHERE user_id = ?
        ORDER BY transaction_date DESC, id DESC
        LIMIT 6
    """, (
        session["user_id"],
    )).fetchall()

    conn.close()

    budget = float(b["amount"]) if b else 0

    used = min(
        expense / budget * 100,
        100
    ) if budget else 0


    # =====================================
    # SMART SALARY PLAN
    # =====================================

    needs_amount = income * 0.50
    wants_amount = income * 0.20
    savings_amount = income * 0.20
    emergency_amount = income * 0.10


    # =====================================
    # SPENDING GUIDE
    # =====================================

    recommended = income * 0.80

    savings_target = income * 0.20

    days_left = max(
        calendar.monthrange(y, m)[1]
        - date.today().day
        + 1,
        1
    )

    daily_guide = max(
        recommended - expense,
        0
    ) / days_left


    # =====================================
    # SMART SUGGESTIONS
    # =====================================

    suggestions = []

    if income <= 0:

        suggestions.append(
            "💡 Add your monthly salary or income "
            "to generate your personalized plan."
        )

    else:

        suggestions.append(
            f"🏠 Try to keep your essential expenses "
            f"around ₹{needs_amount:,.0f}."
        )

        suggestions.append(
            f"💰 Try to save around "
            f"₹{savings_amount:,.0f} this month."
        )

        suggestions.append(
            f"🎉 Your suggested flexible spending "
            f"limit is ₹{wants_amount:,.0f}."
        )

        suggestions.append(
            f"🚨 Keep around ₹{emergency_amount:,.0f} "
            f"as an emergency reserve."
        )

        if expense > needs_amount:

            suggestions.append(
                "⚠️ Your current spending is higher "
                "than the suggested essential limit."
            )

        if savings_amount > 0 and income - expense < savings_amount:

            suggestions.append(
                "📉 Your current remaining balance is "
                "below the suggested savings target."
            )

        if expense == 0:

            suggestions.append(
                "🌟 No expenses recorded yet. "
                "Start tracking your spending to get "
                "more personalized suggestions."
            )


    return render_template(
        "dashboard.html",

        income=income,
        expense=expense,
        balance=income - expense,

        budget=budget,
        used=used,

        recent=recent,

        month=m,
        year=y,

        recommended=recommended,
        savings_target=savings_target,
        daily_guide=daily_guide,

        needs_amount=needs_amount,
        wants_amount=wants_amount,
        emergency_amount=emergency_amount,

        suggestions=suggestions
    )
    

def save_transaction(kind):
    amount=request.form.get("amount",""); d=request.form.get("transaction_date","")
    try: amount=float(amount); assert amount>0
    except: flash("Enter a valid positive amount.","error"); return False
    conn=get_db()
    if kind=="expense":
        cat=request.form.get("category",""); pay=request.form.get("payment_method","")
        if not cat or not d: conn.close(); flash("Category and date are required.","error"); return False
        conn.execute("""INSERT INTO transactions(user_id,type,amount,category,payment_method,description,transaction_date)
        VALUES(?,?,?,?,?,?,?)""",(session["user_id"],"expense",amount,cat,pay,request.form.get("description","").strip(),d))
    else:
        source=request.form.get("source","").strip()
        if not source or not d: conn.close(); flash("Source and date are required.","error"); return False
        conn.execute("""INSERT INTO transactions(user_id,type,amount,source,description,transaction_date)
        VALUES(?,?,?,?,?,?)""",(session["user_id"],"income",amount,source,request.form.get("description","").strip(),d))
    conn.commit(); conn.close(); return True

@app.route("/add-expense",methods=["GET","POST"])
@login_required
def add_expense():
    if request.method=="POST" and save_transaction("expense"):
        flash("Expense added successfully.","success"); return redirect(url_for("transactions"))
    return render_template("transaction_form.html",mode="expense",today=date.today().isoformat())

@app.route("/add-income",methods=["GET","POST"])
@login_required
def add_income():
    if request.method=="POST" and save_transaction("income"):
        flash("Income added successfully.","success"); return redirect(url_for("transactions"))
    return render_template("transaction_form.html",mode="income",today=date.today().isoformat())

@app.route("/transactions")
@login_required
def transactions():
    q=request.args.get("q","").strip(); typ=request.args.get("type",""); cat=request.args.get("category","")
    sql="SELECT * FROM transactions WHERE user_id=?"; p=[session["user_id"]]
    if q: sql+=" AND (description LIKE ? OR source LIKE ? OR category LIKE ?)"; like=f"%{q}%"; p += [like,like,like]
    if typ in ("income","expense"): sql+=" AND type=?"; p.append(typ)
    if cat: sql+=" AND category=?"; p.append(cat)
    sql+=" ORDER BY transaction_date DESC,id DESC"; conn=get_db(); rows=conn.execute(sql,p).fetchall(); conn.close()
    return render_template("transactions.html",transactions=rows,q=q,type_filter=typ,selected_category=cat)

@app.route("/delete/<int:tid>",methods=["POST"])
@login_required
def delete_transaction(tid):
    conn=get_db(); conn.execute("DELETE FROM transactions WHERE id=? AND user_id=?",(tid,session["user_id"])); conn.commit(); conn.close()
    flash("Transaction deleted.","success"); return redirect(url_for("transactions"))

@app.route("/budget",methods=["GET","POST"])
@login_required
def budget():
    m,y=date.today().month,date.today().year
    if request.method=="POST":
        try: amount=float(request.form.get("amount","")); assert amount>=0
        except: flash("Enter a valid budget.","error"); return redirect(url_for("budget"))
        m=int(request.form.get("month",m)); y=int(request.form.get("year",y)); conn=get_db()
        conn.execute("""INSERT INTO budgets(user_id,month,year,amount) VALUES(?,?,?,?)
        ON CONFLICT(user_id,month,year) DO UPDATE SET amount=excluded.amount""",(session["user_id"],m,y,amount))
        conn.commit(); conn.close(); flash("Budget saved.","success"); return redirect(url_for("budget"))
    conn=get_db(); budgets=conn.execute("SELECT * FROM budgets WHERE user_id=? ORDER BY year DESC,month DESC",(session["user_id"],)).fetchall(); conn.close()
    income, expense = totals(session["user_id"], m, y)
    recommended = income * 0.80
    savings_target = income * 0.20
    days_left = max(calendar.monthrange(y,m)[1] - date.today().day + 1, 1) if (m,y)==(date.today().month,date.today().year) else calendar.monthrange(y,m)[1]
    daily_guide = max(recommended - expense, 0) / days_left if days_left else 0
    return render_template("budget.html", budgets=budgets, month=m, year=y, plan_income=income, recommended=recommended, savings_target=savings_target, days_left=days_left, daily_guide=daily_guide)

@app.route("/reset-budget", methods=["POST"])
@login_required
def reset_budget():

    conn = get_db()

    # Get the current month and year
    from datetime import datetime
    now = datetime.now()

    conn.execute("""
        DELETE FROM budgets
        WHERE user_id = ? AND month = ? AND year = ?
    """, (
        session["user_id"],
        now.month,
        now.year
    ))

    conn.commit()
    conn.close()

    flash("Your current month's budget has been reset successfully.", "success")

    return redirect(url_for("budget"))

@app.route("/edit-transaction/<int:tid>",methods=["GET","POST"])
@login_required
def edit_transaction(tid):
    conn=get_db(); t=conn.execute("SELECT * FROM transactions WHERE id=? AND user_id=?",(tid,session["user_id"])).fetchone()
    if not t: conn.close(); flash("Transaction not found.","error"); return redirect(url_for("transactions"))
    if request.method=="POST":
        try: amount=float(request.form.get("amount","")); assert amount>0
        except: conn.close(); flash("Enter a valid amount.","error"); return redirect(url_for("edit_transaction",tid=tid))
        d=request.form.get("transaction_date",""); desc=request.form.get("description","").strip()
        if t["type"]=="expense":
            conn.execute("UPDATE transactions SET amount=?,category=?,payment_method=?,description=?,transaction_date=? WHERE id=? AND user_id=?",(amount,request.form.get("category",""),request.form.get("payment_method",""),desc,d,tid,session["user_id"]))
        else:
            conn.execute("UPDATE transactions SET amount=?,source=?,description=?,transaction_date=? WHERE id=? AND user_id=?",(amount,request.form.get("source","").strip(),desc,d,tid,session["user_id"]))
        conn.commit(); conn.close(); flash("Transaction updated successfully.","success"); return redirect(url_for("transactions"))
    conn.close(); return render_template("transaction_form.html",mode=t["type"],transaction=t,editing=True,today=date.today().isoformat())

@app.route("/categories")
@login_required
def categories():
    return render_template("categories.html", cats=user_categories(session["user_id"]))

@app.route("/add-category",methods=["POST"])
@login_required
def add_category():
    name=request.form.get("name","").strip()
    if not name: flash("Category name is required.","error"); return redirect(url_for("categories"))
    conn=get_db()
    try:
        conn.execute("INSERT INTO categories(user_id,name) VALUES(?,?)",(session["user_id"],name)); conn.commit(); flash("Category added successfully.","success")
    except sqlite3.IntegrityError: flash("This category already exists.","error")
    conn.close(); return redirect(url_for("categories"))

@app.route("/profile",methods=["GET","POST"])
@login_required
def profile():
    conn=get_db(); user=conn.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    if request.method=="POST":
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower(); photo=request.files.get("profile_photo"); filename=user["profile_photo"]
        if not name or not email: conn.close(); flash("Name and email are required.","error"); return redirect(url_for("profile"))
        if photo and photo.filename:
            ext=photo.filename.rsplit(".",1)[-1].lower() if "." in photo.filename else ""
            if ext not in {"png","jpg","jpeg","webp"}: conn.close(); flash("Use PNG, JPG, JPEG or WEBP.","error"); return redirect(url_for("profile"))
            filename=f"user_{session['user_id']}.{ext}"; photo.save(UPLOAD_FOLDER/secure_filename(filename))
        try: conn.execute("UPDATE users SET name=?,email=?,profile_photo=? WHERE id=?",(name,email,filename,session["user_id"])); conn.commit()
        except sqlite3.IntegrityError: conn.close(); flash("That email is already in use.","error"); return redirect(url_for("profile"))
        session["user_name"]=name; conn.close(); flash("Profile updated successfully.","success"); return redirect(url_for("profile"))
    conn.close(); return render_template("profile.html",user=user)

@app.route("/change-password", methods=["POST"])
@login_required
def change_password():

    current_password = request.form.get(
        "current_password",
        ""
    )

    new_password = request.form.get(
        "new_password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    if not current_password or not new_password or not confirm_password:

        flash(
            "Please fill all password fields.",
            "error"
        )

        return redirect(url_for("profile"))

    if new_password != confirm_password:

        flash(
            "New passwords do not match.",
            "error"
        )

        return redirect(url_for("profile"))

    if len(new_password) < 6:

        flash(
            "New password must be at least 6 characters.",
            "error"
        )

        return redirect(url_for("profile"))

    conn = get_db()

    user = conn.execute(
        """
        SELECT password
        FROM users
        WHERE id=?
        """,
        (session["user_id"],)
    ).fetchone()

    if not user:

        conn.close()

        flash(
            "User account not found.",
            "error"
        )

        return redirect(url_for("profile"))

    if not check_password_hash(
        user["password"],
        current_password
    ):

        conn.close()

        flash(
            "Current password is incorrect.",
            "error"
        )

        return redirect(url_for("profile"))

    conn.execute(
        """
        UPDATE users
        SET password=?
        WHERE id=?
        """,
        (
            generate_password_hash(new_password),
            session["user_id"]
        )
    )

    conn.commit()
    conn.close()

    flash(
        "Password changed successfully.",
        "success"
    )

    return redirect(url_for("profile"))

@app.route("/help")
@login_required
def help_page(): return render_template("help.html")

@app.route("/seed-demo",methods=["POST"])
@login_required
def seed_demo():
    d=date.today().isoformat(); uid=session["user_id"]; demo=[("expense",250,"Food","","UPI","Lunch"),("expense",500,"Transportation","","UPI","Travel"),("expense",1200,"Shopping","","Debit Card","Shopping"),("income",15000,"","Salary","","Monthly salary")]
    conn=get_db()
    for typ,amount,cat,source,pay,desc in demo: conn.execute("INSERT INTO transactions(user_id,type,amount,category,source,payment_method,description,transaction_date) VALUES(?,?,?,?,?,?,?,?)",(uid,typ,amount,cat,source,pay,desc,d))
    conn.commit(); conn.close(); flash("Demo data added successfully.","success"); return redirect(url_for("dashboard"))
    
@app.route("/reports")
@login_required
def reports():
    m = int(request.args.get("month", date.today().month))
    y = int(request.args.get("year", date.today().year))

    income, expense = totals(session["user_id"], m, y)

    conn = get_db()

    cats = conn.execute("""
        SELECT category, SUM(amount) total
        FROM transactions
        WHERE user_id = ?
        AND type = 'expense'
        AND strftime('%m', transaction_date) = ?
        AND strftime('%Y', transaction_date) = ?
        GROUP BY category
        ORDER BY total DESC
    """, (
        session["user_id"],
        f"{m:02d}",
        str(y)
    )).fetchall()

    # Get monthly budget
    budget_row = conn.execute("""
        SELECT amount
        FROM budgets
        WHERE user_id = ?
        AND month = ?
        AND year = ?
    """, (
        session["user_id"],
        m,
        y
    )).fetchone()

    conn.close()

    budget = float(budget_row["amount"]) if budget_row else 0

    return render_template(
        "reports.html",
        month=m,
        year=y,
        income=income,
        expense=expense,
        savings=income - expense,
        budget=budget,
        cats=cats
    )

@app.route("/customer-support", methods=["GET", "POST"])
@login_required
def customer_support():

    if request.method == "POST":

        subject = request.form.get("subject", "").strip()
        category = request.form.get("category", "").strip()
        message = request.form.get("message", "").strip()

        if not subject or not category or not message:
            flash("Please fill all the required fields.", "error")
            return redirect(url_for("customer_support"))

        conn = get_db()

        conn.execute("""
            INSERT INTO support_tickets
            (user_id, subject, category, message, status)
            VALUES (?, ?, ?, ?, 'Open')
        """, (
            session["user_id"],
            subject,
            category,
            message
        ))

        conn.commit()
        conn.close()

        flash("Support ticket submitted successfully!", "success")
        return redirect(url_for("my_tickets"))

    return render_template("customer_support.html")
    
@app.route("/admin/support")
@admin_required
def admin_support():

    conn = get_db()

    tickets = conn.execute("""
        SELECT
            support_tickets.*,
            users.name,
            users.email
        FROM support_tickets
        JOIN users
        ON support_tickets.user_id = users.id
        ORDER BY support_tickets.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "admin_support.html",
        tickets=tickets
    )


@app.route("/admin/ticket/<int:ticket_id>", methods=["GET", "POST"])
@admin_required
def admin_ticket(ticket_id):

    conn = get_db()

    ticket = conn.execute("""
        SELECT
            support_tickets.*,
            users.name,
            users.email
        FROM support_tickets
        JOIN users
        ON support_tickets.user_id = users.id
        WHERE support_tickets.id = ?
    """, (ticket_id,)).fetchone()

    if not ticket:
        conn.close()
        flash("Ticket not found.", "error")
        return redirect(url_for("admin_support"))

    if request.method == "POST":

        action = request.form.get("action", "")
        message = request.form.get("message", "").strip()
        status = request.form.get("status", "In Progress")

        # Admin closes ticket
        if action == "close":

            conn.execute("""
                UPDATE support_tickets
                SET status = 'Closed',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (ticket_id,))

            conn.commit()
            conn.close()

            flash("Ticket closed successfully.", "success")

            return redirect(
                url_for("admin_ticket", ticket_id=ticket_id)
            )

        # Admin sends response
        if action == "reply":

            if ticket["status"] == "Closed":
                conn.close()
                flash("This ticket is closed.", "error")
                return redirect(
                    url_for("admin_ticket", ticket_id=ticket_id)
                )

            if status not in ["Open", "In Progress", "Resolved"]:
                status = "In Progress"

            if not message:
                conn.close()
                flash("Please enter a response.", "error")
                return redirect(
                    url_for("admin_ticket", ticket_id=ticket_id)
                )

            conn.execute("""
                INSERT INTO ticket_messages
                (ticket_id, user_id, sender_type, message)
                VALUES (?, ?, 'Admin', ?)
            """, (
                ticket_id,
                session["user_id"],
                message
            ))

            conn.execute("""
                UPDATE support_tickets
                SET status = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                status,
                ticket_id
            ))

            conn.commit()
            conn.close()

            flash("Response sent successfully.", "success")

            return redirect(
                url_for("admin_ticket", ticket_id=ticket_id)
            )

    messages = conn.execute("""
        SELECT
            ticket_messages.*,
            users.name,
            users.email
        FROM ticket_messages
        JOIN users
        ON ticket_messages.user_id = users.id
        WHERE ticket_messages.ticket_id = ?
        ORDER BY ticket_messages.id ASC
    """, (ticket_id,)).fetchall()

    conn.close()

    return render_template(
        "admin_ticket.html",
        ticket=ticket,
        messages=messages
    )

@app.route("/my-tickets")
@login_required
def my_tickets():

    conn = get_db()

    tickets = conn.execute("""
        SELECT *
        FROM support_tickets
        WHERE user_id = ?
        ORDER BY id DESC
    """, (session["user_id"],)).fetchall()

    conn.close()

    return render_template(
        "my_tickets.html",
        tickets=tickets
    )

@app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def view_ticket(ticket_id):

    conn = get_db()

    ticket = conn.execute("""
        SELECT *
        FROM support_tickets
        WHERE id = ? AND user_id = ?
    """, (ticket_id, session["user_id"])).fetchone()

    if not ticket:
        conn.close()
        flash("Ticket not found.", "error")
        return redirect(url_for("my_tickets"))

    if request.method == "POST":

        action = request.form.get("action", "")
        message = request.form.get("message", "").strip()

        # Customer closes ticket
        if action == "close":

            conn.execute("""
                UPDATE support_tickets
                SET status = 'Closed',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
            """, (
                ticket_id,
                session["user_id"]
            ))

            conn.commit()
            conn.close()

            flash("Ticket closed successfully.", "success")

            return redirect(
                url_for("view_ticket", ticket_id=ticket_id)
            )

        # Customer sends reply
        if action == "reply":

            if ticket["status"] == "Closed":
                conn.close()
                flash("This ticket is closed. Please create a new ticket.", "error")
                return redirect(
                    url_for("view_ticket", ticket_id=ticket_id)
                )

            if not message:
                conn.close()
                flash("Please enter a message.", "error")
                return redirect(
                    url_for("view_ticket", ticket_id=ticket_id)
                )

            conn.execute("""
                INSERT INTO ticket_messages
                (ticket_id, user_id, sender_type, message)
                VALUES (?, ?, 'Customer', ?)
            """, (
                ticket_id,
                session["user_id"],
                message
            ))

            conn.execute("""
                UPDATE support_tickets
                SET status = 'Open',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (ticket_id,))

            conn.commit()
            conn.close()

            flash("Your reply has been sent.", "success")

            return redirect(
                url_for("view_ticket", ticket_id=ticket_id)
            )

    messages = conn.execute("""
        SELECT *
        FROM ticket_messages
        WHERE ticket_id = ?
        ORDER BY id ASC
    """, (ticket_id,)).fetchall()

    conn.close()

    return render_template(
        "ticket_detail.html",
        ticket=ticket,
        messages=messages
    )

@app.route("/ai-assistant", methods=["GET", "POST"])
@login_required
def ai_assistant():

    answer = None
    question = ""

    if request.method == "POST":

        question = request.form.get("question", "").strip()

        if not question:
            flash("Please enter a question.", "error")
            return redirect(url_for("ai_assistant"))

        uid = session["user_id"]

        conn = get_db()

        # Get current month/year
        today = date.today()
        month = today.month
        year = today.year

        # Get income and expense
        income, expense = totals(uid, month, year)

        # Get budget
        budget_row = conn.execute(
            """
            SELECT amount
            FROM budgets
            WHERE user_id=? AND month=? AND year=?
            """,
            (uid, month, year)
        ).fetchone()

        budget_amount = float(budget_row["amount"]) if budget_row else 0

        # Get category spending
        category_rows = conn.execute(
            """
            SELECT category, SUM(amount) AS total
            FROM transactions
            WHERE user_id=?
            AND type='expense'
            AND strftime('%m', transaction_date)=?
            AND strftime('%Y', transaction_date)=?
            GROUP BY category
            ORDER BY total DESC
            """,
            (uid, f"{month:02d}", str(year))
        ).fetchall()

        conn.close()

        categories = []

        for row in category_rows:
            categories.append(
                f"{row['category']}: ₹{float(row['total']):.2f}"
            )

        category_text = ", ".join(categories)

        balance = income - expense

        # Simple AI-style financial assistant
        q = question.lower()

        if "spend" in q or "expense" in q:
            answer = (
                f"This month you have earned ₹{income:.2f} and "
                f"spent ₹{expense:.2f}. Your current balance is "
                f"₹{balance:.2f}."
            )

        elif "budget" in q:
            if budget_amount:
                remaining = budget_amount - expense

                answer = (
                    f"Your monthly budget is ₹{budget_amount:.2f}. "
                    f"You have used ₹{expense:.2f}, leaving "
                    f"₹{remaining:.2f}."
                )
            else:
                answer = (
                    "You have not set a monthly budget yet. "
                    "Set one from the Budget page so I can help "
                    "you track it."
                )

        elif "save" in q:
            savings = max(income - expense, 0)

            answer = (
                f"Based on your current numbers, you have "
                f"₹{savings:.2f} left after expenses this month. "
                f"Consider keeping part of this amount as savings "
                f"and maintaining an emergency fund."
            )

        elif "category" in q or "where" in q:
            if category_text:
                answer = (
                    "Your spending by category is: "
                    + category_text
                )
            else:
                answer = "You don't have expense data for this month yet."

        else:
            answer = (
                f"Here is your current financial summary: "
                f"income ₹{income:.2f}, expenses ₹{expense:.2f}, "
                f"balance ₹{balance:.2f}. "
                f"You can ask me about your spending, budget, "
                f"savings or categories."
            )

    return render_template(
        "ai_assistant.html",
        answer=answer,
        question=question
    )

client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY")
)

@app.route("/api/ai-chat", methods=["POST"])
@login_required
def ai_chat():

    try:

        data = request.get_json()
        question = data.get("question", "").strip()

        if not question:
            return jsonify({
                "answer": "Please ask me something."
            })

        api_key = os.environ.get("OPENAI_API_KEY")

        if not api_key:
            return jsonify({
                "answer": "AI is currently unavailable because the AI API key is not configured."
            }), 503

        client = OpenAI(api_key=api_key)

        response = client.responses.create(
            model="gpt-5.6-luna",
            instructions="""
You are SpendTrack AI, a helpful personal finance assistant
inside a monthly expense tracking application.

Answer the user's question directly and clearly.

If the question is about their finances, use the financial
information provided by the application.

Do not invent financial information.

If information is unavailable, clearly say that it is unavailable.

Use Indian Rupees (₹) when discussing money.

Keep answers simple and useful.
""",
            input=question
        )

        return jsonify({
            "answer": response.output_text
        })

    except Exception as e:

        print("AI ERROR:", repr(e))

        return jsonify({
            "answer": "AI error: " + str(e)
        }), 500


init_db()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=True
    )