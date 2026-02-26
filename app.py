import sqlite3
import os

import threading
import time
from datetime import datetime, timedelta, date
from calendar import monthrange

from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash

DB_FILE = "tirelire.db"




app = Flask(__name__)
app.secret_key = "change-me-please"  # change en prod


# --------------------- DB helpers ---------------------
def db_connect():
    con = sqlite3.connect(DB_FILE, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON;")
    return con


def init_db():
    con = db_connect()
    cur = con.cursor()

    # 1) Tables (création si inexistantes)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'parent'
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS children (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_user_id INTEGER,
        firstname TEXT NOT NULL,
        balance REAL NOT NULL DEFAULT 0,
        allowance REAL NOT NULL DEFAULT 0,
        frequency TEXT NOT NULL CHECK(frequency IN ('hebdomadaire','mensuelle')),
        paypal TEXT,
        iban TEXT,
        last_allowance_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        child_id INTEGER NOT NULL,
        op_type TEXT NOT NULL CHECK(op_type IN ('credit','debit','allowance')),
        amount REAL NOT NULL,
        method TEXT, -- Cash / Paypal / Banque / Auto
        created_at TEXT NOT NULL,
        note TEXT,
        FOREIGN KEY(child_id) REFERENCES children(id) ON DELETE CASCADE
    )
    """)

    con.commit()

    # 2) Migrations légères (si DB déjà existante)
    cur.execute("PRAGMA table_info(users)")
    user_cols = {r["name"] for r in cur.fetchall()}
    if "role" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'parent'")
        con.commit()

    cur.execute("PRAGMA table_info(children)")
    child_cols = {r["name"] for r in cur.fetchall()}
    if "owner_user_id" not in child_cols:
        cur.execute("ALTER TABLE children ADD COLUMN owner_user_id INTEGER")
        con.commit()

    # 3) Crée un utilisateur admin par défaut si aucun user
    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO users(username, password_hash, role) VALUES (?,?,?)",
            ("admin", generate_password_hash("admin123"), "admin")
        )
        con.commit()

    # 4) Assigne les enfants existants à l'admin si owner_user_id est NULL
    cur.execute("SELECT id FROM users WHERE username = ? LIMIT 1", ("admin",))
    admin_row = cur.fetchone()
    if admin_row:
        admin_id = admin_row["id"]
        cur.execute(
            "UPDATE children SET owner_user_id = ? WHERE owner_user_id IS NULL",
            (admin_id,)
        )
        con.commit()

    con.close()


def get_db():
    if "db" not in g:
        g.db = db_connect()
    return g.db


@app.route("/parent", methods=["GET", "POST"])
def parent_access():
    """
    Création d'un compte parent (username / mot de passe).
    Le parent pourra ensuite créer ses propres profils enfants.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username:
            flash("Le nom d'utilisateur est obligatoire.")
            return render_template("parent_access.html")

        if len(password) < 4:
            flash("Mot de passe trop court (minimum 4 caractères).")
            return render_template("parent_access.html")

        if password != confirm:
            flash("Les mots de passe ne correspondent pas.")
            return render_template("parent_access.html")

        db = get_db()
        exists = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            flash("Ce nom d'utilisateur existe déjà.")
            return render_template("parent_access.html")

        cur = db.execute(
            "INSERT INTO users(username, password_hash, role) VALUES (?,?,?)",
            (username, generate_password_hash(password), "parent")
        )
        db.commit()

        session.clear()
        session["user_id"] = cur.lastrowid
        session["username"] = username
        session["role"] = "parent"
        return redirect(url_for("home"))

    return render_template("parent_access.html")


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# --------------------- Auth ---------------------
def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))

        # ✅ Toujours recharger le rôle depuis la DB (même si session["role"] existe)
        db = get_db()
        user = db.execute(
            "SELECT username, role FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        if not user:
            session.clear()
            return redirect(url_for("login"))

        session["username"] = user["username"]
        session["role"] = user["role"] if user["role"] else ("admin" if user["username"] == "admin" else "parent")

        return fn(*args, **kwargs)

    return wrapper




@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"] if user["role"] else ("admin" if user["username"] == "admin" else "parent")
            return redirect(url_for("home"))

        flash("Identifiants invalides.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# Contrôle d'accès: un parent ne voit que SES enfants
def child_access_guard(child_row):
    if session.get("role") == "admin":
        return None
    if child_row is None:
        return None
    if child_row["owner_user_id"] != session.get("user_id"):
        flash("Accès non autorisé à ce profil enfant.")
        return redirect(url_for("home"))
    return None


# --------------------- Allowance scheduler ---------------------
def add_months(d: date, months: int) -> date:
    y = d.year + (d.month - 1 + months) // 12
    m = (d.month - 1 + months) % 12 + 1
    last_day = monthrange(y, m)[1]
    return date(y, m, min(d.day, last_day))


def next_due_date(last_dt: datetime, frequency: str) -> datetime:
    base = last_dt.date()
    if frequency == "hebdomadaire":
        return datetime.combine(base + timedelta(days=7), datetime.min.time())
    return datetime.combine(add_months(base, 1), datetime.min.time())


def scheduler_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            con = db_connect()
            cur = con.cursor()
            cur.execute("SELECT * FROM children")
            children = cur.fetchall()

            now = datetime.now()

            for ch in children:
                allowance = float(ch["allowance"])
                if allowance <= 0:
                    continue

                freq = ch["frequency"]
                last = ch["last_allowance_at"]

                if not last:
                    cur.execute(
                        "UPDATE children SET last_allowance_at = ? WHERE id = ?",
                        (now.isoformat(timespec="seconds"), ch["id"])
                    )
                    con.commit()
                    continue

                last_dt = datetime.fromisoformat(last)
                due = next_due_date(last_dt, freq)

                while now >= due:
                    cur.execute("UPDATE children SET balance = balance + ? WHERE id = ?", (allowance, ch["id"]))
                    cur.execute("""
                        INSERT INTO operations(child_id, op_type, amount, method, created_at, note)
                        VALUES (?,?,?,?,?,?)
                    """, (ch["id"], "allowance", allowance, "Auto", now.isoformat(timespec="seconds"),
                          f"Argent de poche ({freq})"))
                    last_dt = due
                    due = next_due_date(last_dt, freq)

                cur.execute("UPDATE children SET last_allowance_at = ? WHERE id = ?",
                            (last_dt.isoformat(timespec="seconds"), ch["id"]))
                con.commit()

            con.close()
        except Exception:
            pass

        stop_event.wait(20)


stop_event = threading.Event()
scheduler_thread = threading.Thread(target=scheduler_loop, args=(stop_event,), daemon=True)


# --------------------- Routes (Tirelire) ---------------------
@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("home"))
    return redirect(url_for("login"))


@app.route("/home")
@login_required
def home():
    db = get_db()
    print("DB USED BY FLASK:", os.path.abspath(DB_FILE))

    user = db.execute("SELECT id, username, role FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    print("CONNECTED USER:", dict(user) if user else None)

    children_all = db.execute("SELECT id, firstname, owner_user_id FROM children ORDER BY id").fetchall()
    print("CHILDREN IN THIS DB:", [dict(c) for c in children_all])

    role = user["role"] if user else "parent"
    if role == "admin":
        children = db.execute("SELECT * FROM children ORDER BY firstname COLLATE NOCASE").fetchall()
    else:
        children = db.execute("SELECT * FROM children WHERE owner_user_id = ? ORDER BY firstname COLLATE NOCASE",
                              (session["user_id"],)).fetchall()

    return render_template("home.html", children=children)

@app.route("/children/new", methods=["GET", "POST"])
@login_required
def child_new():
    if request.method == "POST":
        firstname = request.form.get("firstname", "").strip()
        balance = request.form.get("balance", "0").strip()
        allowance = request.form.get("allowance", "0").strip()
        frequency = request.form.get("frequency", "").strip()
        paypal = request.form.get("paypal", "").strip() or None
        iban = request.form.get("iban", "").strip() or None

        if not firstname:
            flash("Le prénom est obligatoire.")
            return render_template("child_form.html", child=None)

        try:
            balance_f = float(balance)
            allowance_f = float(allowance)
        except ValueError:
            flash("Solde et argent de poche doivent être des nombres.")
            return render_template("child_form.html", child=None)

        if frequency not in ("hebdomadaire", "mensuelle"):
            flash("Fréquence invalide.")
            return render_template("child_form.html", child=None)

        db = get_db()
        now = datetime.now().isoformat(timespec="seconds")
        owner_id = session.get("user_id")

        cur = db.execute("""
            INSERT INTO children(owner_user_id, firstname, balance, allowance, frequency, paypal, iban, last_allowance_at)
            VALUES (?,?,?,?,?,?,?,?)
        """, (owner_id, firstname, balance_f, allowance_f, frequency, paypal, iban, now))
        child_id = cur.lastrowid

        if allowance_f > 0:
            db.execute("UPDATE children SET balance = balance + ? WHERE id = ?", (allowance_f, child_id))
            db.execute("""
                INSERT INTO operations(child_id, op_type, amount, method, created_at, note)
                VALUES (?,?,?,?,?,?)
            """, (child_id, "allowance", allowance_f, "Auto", now, f"Argent de poche ({frequency}) - premier versement"))

        if balance_f != 0:
            db.execute("""
                INSERT INTO operations(child_id, op_type, amount, method, created_at, note)
                VALUES (?,?,?,?,?,?)
            """, (child_id, "credit" if balance_f > 0 else "debit", abs(balance_f), "Init", now, "Solde de départ"))

        db.commit()
        return redirect(url_for("child_profile", child_id=child_id))

    return render_template("child_form.html", child=None)


@app.route("/children/<int:child_id>/edit", methods=["GET", "POST"])
@login_required
def child_edit(child_id: int):
    db = get_db()
    child = db.execute("SELECT * FROM children WHERE id = ?", (child_id,)).fetchone()
    if not child:
        flash("Enfant introuvable.")
        return redirect(url_for("home"))
    resp = child_access_guard(child)
    if resp:
        return resp

    if request.method == "POST":
        firstname = request.form.get("firstname", "").strip()
        allowance = request.form.get("allowance", "0").strip()
        frequency = request.form.get("frequency", "").strip()
        paypal = request.form.get("paypal", "").strip() or None
        iban = request.form.get("iban", "").strip() or None

        if not firstname:
            flash("Le prénom est obligatoire.")
            return render_template("child_form.html", child=child)

        try:
            allowance_f = float(allowance)
        except ValueError:
            flash("Argent de poche invalide.")
            return render_template("child_form.html", child=child)

        if frequency not in ("hebdomadaire", "mensuelle"):
            flash("Fréquence invalide.")
            return render_template("child_form.html", child=child)

        db.execute("""
            UPDATE children
            SET firstname=?, allowance=?, frequency=?, paypal=?, iban=?
            WHERE id=?
        """, (firstname, allowance_f, frequency, paypal, iban, child_id))
        db.commit()
        return redirect(url_for("child_profile", child_id=child_id))

    return render_template("child_form.html", child=child)


@app.route("/children/<int:child_id>")
@login_required
def child_profile(child_id: int):
    db = get_db()
    child = db.execute("SELECT * FROM children WHERE id = ?", (child_id,)).fetchone()
    if not child:
        flash("Enfant introuvable.")
        return redirect(url_for("home"))
    resp = child_access_guard(child)
    if resp:
        return resp
    return render_template("child_profile.html", child=child)


@app.route("/children/<int:child_id>/add", methods=["GET", "POST"])
@login_required
def child_add(child_id: int):
    db = get_db()
    child = db.execute("SELECT * FROM children WHERE id = ?", (child_id,)).fetchone()
    if not child:
        flash("Enfant introuvable.")
        return redirect(url_for("home"))
    resp = child_access_guard(child)
    if resp:
        return resp

    if request.method == "POST":
        amount = request.form.get("amount", "").strip()
        try:
            amt = float(amount)
            if amt <= 0:
                raise ValueError
        except ValueError:
            flash("Montant invalide (doit être > 0).")
            return render_template("add.html", child=child)

        now = datetime.now().isoformat(timespec="seconds")
        db.execute("UPDATE children SET balance = balance + ? WHERE id = ?", (amt, child_id))
        db.execute("""
            INSERT INTO operations(child_id, op_type, amount, method, created_at, note)
            VALUES (?,?,?,?,?,?)
        """, (child_id, "credit", amt, "Manuel", now, "Ajout manuel"))
        db.commit()
        return redirect(url_for("child_profile", child_id=child_id))

    return render_template("add.html", child=child)


@app.route("/children/<int:child_id>/withdraw", methods=["GET", "POST"])
@login_required
def child_withdraw(child_id: int):
    db = get_db()
    child = db.execute("SELECT * FROM children WHERE id = ?", (child_id,)).fetchone()
    if not child:
        flash("Enfant introuvable.")
        return redirect(url_for("home"))
    resp = child_access_guard(child)
    if resp:
        return resp

    has_paypal = bool(child["paypal"])
    has_iban = bool(child["iban"])

    if request.method == "POST":
        amount = request.form.get("amount", "").strip()
        method = request.form.get("method", "").strip()  # Cash/Paypal/Banque

        try:
            amt = float(amount)
            if amt <= 0:
                raise ValueError
        except ValueError:
            flash("Montant invalide (doit être > 0).")
            return render_template("withdraw.html", child=child, has_paypal=has_paypal, has_iban=has_iban)

        if method not in ("Cash", "Paypal", "Banque"):
            flash("Méthode invalide.")
            return render_template("withdraw.html", child=child, has_paypal=has_paypal, has_iban=has_iban)

        if method == "Paypal" and not has_paypal:
            flash("Paypal non renseigné pour cet enfant.")
            return render_template("withdraw.html", child=child, has_paypal=has_paypal, has_iban=has_iban)

        if method == "Banque" and not has_iban:
            flash("IBAN non renseigné pour cet enfant.")
            return render_template("withdraw.html", child=child, has_paypal=has_paypal, has_iban=has_iban)

        balance = float(child["balance"])
        if amt > balance:
            flash("Solde insuffisant.")
            return render_template("withdraw.html", child=child, has_paypal=has_paypal, has_iban=has_iban)

        now = datetime.now().isoformat(timespec="seconds")

        db.execute("UPDATE children SET balance = balance - ? WHERE id = ?", (amt, child_id))
        note = "Retrait cash" if method == "Cash" else f"Virement vers {method} (simulé)"
        db.execute("""
            INSERT INTO operations(child_id, op_type, amount, method, created_at, note)
            VALUES (?,?,?,?,?,?)
        """, (child_id, "debit", amt, method, now, note))
        db.commit()
        return redirect(url_for("child_profile", child_id=child_id))

    return render_template("withdraw.html", child=child, has_paypal=has_paypal, has_iban=has_iban)


@app.route("/children/<int:child_id>/history")
@login_required
def child_history(child_id: int):
    db = get_db()
    child = db.execute("SELECT * FROM children WHERE id = ?", (child_id,)).fetchone()
    if not child:
        flash("Enfant introuvable.")
        return redirect(url_for("home"))
    resp = child_access_guard(child)
    if resp:
        return resp

    ops = db.execute("""
        SELECT * FROM operations
        WHERE child_id = ?
        ORDER BY datetime(created_at) DESC
    """, (child_id,)).fetchall()

    return render_template("history.html", child=child, ops=ops)


@app.route("/child/<int:child_id>/delete", methods=["POST"])
@login_required
def child_delete(child_id):
    db = get_db()

    child = db.execute("SELECT id FROM children WHERE id = ?", (child_id,)).fetchone()
    if not child:
        flash("Enfant introuvable.")
        return redirect(url_for("home"))

    full_child = db.execute("SELECT * FROM children WHERE id = ?", (child_id,)).fetchone()
    resp = child_access_guard(full_child)
    if resp:
        return resp

    db.execute("DELETE FROM operations WHERE child_id = ?", (child_id,))
    db.execute("DELETE FROM children WHERE id = ?", (child_id,))
    db.commit()

    flash("Profil enfant supprimé.")
    return redirect(url_for("home"))


# --------------------- Main ---------------------
if __name__ == "__main__":
    init_db()
    if not scheduler_thread.is_alive():
        scheduler_thread.start()
    app.run(debug=True)
