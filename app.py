# 3. Create the database, secure admin account, and complete Hospital Management System
import sqlite3, os, hashlib, secrets, hmac
from datetime import datetime, date
import gradio as gr
import pandas as pd

# ---------- DATABASE ----------
DB_PATH = os.environ.get("DB_PATH", "hospital_management.db")

def db():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      user_id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('Admin','Receptionist','Doctor')),
      doctor_id INTEGER,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS departments(
      department_id INTEGER PRIMARY KEY AUTOINCREMENT,
      department_name TEXT NOT NULL UNIQUE,
      description TEXT DEFAULT '',
      is_active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS doctors(
      doctor_id INTEGER PRIMARY KEY AUTOINCREMENT,
      doctor_name TEXT NOT NULL,
      specialization TEXT NOT NULL,
      contact TEXT DEFAULT '',
      email TEXT DEFAULT '',
      department_id INTEGER,
      consultation_fee REAL NOT NULL DEFAULT 0 CHECK(consultation_fee>=0),
      is_active INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY(department_id) REFERENCES departments(department_id)
    );
    CREATE TABLE IF NOT EXISTS patients(
      patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_name TEXT NOT NULL,
      age INTEGER,
      gender TEXT DEFAULT '',
      contact TEXT DEFAULT '',
      email TEXT DEFAULT '',
      address TEXT DEFAULT '',
      blood_group TEXT DEFAULT '',
      medical_history TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS appointments(
      appointment_id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_id INTEGER NOT NULL,
      doctor_id INTEGER NOT NULL,
      appointment_date TEXT NOT NULL,
      appointment_time TEXT NOT NULL,
      reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending'
        CHECK(status IN ('Pending','Confirmed','Completed','Cancelled')),
      created_by INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(patient_id) REFERENCES patients(patient_id),
      FOREIGN KEY(doctor_id) REFERENCES doctors(doctor_id),
      FOREIGN KEY(created_by) REFERENCES users(user_id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uq_doctor_active_slot
      ON appointments(doctor_id, appointment_date, appointment_time)
      WHERE status <> 'Cancelled';
    CREATE TABLE IF NOT EXISTS consultations(
      consultation_id INTEGER PRIMARY KEY AUTOINCREMENT,
      appointment_id INTEGER NOT NULL UNIQUE,
      symptoms TEXT DEFAULT '',
      diagnosis TEXT NOT NULL,
      treatment_notes TEXT DEFAULT '',
      follow_up_date TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(appointment_id) REFERENCES appointments(appointment_id)
    );
    CREATE TABLE IF NOT EXISTS medicines(
      medicine_id INTEGER PRIMARY KEY AUTOINCREMENT,
      medicine_name TEXT NOT NULL,
      category TEXT DEFAULT '',
      strength TEXT DEFAULT '',
      quantity INTEGER NOT NULL DEFAULT 0 CHECK(quantity>=0),
      unit TEXT DEFAULT 'unit',
      selling_price REAL NOT NULL DEFAULT 0 CHECK(selling_price>=0),
      expiry_date TEXT DEFAULT '',
      low_stock_level INTEGER NOT NULL DEFAULT 5
    );
    CREATE TABLE IF NOT EXISTS stock_movements(
      movement_id INTEGER PRIMARY KEY AUTOINCREMENT,
      medicine_id INTEGER NOT NULL,
      movement_type TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      notes TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(medicine_id) REFERENCES medicines(medicine_id)
    );
    CREATE TABLE IF NOT EXISTS prescriptions(
      prescription_id INTEGER PRIMARY KEY AUTOINCREMENT,
      appointment_id INTEGER NOT NULL,
      diagnosis TEXT DEFAULT '',
      instructions TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(appointment_id) REFERENCES appointments(appointment_id)
    );
    CREATE TABLE IF NOT EXISTS prescription_items(
      item_id INTEGER PRIMARY KEY AUTOINCREMENT,
      prescription_id INTEGER NOT NULL,
      medicine_id INTEGER,
      medicine_name TEXT NOT NULL,
      dosage TEXT DEFAULT '',
      frequency TEXT DEFAULT '',
      duration TEXT DEFAULT '',
      instructions TEXT DEFAULT '',
      FOREIGN KEY(prescription_id) REFERENCES prescriptions(prescription_id),
      FOREIGN KEY(medicine_id) REFERENCES medicines(medicine_id)
    );
    CREATE TABLE IF NOT EXISTS bills(
      bill_id INTEGER PRIMARY KEY AUTOINCREMENT,
      patient_id INTEGER NOT NULL,
      appointment_id INTEGER,
      consultation_fee REAL NOT NULL DEFAULT 0,
      medicine_charges REAL NOT NULL DEFAULT 0,
      other_charges REAL NOT NULL DEFAULT 0,
      total_amount REAL NOT NULL DEFAULT 0,
      paid_amount REAL NOT NULL DEFAULT 0,
      payment_status TEXT NOT NULL DEFAULT 'Unpaid',
      bill_date TEXT NOT NULL,
      FOREIGN KEY(patient_id) REFERENCES patients(patient_id),
      FOREIGN KEY(appointment_id) REFERENCES appointments(appointment_id)
    );
    CREATE TABLE IF NOT EXISTS payments(
      payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
      bill_id INTEGER NOT NULL,
      amount REAL NOT NULL CHECK(amount>0),
      payment_method TEXT DEFAULT 'Cash',
      payment_date TEXT NOT NULL,
      FOREIGN KEY(bill_id) REFERENCES bills(bill_id)
    );
    """)
    con.commit()
    con.close()

def hash_password(password):
    salt = secrets.token_hex(16)
    iterations = 350000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"

def verify_password(password, stored):
    try:
        algo, iterations, salt, digest = stored.split("$")
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations)).hex()
        return hmac.compare_digest(check, digest)
    except Exception:
        return False

def create_admin_if_needed():
    con = db()
    count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    con.close()
    if count == 0:
        username = os.environ.get("ADMIN_USERNAME", "").strip()
        password = os.environ.get("ADMIN_PASSWORD", "")
        if len(username) < 4 or len(password) < 10:
            raise RuntimeError(
                "First launch requires ADMIN_USERNAME (at least 4 characters) "
                "and ADMIN_PASSWORD (at least 10 characters) environment variables."
            )
        con = db()
        con.execute(
            "INSERT INTO users(username,password_hash,role) VALUES(?,?, 'Admin')",
            (username, hash_password(password))
        )
        con.commit()
        con.close()
        print("Initial Administrator account created.")
    else:
        print("Existing user accounts found.")

init_db()
create_admin_if_needed()

# ---------- SHARED HELPERS ----------
def rows_df(sql, params=()):
    con = db()
    rows = con.execute(sql, params).fetchall()
    con.close()
    return pd.DataFrame([dict(r) for r in rows])

def is_allowed(user, roles):
    return bool(user and user.get("role") in roles)

def login_user(username, password):
    con = db()
    row = con.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username.strip(),)).fetchone()
    con.close()
    if row and verify_password(password, row["password_hash"]):
        return {"user_id": row["user_id"], "username": row["username"], "role": row["role"], "doctor_id": row["doctor_id"]}
    return None

def patient_choices():
    df = rows_df("SELECT patient_id, patient_name FROM patients ORDER BY patient_name")
    return [(f"{r.patient_name} (ID {r.patient_id})", int(r.patient_id)) for r in df.itertuples()]

def doctor_choices():
    df = rows_df("""SELECT d.doctor_id,d.doctor_name,d.specialization,dep.department_name
                    FROM doctors d LEFT JOIN departments dep USING(department_id)
                    WHERE d.is_active=1 ORDER BY d.doctor_name""")
    return [(f"{r.doctor_name} - {r.specialization} (ID {r.doctor_id})", int(r.doctor_id)) for r in df.itertuples()]

def dept_choices():
    df = rows_df("SELECT department_id,department_name FROM departments WHERE is_active=1 ORDER BY department_name")
    return [(r.department_name, int(r.department_id)) for r in df.itertuples()]

def medicine_choices():
    df = rows_df("SELECT medicine_id,medicine_name FROM medicines ORDER BY medicine_name")
    return [(f"{r.medicine_name} (ID {r.medicine_id})", int(r.medicine_id)) for r in df.itertuples()]

def msg_and_df(message, sql, params=()):
    return message, rows_df(sql, params)

# ---------- AUTHENTICATION ----------
def do_login(username, password):
    user = login_user(username, password)
    if not user:
        return None, gr.update(visible=True), gr.update(visible=False), "Invalid username or password."
    return user, gr.update(visible=False), gr.update(visible=True), f"Signed in as {user['username']} ({user['role']})."

def do_logout():
    return None, gr.update(visible=True), gr.update(visible=False), "", ""

# ---------- DASHBOARD ----------
def dashboard(user):
    if not user: return pd.DataFrame()
    con = db()
    data = [
      ("Patients", con.execute("SELECT COUNT(*) FROM patients").fetchone()[0]),
      ("Active doctors", con.execute("SELECT COUNT(*) FROM doctors WHERE is_active=1").fetchone()[0]),
      ("Departments", con.execute("SELECT COUNT(*) FROM departments WHERE is_active=1").fetchone()[0]),
      ("Appointments today", con.execute("SELECT COUNT(*) FROM appointments WHERE appointment_date=?",(date.today().isoformat(),)).fetchone()[0]),
      ("Pending appointments", con.execute("SELECT COUNT(*) FROM appointments WHERE status='Pending'").fetchone()[0]),
      ("Unpaid / partial bills", con.execute("SELECT COUNT(*) FROM bills WHERE payment_status<>'Paid'").fetchone()[0])
    ]
    con.close()
    return pd.DataFrame(data, columns=["Metric","Count"])

# ---------- DEPARTMENTS ----------
def add_department(name, description, user):
    if not is_allowed(user, ["Admin"]): return "Only Admin can add departments.", rows_df("SELECT * FROM departments")
    if not name.strip(): return "Department name is required.", rows_df("SELECT * FROM departments")
    try:
        con=db(); con.execute("INSERT INTO departments(department_name,description) VALUES(?,?)",(name.strip(),description.strip())); con.commit(); con.close()
        return "Department added.", rows_df("SELECT * FROM departments")
    except sqlite3.IntegrityError: return "Department already exists.", rows_df("SELECT * FROM departments")

# ---------- PATIENTS ----------
def add_patient(name, age, gender, contact, email, address, blood, history, user):
    if not is_allowed(user, ["Admin","Receptionist"]): return "Admin/Receptionist access required.", rows_df("SELECT * FROM patients")
    if not name.strip(): return "Patient name is required.", rows_df("SELECT * FROM patients")
    try:
        age_value = int(age) if age not in (None,"") else None
        if age_value is not None and not 0 <= age_value <= 120: raise ValueError()
    except Exception: return "Age must be a whole number from 0 to 120.", rows_df("SELECT * FROM patients")
    con=db()
    con.execute("""INSERT INTO patients(patient_name,age,gender,contact,email,address,blood_group,medical_history)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (name.strip(),age_value,gender,contact,email,address,blood,history))
    con.commit(); con.close()
    return "Patient registered successfully.", rows_df("SELECT * FROM patients ORDER BY patient_id DESC")

def search_patients(term):
    term = (term or "").strip()
    return rows_df("""SELECT * FROM patients WHERE CAST(patient_id AS TEXT) LIKE ?
                      OR patient_name LIKE ? OR contact LIKE ? ORDER BY patient_id DESC""",
                   (f"%{term}%",f"%{term}%",f"%{term}%"))

# ---------- DOCTORS ----------
def add_doctor(name, specialization, contact, email, department_id, fee, user):
    if not is_allowed(user, ["Admin"]): return "Only Admin can add doctors.", rows_df("SELECT * FROM doctors")
    if not name.strip() or not specialization.strip() or not department_id: return "Name, specialization and department are required.", rows_df("SELECT * FROM doctors")
    try:
        con=db()
        con.execute("""INSERT INTO doctors(doctor_name,specialization,contact,email,department_id,consultation_fee)
                       VALUES(?,?,?,?,?,?)""",(name.strip(),specialization.strip(),contact,email,int(department_id),float(fee or 0)))
        con.commit(); con.close()
        return "Doctor added successfully.", rows_df("""SELECT d.*,dep.department_name FROM doctors d LEFT JOIN departments dep USING(department_id)""")
    except Exception as e: return f"Could not add doctor: {e}", rows_df("SELECT * FROM doctors")

# ---------- APPOINTMENTS ----------
def book_appt(patient_id, doctor_id, appt_date, appt_time, reason, user):
    if not is_allowed(user, ["Admin","Receptionist"]): return "Admin/Receptionist access required.", rows_df("SELECT * FROM appointments")
    if not all([patient_id,doctor_id,appt_date,appt_time,reason and reason.strip()]): return "Complete all appointment fields.", rows_df("SELECT * FROM appointments")
    try:
        dt=datetime.strptime(appt_date,"%Y-%m-%d").date()
        tm=datetime.strptime(appt_time,"%H:%M").time()
        if datetime.combine(dt,tm) <= datetime.now(): return "Choose a future date and time.", rows_df("SELECT * FROM appointments")
        con=db()
        cur=con.execute("""INSERT INTO appointments(patient_id,doctor_id,appointment_date,appointment_time,reason,created_by)
                           VALUES(?,?,?,?,?,?)""",(int(patient_id),int(doctor_id),appt_date,appt_time,reason.strip(),user["user_id"]))
        con.commit(); new_id=cur.lastrowid; con.close()
        return f"Appointment #{new_id} booked. Status: Pending.", rows_df("""SELECT a.appointment_id,p.patient_name,d.doctor_name,a.appointment_date,a.appointment_time,a.reason,a.status
          FROM appointments a JOIN patients p USING(patient_id) JOIN doctors d USING(doctor_id) ORDER BY a.appointment_id DESC""")
    except sqlite3.IntegrityError: return "This doctor already has an active appointment at that exact time.", rows_df("SELECT * FROM appointments")
    except ValueError: return "Use date YYYY-MM-DD and time HH:MM (24-hour).", rows_df("SELECT * FROM appointments")
    except Exception as e: return f"Booking error: {e}", rows_df("SELECT * FROM appointments")

def appointment_list(user):
    if not user: return pd.DataFrame()
    sql="""SELECT a.appointment_id,p.patient_name,d.doctor_name,a.appointment_date,a.appointment_time,a.reason,a.status
           FROM appointments a JOIN patients p USING(patient_id) JOIN doctors d USING(doctor_id)"""
    params=()
    if user["role"]=="Doctor":
        sql += " WHERE d.doctor_id=?"; params=(user["doctor_id"],)
    sql += " ORDER BY a.appointment_date DESC,a.appointment_time DESC"
    return rows_df(sql,params)

def update_appt_status(appt_id,status,user):
    if not is_allowed(user,["Admin","Receptionist"]): return "Admin/Receptionist access required.", appointment_list(user)
    try:
        con=db(); cur=con.execute("UPDATE appointments SET status=? WHERE appointment_id=?",(status,int(appt_id))); con.commit(); con.close()
        if not cur.rowcount: return "Appointment ID not found.", appointment_list(user)
        return "Appointment status updated.", appointment_list(user)
    except Exception as e: return f"Update error: {e}", appointment_list(user)

# ---------- CONSULTATIONS ----------
def save_consultation(appt_id, symptoms, diagnosis, treatment, followup, user):
    if not is_allowed(user,["Admin","Doctor"]): return "Only a doctor or Admin can record consultations.", rows_df("SELECT * FROM consultations")
    if not appt_id or not diagnosis.strip(): return "Appointment ID and diagnosis are required.", rows_df("SELECT * FROM consultations")
    try:
        con=db()
        appt=con.execute("SELECT doctor_id FROM appointments WHERE appointment_id=?",(int(appt_id),)).fetchone()
        if not appt: con.close(); return "Appointment not found.", rows_df("SELECT * FROM consultations")
        if user["role"]=="Doctor" and user["doctor_id"] != appt["doctor_id"]:
            con.close(); return "You can only access your own appointments.", rows_df("SELECT * FROM consultations")
        con.execute("""INSERT INTO consultations(appointment_id,symptoms,diagnosis,treatment_notes,follow_up_date)
                       VALUES(?,?,?,?,?) ON CONFLICT(appointment_id) DO UPDATE SET
                       symptoms=excluded.symptoms, diagnosis=excluded.diagnosis,
                       treatment_notes=excluded.treatment_notes, follow_up_date=excluded.follow_up_date""",
                    (int(appt_id),symptoms,diagnosis.strip(),treatment,followup))
        con.commit(); con.close()
        return "Consultation saved.", rows_df("SELECT * FROM consultations ORDER BY consultation_id DESC")
    except Exception as e: return f"Consultation error: {e}", rows_df("SELECT * FROM consultations")

# ---------- MEDICINES / STOCK ----------
def add_medicine(name, category, strength, quantity, unit, price, expiry, low_level, user):
    if not is_allowed(user,["Admin"]): return "Only Admin can add medicines.", rows_df("SELECT * FROM medicines")
    if not name.strip(): return "Medicine name is required.", rows_df("SELECT * FROM medicines")
    try:
        q=int(quantity); p=float(price or 0); low=int(low_level or 5)
        if q<0 or p<0 or low<0: raise ValueError()
        con=db(); cur=con.execute("""INSERT INTO medicines(medicine_name,category,strength,quantity,unit,selling_price,expiry_date,low_stock_level)
          VALUES(?,?,?,?,?,?,?,?)""",(name.strip(),category,strength,q,unit,p,expiry,low))
        mid=cur.lastrowid
        if q: con.execute("INSERT INTO stock_movements(medicine_id,movement_type,quantity,notes) VALUES(?,?,?,?)",(mid,"Stock In",q,"Opening stock"))
        con.commit(); con.close()
        return "Medicine added.", rows_df("SELECT * FROM medicines")
    except Exception as e: return f"Medicine error: {e}", rows_df("SELECT * FROM medicines")

def adjust_stock(medicine_id, qty, movement, notes, user):
    if not is_allowed(user,["Admin"]): return "Only Admin can adjust stock.", rows_df("SELECT * FROM medicines")
    try:
        qty=int(qty)
        if qty<=0: return "Quantity must be greater than zero.", rows_df("SELECT * FROM medicines")
        con=db()
        med=con.execute("SELECT quantity FROM medicines WHERE medicine_id=?",(int(medicine_id),)).fetchone()
        if not med: con.close(); return "Medicine not found.", rows_df("SELECT * FROM medicines")
        newq=med["quantity"]+qty if movement=="Stock In" else med["quantity"]-qty
        if newq<0: con.close(); return "Not enough stock available.", rows_df("SELECT * FROM medicines")
        con.execute("UPDATE medicines SET quantity=? WHERE medicine_id=?",(newq,int(medicine_id)))
        con.execute("INSERT INTO stock_movements(medicine_id,movement_type,quantity,notes) VALUES(?,?,?,?)",(int(medicine_id),movement,qty,notes))
        con.commit(); con.close()
        return "Stock updated.", rows_df("SELECT * FROM medicines")
    except Exception as e: return f"Stock error: {e}", rows_df("SELECT * FROM medicines")

# ---------- PRESCRIPTIONS ----------
def create_prescription(appt_id, diagnosis, medicine_id, medicine_name, dosage, frequency, duration, instructions, user):
    if not is_allowed(user,["Admin","Doctor"]): return "Doctor/Admin access required.", rows_df("SELECT * FROM prescriptions")
    try:
        con=db()
        appt=con.execute("SELECT doctor_id,patient_id FROM appointments WHERE appointment_id=?",(int(appt_id),)).fetchone()
        if not appt: con.close(); return "Appointment not found.", rows_df("SELECT * FROM prescriptions")
        if user["role"]=="Doctor" and user["doctor_id"] != appt["doctor_id"]:
            con.close(); return "You can only prescribe for your own appointments.", rows_df("SELECT * FROM prescriptions")
        cur=con.execute("INSERT INTO prescriptions(appointment_id,diagnosis,instructions) VALUES(?,?,?)",(int(appt_id),diagnosis,instructions))
        pid=cur.lastrowid
        if medicine_name.strip():
            con.execute("""INSERT INTO prescription_items(prescription_id,medicine_id,medicine_name,dosage,frequency,duration,instructions)
                           VALUES(?,?,?,?,?,?,?)""",(pid,int(medicine_id) if medicine_id else None,medicine_name.strip(),dosage,frequency,duration,instructions))
        con.commit(); con.close()
        return f"Prescription #{pid} saved.", rows_df("SELECT * FROM prescriptions ORDER BY prescription_id DESC")
    except Exception as e: return f"Prescription error: {e}", rows_df("SELECT * FROM prescriptions")

# ---------- BILLING / PAYMENTS ----------
def create_bill(patient_id, appt_id, consultation_fee, medicine_charges, other_charges, user):
    if not is_allowed(user,["Admin","Receptionist"]): return "Admin/Receptionist access required.", rows_df("SELECT * FROM bills")
    try:
        fee=float(consultation_fee or 0); med=float(medicine_charges or 0); other=float(other_charges or 0)
        if min(fee,med,other)<0: return "Charges cannot be negative.", rows_df("SELECT * FROM bills")
        total=fee+med+other
        con=db()
        cur=con.execute("""INSERT INTO bills(patient_id,appointment_id,consultation_fee,medicine_charges,other_charges,total_amount,bill_date)
                           VALUES(?,?,?,?,?,?,?)""",(int(patient_id),int(appt_id) if appt_id else None,fee,med,other,total,date.today().isoformat()))
        bid=cur.lastrowid; con.commit(); con.close()
        return f"Bill #{bid} created. Total: {total:.2f}", rows_df("SELECT * FROM bills ORDER BY bill_id DESC")
    except Exception as e: return f"Billing error: {e}", rows_df("SELECT * FROM bills")

def record_payment(bill_id, amount, method, user):
    if not is_allowed(user,["Admin","Receptionist"]): return "Admin/Receptionist access required.", rows_df("SELECT * FROM bills")
    try:
        amount=float(amount)
        if amount<=0: return "Payment must be greater than zero.", rows_df("SELECT * FROM bills")
        con=db()
        bill=con.execute("SELECT total_amount,paid_amount FROM bills WHERE bill_id=?",(int(bill_id),)).fetchone()
        if not bill: con.close(); return "Bill not found.", rows_df("SELECT * FROM bills")
        if bill["paid_amount"]+amount > bill["total_amount"]+0.0001:
            con.close(); return "Payment exceeds outstanding balance.", rows_df("SELECT * FROM bills")
        paid=bill["paid_amount"]+amount
        status="Paid" if paid >= bill["total_amount"] else "Partially Paid"
        con.execute("INSERT INTO payments(bill_id,amount,payment_method,payment_date) VALUES(?,?,?,?)",(int(bill_id),amount,method,date.today().isoformat()))
        con.execute("UPDATE bills SET paid_amount=?,payment_status=? WHERE bill_id=?",(paid,status,int(bill_id)))
        con.commit(); con.close()
        return "Payment recorded.", rows_df("SELECT * FROM bills ORDER BY bill_id DESC")
    except Exception as e: return f"Payment error: {e}", rows_df("SELECT * FROM bills")

# ---------- USER MANAGEMENT ----------
def add_staff(username,password,role,doctor_id,user):
    if not is_allowed(user,["Admin"]): return "Only Admin can create staff accounts.", rows_df("SELECT user_id,username,role,doctor_id,is_active,created_at FROM users")
    if len(username.strip())<4 or len(password)<10: return "Username must be 4+ characters and password 10+ characters.", rows_df("SELECT user_id,username,role,doctor_id,is_active,created_at FROM users")
    if role=="Doctor" and not doctor_id: return "Select the doctor profile for this login.", rows_df("SELECT user_id,username,role,doctor_id,is_active,created_at FROM users")
    try:
        con=db(); con.execute("INSERT INTO users(username,password_hash,role,doctor_id) VALUES(?,?,?,?)",(username.strip(),hash_password(password),role,int(doctor_id) if role=="Doctor" else None)); con.commit(); con.close()
        return "Staff account created.", rows_df("SELECT user_id,username,role,doctor_id,is_active,created_at FROM users")
    except sqlite3.IntegrityError: return "Username already exists.", rows_df("SELECT user_id,username,role,doctor_id,is_active,created_at FROM users")

# ---------- REPORTS ----------
def report_data(user):
    if not user: return pd.DataFrame()
    return rows_df("""SELECT
      (SELECT COUNT(*) FROM patients) AS total_patients,
      (SELECT COUNT(*) FROM doctors WHERE is_active=1) AS active_doctors,
      (SELECT COUNT(*) FROM appointments WHERE appointment_date=?) AS appointments_today,
      (SELECT COUNT(*) FROM appointments WHERE status='Completed') AS completed_appointments,
      (SELECT COALESCE(SUM(total_amount),0) FROM bills) AS billed_total,
      (SELECT COALESCE(SUM(paid_amount),0) FROM bills) AS received_total""",(date.today().isoformat(),))

# ---------- GRADIO UI ----------
with gr.Blocks(title="Hospital Management System", theme=gr.themes.Soft()) as app:
    session = gr.State(None)
    gr.Markdown("# 🏥 Hospital Management System")
    gr.Markdown("Academic project application. Use fictional test records only.")
    with gr.Group(visible=True) as login_panel:
        gr.Markdown("### Staff Login")
        login_name=gr.Textbox(label="Username")
        login_pass=gr.Textbox(label="Password",type="password")
        login_btn=gr.Button("Login",variant="primary")
        login_msg=gr.Textbox(label="Message",interactive=False)
    with gr.Group(visible=False) as main_panel:
        with gr.Row():
            who=gr.Markdown()
            logout_btn=gr.Button("Logout")
        with gr.Tabs():
            with gr.Tab("Dashboard"):
                dash_btn=gr.Button("Refresh Dashboard")
                dash_table=gr.Dataframe(label="Hospital Summary",interactive=False)
            with gr.Tab("Patients"):
                gr.Markdown("#### Register Patient")
                p_name=gr.Textbox(label="Full name")
                with gr.Row():
                    p_age=gr.Number(label="Age",precision=0)
                    p_gender=gr.Dropdown(["Female","Male","Other"],label="Gender")
                    p_blood=gr.Dropdown(["","A+","A-","B+","B-","AB+","AB-","O+","O-"],label="Blood group")
                p_contact=gr.Textbox(label="Contact")
                p_email=gr.Textbox(label="Email (optional)")
                p_address=gr.Textbox(label="Address")
                p_history=gr.Textbox(label="Medical history / allergies (restricted)",lines=2)
                p_add=gr.Button("Register Patient",variant="primary")
                p_msg=gr.Textbox(label="Result")
                p_search=gr.Textbox(label="Search by ID, name or phone")
                p_search_btn=gr.Button("Search Patients")
                p_table=gr.Dataframe(label="Patient Records",interactive=False)
            with gr.Tab("Departments"):
                dep_name=gr.Textbox(label="Department name")
                dep_desc=gr.Textbox(label="Description")
                dep_add=gr.Button("Add Department")
                dep_msg=gr.Textbox(label="Result")
                dep_table=gr.Dataframe(value=rows_df("SELECT * FROM departments"),label="Departments",interactive=False)
            with gr.Tab("Doctors"):
                d_name=gr.Textbox(label="Doctor name")
                d_spec=gr.Textbox(label="Specialization")
                d_contact=gr.Textbox(label="Contact")
                d_email=gr.Textbox(label="Email")
                d_dept=gr.Dropdown(choices=dept_choices(),label="Department")
                d_fee=gr.Number(label="Consultation fee",value=0)
                d_add=gr.Button("Add Doctor")
                d_msg=gr.Textbox(label="Result")
                d_table=gr.Dataframe(label="Doctors",interactive=False)
            with gr.Tab("Appointments"):
                ap_patient=gr.Dropdown(choices=patient_choices(),label="Select Registered Patient")
                ap_doctor=gr.Dropdown(choices=doctor_choices(),label="Select Registered Doctor")
                ap_date=gr.Textbox(label="Appointment Date (YYYY-MM-DD)",placeholder="2026-12-15")
                ap_time=gr.Textbox(label="Appointment Time (24-hour HH:MM)",placeholder="10:30")
                ap_reason=gr.Textbox(label="Reason for Appointment",lines=2)
                ap_refresh=gr.Button("Refresh Patient/Doctor Lists")
                ap_book=gr.Button("Book Appointment",variant="primary")
                ap_msg=gr.Textbox(label="Booking result")
                ap_table=gr.Dataframe(label="Appointments",interactive=False)
                ap_id=gr.Number(label="Appointment ID",precision=0)
                ap_status=gr.Dropdown(["Pending","Confirmed","Completed","Cancelled"],label="New status")
                ap_update=gr.Button("Update Appointment Status")
                ap_update_msg=gr.Textbox(label="Update result")
            with gr.Tab("Consultations"):
                c_appt=gr.Number(label="Appointment ID",precision=0)
                c_symptoms=gr.Textbox(label="Symptoms")
                c_diagnosis=gr.Textbox(label="Diagnosis")
                c_treatment=gr.Textbox(label="Treatment notes",lines=3)
                c_follow=gr.Textbox(label="Follow-up date (YYYY-MM-DD, optional)")
                c_save=gr.Button("Save Consultation")
                c_msg=gr.Textbox(label="Result")
                c_table=gr.Dataframe(label="Consultations",interactive=False)
            with gr.Tab("Prescriptions"):
                pr_appt=gr.Number(label="Appointment ID",precision=0)
                pr_diag=gr.Textbox(label="Diagnosis")
                pr_med=gr.Dropdown(choices=medicine_choices(),label="Select medicine (optional)")
                pr_medname=gr.Textbox(label="Medicine name (if not in stock list)")
                pr_dosage=gr.Textbox(label="Dosage")
                pr_frequency=gr.Textbox(label="Frequency")
                pr_duration=gr.Textbox(label="Duration")
                pr_instruction=gr.Textbox(label="Instructions")
                pr_create=gr.Button("Create Prescription")
                pr_msg=gr.Textbox(label="Result")
                pr_table=gr.Dataframe(label="Prescriptions",interactive=False)
            with gr.Tab("Medicines / Stock"):
                m_name=gr.Textbox(label="Medicine name")
                m_category=gr.Textbox(label="Category")
                m_strength=gr.Textbox(label="Strength")
                with gr.Row():
                    m_qty=gr.Number(label="Opening quantity",value=0,precision=0)
                    m_unit=gr.Textbox(label="Unit",value="tablet")
                    m_price=gr.Number(label="Selling price",value=0)
                m_expiry=gr.Textbox(label="Expiry date (YYYY-MM-DD)")
                m_low=gr.Number(label="Low stock alert level",value=5,precision=0)
                m_add=gr.Button("Add Medicine")
                m_msg=gr.Textbox(label="Result")
                m_table=gr.Dataframe(label="Medicine Stock",interactive=False)
                stock_med=gr.Dropdown(choices=medicine_choices(),label="Medicine")
                stock_qty=gr.Number(label="Quantity",precision=0)
                stock_type=gr.Radio(["Stock In","Dispense"],label="Movement")
                stock_notes=gr.Textbox(label="Notes")
                stock_btn=gr.Button("Update Stock")
                stock_msg=gr.Textbox(label="Stock result")
            with gr.Tab("Billing / Payments"):
                b_patient=gr.Dropdown(choices=patient_choices(),label="Patient")
                b_appt=gr.Number(label="Appointment ID (optional)",precision=0)
                with gr.Row():
                    b_fee=gr.Number(label="Consultation fee",value=0)
                    b_med=gr.Number(label="Medicine charges",value=0)
                    b_other=gr.Number(label="Other charges",value=0)
                b_create=gr.Button("Create Bill")
                b_msg=gr.Textbox(label="Bill result")
                bill_table=gr.Dataframe(label="Bills",interactive=False)
                pay_bill=gr.Number(label="Bill ID",precision=0)
                pay_amount=gr.Number(label="Payment amount")
                pay_method=gr.Dropdown(["Cash","Card","Bank transfer","Other"],value="Cash",label="Payment method")
                pay_btn=gr.Button("Record Payment")
                pay_msg=gr.Textbox(label="Payment result")
            with gr.Tab("User Management"):
                u_name=gr.Textbox(label="New username")
                u_password=gr.Textbox(label="Temporary password (10+ characters)",type="password")
                u_role=gr.Dropdown(["Admin","Receptionist","Doctor"],label="Role")
                u_doctor=gr.Dropdown(choices=doctor_choices(),label="Linked doctor profile (Doctor role)")
                u_add=gr.Button("Create Staff Account")
                u_msg=gr.Textbox(label="Result")
                u_table=gr.Dataframe(label="Staff Accounts (no passwords shown)",interactive=False)
            with gr.Tab("Reports"):
                rep_btn=gr.Button("Refresh Reports")
                rep_table=gr.Dataframe(label="Summary Report",interactive=False)

    # Authentication / visibility
    def login_and_show(un,pw):
        u, a, b, message = do_login(un,pw)
        return u,a,b,message, (f"### Signed in: {u['username']} | Role: {u['role']}" if u else "")
    login_btn.click(login_and_show,[login_name,login_pass],[session,login_panel,main_panel,login_msg,who])
    logout_btn.click(do_logout,outputs=[session,login_panel,main_panel,login_name,login_pass])

    # Patients
    p_add.click(add_patient,[p_name,p_age,p_gender,p_contact,p_email,p_address,p_blood,p_history,session],[p_msg,p_table])
    p_search_btn.click(search_patients,[p_search],[p_table])

    # Departments / Doctors
    dep_add.click(add_department,[dep_name,dep_desc,session],[dep_msg,dep_table])
    d_add.click(add_doctor,[d_name,d_spec,d_contact,d_email,d_dept,d_fee,session],[d_msg,d_table])

    # Appointments
    def refresh_appt_choices():
        return gr.update(choices=patient_choices()),gr.update(choices=doctor_choices()),gr.update(choices=patient_choices())
    ap_refresh.click(refresh_appt_choices,outputs=[ap_patient,ap_doctor,b_patient])
    ap_book.click(book_appt,[ap_patient,ap_doctor,ap_date,ap_time,ap_reason,session],[ap_msg,ap_table])
    ap_update.click(update_appt_status,[ap_id,ap_status,session],[ap_update_msg,ap_table])

    # Consultations
    c_save.click(save_consultation,[c_appt,c_symptoms,c_diagnosis,c_treatment,c_follow,session],[c_msg,c_table])

    # Prescriptions
    def create_pr_from_ui(appt,diag,medid,medname,dosage,freq,duration,instructions,user):
        if not medname and medid:
            df=rows_df("SELECT medicine_name FROM medicines WHERE medicine_id=?",(int(medid),))
            medname=df.iloc[0]["medicine_name"] if len(df) else ""
        return create_prescription(appt,diag,medid,medname,dosage,freq,duration,instructions,user)
    pr_create.click(create_pr_from_ui,[pr_appt,pr_diag,pr_med,pr_medname,pr_dosage,pr_frequency,pr_duration,pr_instruction,session],[pr_msg,pr_table])

    # Medicines / stock
    m_add.click(add_medicine,[m_name,m_category,m_strength,m_qty,m_unit,m_price,m_expiry,m_low,session],[m_msg,m_table])
    stock_btn.click(adjust_stock,[stock_med,stock_qty,stock_type,stock_notes,session],[stock_msg,m_table])

    # Billing / payments
    b_create.click(create_bill,[b_patient,b_appt,b_fee,b_med,b_other,session],[b_msg,bill_table])
    pay_btn.click(record_payment,[pay_bill,pay_amount,pay_method,session],[pay_msg,bill_table])

    # Users
    u_add.click(add_staff,[u_name,u_password,u_role,u_doctor,session],[u_msg,u_table])

    # Reports / dashboard
    dash_btn.click(dashboard,[session],[dash_table])
    rep_btn.click(report_data,[session],[rep_table])

    # Initial table loads and dropdown refresh after login
    def after_login(un,pw):
        u=login_user(un,pw)
        if not u: return (gr.update(),)*7
        return (dashboard(u),
                rows_df("SELECT * FROM patients ORDER BY patient_id DESC"),
                rows_df("SELECT d.*,dep.department_name FROM doctors d LEFT JOIN departments dep USING(department_id)"),
                appointment_list(u),
                rows_df("SELECT * FROM medicines"),
                rows_df("SELECT * FROM bills ORDER BY bill_id DESC"),
                rows_df("SELECT user_id,username,role,doctor_id,is_active,created_at FROM users"))
    login_btn.click(after_login,[login_name,login_pass],[dash_table,p_table,d_table,ap_table,m_table,bill_table,u_table])

print("Hospital Management System is ready.")
print("Application initialized.")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "7860"))
    app.launch(server_name="0.0.0.0", server_port=port)
