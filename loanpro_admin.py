"""

 LOANPRO ADMIN 
 LOAN & DISBURSEMENT MANAGEMENT SYSTEM


Technology: Python | Tkinter | MySQL
Installation: py -m pip install mysql-connector-python

Run: py loanpro_admin.py

FEATURES:
1. Secure Admin Login
2. First-Time Admin Setup
3. Admin and Staff Roles
4. Customer Registration
5. Aadhaar and PAN Validation
6. Wife Contact Information
7. Bank Details
8. Loan Disbursement
9. Customer Search and Records
10. Dashboard Statistics
11. Audit Logging
12. Customer Update and Delete
13. Full Aadhaar and PAN visibility in customer records
14. Custom LoanPro fintech logo
15. Logout


import tkinter as tk
from tkinter import ttk, messagebox

from datetime import date
from decimal import Decimal, InvalidOperation

import mysql.connector
from mysql.connector import Error

import hashlib
import secrets
import re
import configparser
import sys
from pathlib import Path



# DATABASE CONFIGURATION


DATABASE_CONFIG_FILE = "database.ini"


# =========================================================
# WARM COFFEE COLOUR THEME
# =========================================================

COLORS = {

    "header": "#38271F",

    "sidebar": "#49352A",

    "sidebar_light": "#6B4B3E",

    "background": "#F7F1E8",

    "card": "#FFFDF8",

    "primary": "#B96545",

    "primary_hover": "#984B34",

    "mustard": "#D6A64F",

    "text": "#3D3028",

    "muted": "#89796D",

    "success": "#648568",

    "danger": "#B94C42",

    "warning": "#C58A36",

    "border": "#E7D9C8",

    "table_alt": "#F4E9DA",

    "light_coffee": "#E9DCCB",

    "white": "#FFFFFF"

}


# =========================================================
# PASSWORD SECURITY
# =========================================================

def hash_password(password, salt=None):

    if salt is None:
        salt = secrets.token_bytes(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        310000
    )

    return salt.hex(), hashed.hex()


def verify_password(password, salt_hex, hash_hex):

    salt = bytes.fromhex(salt_hex)

    _, calculated_hash = hash_password(
        password,
        salt
    )

    return secrets.compare_digest(
        calculated_hash,
        hash_hex
    )


# =========================================================
# MAIN APPLICATION
# =========================================================

class LoanManagementApp:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "LoanPro Admin 3.2 | Loan Management System"
        )

        self.root.geometry("1450x850")

        self.root.minsize(1150, 700)

        self.root.configure(
            bg=COLORS["background"]
        )

        self.conn = None

        self.current_user = None

        self.current_role = None

        self.colors = COLORS

        self.setup_style()

        if not self.connect_database():

            self.root.after(
                100,
                self.root.destroy
            )

            return

        try:

            self.create_tables()

            self.show_authentication()

        except Error as exc:

            messagebox.showerror(
                "Database Error",
                str(exc)
            )

            self.on_close()

        # =====================================================
    # DATABASE CONNECTION USING database.ini
    # =====================================================

    def connect_database(self):

        try:

            # Locate the configuration file.

            if getattr(sys, "frozen", False):

                # Running as a packaged EXE
                application_folder = Path(sys.executable).resolve().parent

                config_path = (
                    application_folder
                    / "config"
                    / DATABASE_CONFIG_FILE
                )

            else:

                # Running the Python source code
                source_folder = Path(__file__).resolve().parent

                config_candidates = [

                    source_folder.parent
                    / "01_Application"
                    / "config"
                    / DATABASE_CONFIG_FILE,

                    source_folder
                    / "config"
                    / DATABASE_CONFIG_FILE

                ]

                config_path = next(
                    (
                        path for path in config_candidates
                        if path.is_file()
                    ),
                    None
                )

            if config_path is None or not config_path.is_file():

                raise FileNotFoundError(
                    "database.ini was not found.\n\n"
                    "Expected location:\n"
                    "01_Application/config/database.ini"
                )

            # Read configuration without interpreting % in passwords.
            config = configparser.RawConfigParser()

            config.read(config_path, encoding="utf-8")

            if not config.has_section("mysql"):

                raise ValueError(
                    "The [mysql] section is missing in database.ini."
                )

            # Read database credentials.
            db_config = {

                "host": config.get("mysql", "host"),

                "port": config.getint(
                    "mysql",
                    "port",
                    fallback=3306
                ),

                "user": config.get("mysql", "user"),

                "password": config.get("mysql", "password"),

                "database": config.get("mysql", "database")

            }

            # Check required configuration values.
            required = [
                "host",
                "user",
                "password",
                "database"
            ]

            for key in required:

                if not db_config[key].strip():

                    raise ValueError(
                        f"Database configuration '{key}' is empty."
                    )

            self.database_name = db_config["database"]

            # Connect directly to the existing database.
            # No root account or database creation is required.

            self.conn = mysql.connector.connect(
                **db_config,
                connection_timeout=10
            )

            if self.conn.is_connected():

                return True

            raise Error(
                "MySQL connection could not be established."
            )

        except (
            Error,
            OSError,
            ValueError,
            configparser.Error
        ) as exc:

            messagebox.showerror(
                "MySQL Connection Error",
                f"Unable to connect to LoanPro database.\n\n{exc}"
            )

            return False

    # =====================================================
    # CREATE DATABASE TABLES
    # =====================================================

    def create_tables(self):

        cursor = self.conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admins (

                user_id INT AUTO_INCREMENT PRIMARY KEY,

                username VARCHAR(50) UNIQUE NOT NULL,

                password_salt VARCHAR(64) NOT NULL,

                password_hash VARCHAR(64) NOT NULL,

                role ENUM('Admin','Staff')
                NOT NULL DEFAULT 'Staff',

                created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP

            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS customers (

                customer_id VARCHAR(20) PRIMARY KEY,

                customer_name VARCHAR(100) NOT NULL,

                address TEXT,

                contact_number VARCHAR(15),

                aadhaar_number VARCHAR(12),

                pan_number VARCHAR(10),

                relative_name VARCHAR(100),

                relative_contact VARCHAR(15),

                bank_name VARCHAR(100),

                account_holder VARCHAR(100),

                account_number VARCHAR(40),

                ifsc_code VARCHAR(15),

                branch_name VARCHAR(100),

                registration_date DATE

            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS loans (

                loan_id INT AUTO_INCREMENT PRIMARY KEY,

                customer_id VARCHAR(20) NOT NULL,

                approved_amount DECIMAL(12,2) NOT NULL,

                disbursed_amount DECIMAL(12,2) NOT NULL,

                disbursement_date DATE NOT NULL,

                payment_mode VARCHAR(30),

                payment_reference VARCHAR(100),

                loan_status VARCHAR(30) NOT NULL,

                created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (customer_id)
                REFERENCES customers(customer_id)

            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (

                log_id INT AUTO_INCREMENT PRIMARY KEY,

                username VARCHAR(50),

                action VARCHAR(255),

                log_time TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP

            )
        """)

        # Migration for existing databases

        cursor.execute("""
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = %s
            AND TABLE_NAME = 'customers'
        """, (self.database_name,))

        columns = {
            row[0] for row in cursor.fetchall()
        }

        migrations = {

            "aadhaar_number": "VARCHAR(12)",

            "pan_number": "VARCHAR(10)"

        }

        for column, datatype in migrations.items():

            if column not in columns:

                cursor.execute(
                    f"""
                    ALTER TABLE customers
                    ADD COLUMN {column} {datatype}
                    """
                )

        self.conn.commit()

        cursor.close()

    # =====================================================
    # DATABASE EXECUTION
    # =====================================================

    def execute(
        self,
        query,
        values=None,
        fetch=False
    ):

        cursor = self.conn.cursor(
            dictionary=True
        )

        try:

            cursor.execute(
                query,
                values or ()
            )

            if fetch:

                return cursor.fetchall()

            self.conn.commit()

            return cursor.lastrowid

        except Error:

            self.conn.rollback()

            raise

        finally:

            cursor.close()

    # =====================================================
    # AUDIT LOGGING
    # =====================================================

    def log_action(self, action):

        if not self.current_user:
            return

        self.execute(
            """
            INSERT INTO audit_logs
            (username, action)
            VALUES (%s, %s)
            """,
            (
                self.current_user,
                action
            )
        )

    # =====================================================
    # APPLICATION STYLE
    # =====================================================

    def setup_style(self):

        style = ttk.Style()

        style.theme_use("clam")

        # Buttons

        style.configure(
            "TButton",
            font=("Segoe UI", 9, "bold"),
            padding=10,
            background=COLORS["light_coffee"],
            foreground=COLORS["text"],
            borderwidth=0
        )

        style.map(
            "TButton",
            background=[
                ("active", "#DCC8B3"),
                ("pressed", "#C9B49E")
            ]
        )

        # Primary button

        style.configure(
            "Primary.TButton",
            background=COLORS["primary"],
            foreground="white",
            font=("Segoe UI", 9, "bold"),
            padding=11,
            borderwidth=0
        )

        style.map(
            "Primary.TButton",
            background=[
                ("active", COLORS["primary_hover"]),
                ("pressed", "#82402E")
            ],
            foreground=[
                ("active", "white")
            ]
        )

        # Entry fields

        style.configure(
            "TEntry",
            padding=8,
            fieldbackground=COLORS["card"],
            foreground=COLORS["text"],
            bordercolor=COLORS["border"]
        )

        # Dropdown

        style.configure(
            "TCombobox",
            padding=8,
            fieldbackground=COLORS["card"],
            background=COLORS["card"],
            foreground=COLORS["text"],
            arrowcolor=COLORS["primary"]
        )

        # Tables

        style.configure(
            "Treeview",
            rowheight=34,
            font=("Segoe UI", 9),
            background=COLORS["card"],
            fieldbackground=COLORS["card"],
            foreground=COLORS["text"],
            bordercolor=COLORS["border"]
        )

        style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 9, "bold"),
            background=COLORS["light_coffee"],
            foreground=COLORS["sidebar"],
            padding=10
        )

        style.map(
            "Treeview",
            background=[
                ("selected", COLORS["primary"])
            ],
            foreground=[
                ("selected", "white")
            ]
        )

    # =====================================================
    # CUSTOM LOANPRO BRAND LOGO
    # Original fintech-style mark: rupee coin + upward growth stroke.
    # It is not a copy of another company's trademark/logo.
    # =====================================================

    def create_brand_logo(self, parent, compact=False):

        logo = tk.Frame(parent, bg=parent.cget("bg"))

        size = 42 if compact else 64
        canvas = tk.Canvas(
            logo,
            width=size,
            height=size,
            bg=parent.cget("bg"),
            highlightthickness=0
        )
        canvas.pack(side="left", padx=(0, 9))

        pad = 3
        canvas.create_oval(
            pad, pad, size-pad, size-pad,
            fill=COLORS["primary"],
            outline=COLORS["mustard"],
            width=3
        )
        canvas.create_text(
            size * 0.48, size * 0.51,
            text="₹",
            fill=COLORS["white"],
            font=("Segoe UI", int(size * 0.48), "bold")
        )
        # Small upward stroke gives the mark a finance/growth identity.
        canvas.create_line(
            size * 0.60, size * 0.72,
            size * 0.76, size * 0.56,
            size * 0.87, size * 0.60,
            fill=COLORS["mustard"],
            width=2.5,
            smooth=True
        )

        text_frame = tk.Frame(logo, bg=parent.cget("bg"))
        text_frame.pack(side="left", fill="y")
        tk.Label(
            text_frame, text="LOANPRO",
            bg=parent.cget("bg"), fg=COLORS["primary"] if not compact else COLORS["white"],
            font=("Segoe UI", 22 if not compact else 17, "bold")
        ).pack(anchor="w", pady=(2, 0))
        tk.Label(
            text_frame, text="SMART LOAN MANAGEMENT",
            bg=parent.cget("bg"),
            fg=COLORS["muted"] if not compact else "#DCC8B3",
            font=("Segoe UI", 7 if not compact else 6, "bold")
        ).pack(anchor="w")

        return logo

    # =====================================================
    # CLEAR ROOT
    # =====================================================

    def clear_root(self):

        for widget in self.root.winfo_children():

            widget.destroy()

    # =====================================================
    # AUTHENTICATION
    # =====================================================

    def show_authentication(self):

        self.clear_root()

        users = self.execute(
            "SELECT COUNT(*) AS total FROM admins",
            fetch=True
        )[0]["total"]

        if users == 0:

            self.show_first_admin_setup()

        else:

            self.show_login()

    # =====================================================
    # AUTHENTICATION BACKGROUND
    # =====================================================

    def auth_background(self):

        background = tk.Frame(
            self.root,
            bg=COLORS["header"]
        )

        background.pack(
            fill="both",
            expand=True
        )

        return background

    # =====================================================
    # AUTHENTICATION FIELD
    # =====================================================

    def auth_field(
        self,
        parent,
        label,
        show=None
    ):

        tk.Label(
            parent,
            text=label,
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w",
            pady=(8, 4)
        )

        entry = ttk.Entry(
            parent,
            width=35,
            show=show
        )

        entry.pack(
            fill="x",
            pady=(0, 5)
        )

        return entry

    # =====================================================
    # FIRST ADMIN SETUP
    # =====================================================

    def show_first_admin_setup(self):

        self.clear_root()

        background = self.auth_background()

        card = tk.Frame(
            background,
            bg=COLORS["card"],
            padx=45,
            pady=40,
            highlightbackground=COLORS["mustard"],
            highlightthickness=2
        )

        card.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        self.create_brand_logo(card).pack(pady=(0, 12))

        tk.Label(
            card,
            text="INITIAL ADMINISTRATOR SETUP",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=("Segoe UI", 10, "bold")
        ).pack(pady=(0, 20))

        username = self.auth_field(
            card,
            "Administrator Username"
        )

        password = self.auth_field(
            card,
            "Create Password",
            show="*"
        )

        confirm = self.auth_field(
            card,
            "Confirm Password",
            show="*"
        )

        def create_admin():

            user = username.get().strip()

            pwd = password.get()

            confirm_pwd = confirm.get()

            if not user or not pwd or not confirm_pwd:

                messagebox.showwarning(
                    "Validation",
                    "Complete all fields."
                )

                return

            if len(user) < 4:

                messagebox.showwarning(
                    "Username",
                    "Username must contain at least 4 characters."
                )

                return

            if len(pwd) < 12:

                messagebox.showwarning(
                    "Password",
                    "Password must contain at least 12 characters."
                )

                return

            if pwd != confirm_pwd:

                messagebox.showerror(
                    "Password Error",
                    "Passwords do not match."
                )

                return

            salt, hashed = hash_password(pwd)

            try:

                self.execute(
                    """
                    INSERT INTO admins
                    (
                        username,
                        password_salt,
                        password_hash,
                        role
                    )
                    VALUES (%s,%s,%s,'Admin')
                    """,
                    (
                        user,
                        salt,
                        hashed
                    )
                )

                messagebox.showinfo(
                    "Success",
                    "Administrator account created successfully."
                )

                self.show_login()

            except Error as exc:

                messagebox.showerror(
                    "Setup Error",
                    str(exc)
                )

        ttk.Button(
            card,
            text="CREATE ADMIN ACCOUNT",
            style="Primary.TButton",
            command=create_admin
        ).pack(
            fill="x",
            pady=20
        )

    # =====================================================
    # LOGIN
    # =====================================================

    def show_login(self):

        self.clear_root()

        background = self.auth_background()

        card = tk.Frame(
            background,
            bg=COLORS["card"],
            padx=45,
            pady=40,
            highlightbackground=COLORS["mustard"],
            highlightthickness=2
        )

        card.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        self.create_brand_logo(card).pack(pady=(0, 12))

        tk.Label(
            card,
            text="ADMIN LOGIN",
            bg=COLORS["card"],
            fg=COLORS["muted"],
            font=("Segoe UI", 11, "bold")
        ).pack(pady=(0, 25))

        username = self.auth_field(
            card,
            "Username"
        )

        password = self.auth_field(
            card,
            "Password",
            show="*"
        )

        def login():

            user = username.get().strip()

            pwd = password.get()

            if not user or not pwd:

                messagebox.showwarning(
                    "Login",
                    "Enter username and password."
                )

                return

            rows = self.execute(
                """
                SELECT *
                FROM admins
                WHERE username=%s
                """,
                (user,),
                fetch=True
            )

            if not rows:

                messagebox.showerror(
                    "Login Failed",
                    "Invalid username or password."
                )

                return

            account = rows[0]

            if not verify_password(
                pwd,
                account["password_salt"],
                account["password_hash"]
            ):

                messagebox.showerror(
                    "Login Failed",
                    "Invalid username or password."
                )

                return

            self.current_user = account["username"]

            self.current_role = account["role"]

            self.log_action("Logged in")

            self.show_main_application()

        ttk.Button(
            card,
            text="LOGIN",
            style="Primary.TButton",
            command=login
        ).pack(
            fill="x",
            pady=20
        )

        password.bind(
            "<Return>",
            lambda event: login()
        )

    # =====================================================
    # MAIN APPLICATION
    # =====================================================

    def show_main_application(self):

        self.clear_root()

        self.root.title(
            f"LoanPro Admin | {self.current_user}"
        )

        self.build_header()

        self.build_navigation()

        self.refresh_all()

    # =====================================================
    # HEADER
    # =====================================================

    def build_header(self):

        header = tk.Frame(
            self.root,
            bg=COLORS["header"],
            height=75
        )

        header.pack(fill="x")

        header.pack_propagate(False)

        self.create_brand_logo(header, compact=True).pack(
            side="left",
            padx=18,
            pady=5
        )

        tk.Label(
            header,
            text="LOAN DISBURSEMENT MANAGEMENT SYSTEM",
            bg=COLORS["header"],
            fg="#DCC8B3",
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left",
            padx=10
        )

        user_frame = tk.Frame(
            header,
            bg=COLORS["header"]
        )

        user_frame.pack(
            side="right",
            padx=18
        )

        tk.Label(
            user_frame,
            text=f"{self.current_user} | {self.current_role}",
            bg=COLORS["header"],
            fg="#FFFDF8",
            font=("Segoe UI", 9, "bold")
        ).pack(
            side="left",
            padx=10
        )

        ttk.Button(
            user_frame,
            text="LOGOUT",
            command=self.logout
        ).pack(side="left")

    # =====================================================
    # NAVIGATION
    # =====================================================

    def build_navigation(self):

        main = tk.Frame(
            self.root,
            bg=COLORS["background"]
        )

        main.pack(
            fill="both",
            expand=True
        )

        self.sidebar = tk.Frame(
            main,
            bg=COLORS["sidebar"],
            width=245
        )

        self.sidebar.pack(
            side="left",
            fill="y"
        )

        self.sidebar.pack_propagate(False)

        self.content = tk.Frame(
            main,
            bg=COLORS["background"]
        )

        self.content.pack(
            side="left",
            fill="both",
            expand=True
        )

        self.pages = {

            "Dashboard": tk.Frame(
                self.content,
                bg=COLORS["background"]
            ),

            "Customer Registration": tk.Frame(
                self.content,
                bg=COLORS["background"]
            ),

            "Loan Disbursement": tk.Frame(
                self.content,
                bg=COLORS["background"]
            ),

            "Search & Records": tk.Frame(
                self.content,
                bg=COLORS["background"]
            )

        }

        tk.Label(
            self.sidebar,
            text="MAIN MENU",
            bg=COLORS["sidebar"],
            fg="#DCC8B3",
            font=("Segoe UI", 9, "bold")
        ).pack(
            anchor="w",
            padx=22,
            pady=25
        )

        menu = [

            ("▦", "Dashboard"),

            ("♙", "Customer Registration"),

            ("₹", "Loan Disbursement"),

            ("▤", "Search & Records")

        ]

        self.nav_buttons = {}

        for icon, name in menu:

            button = tk.Button(
                self.sidebar,
                text=f"  {icon}   {name}",
                bg=COLORS["sidebar"],
                fg=COLORS["white"],
                activebackground=COLORS["sidebar_light"],
                activeforeground=COLORS["white"],
                font=("Segoe UI", 10, "bold"),
                anchor="w",
                bd=0,
                cursor="hand2",
                padx=15,
                pady=15,
                command=lambda p=name: self.show_page(p)
            )

            button.pack(
                fill="x",
                padx=9,
                pady=4
            )

            self.nav_buttons[name] = button

        if self.current_role == "Admin":

            button = tk.Button(
                self.sidebar,
                text="  ◷   Audit Logs",
                bg=COLORS["sidebar"],
                fg=COLORS["white"],
                activebackground=COLORS["sidebar_light"],
                activeforeground=COLORS["white"],
                font=("Segoe UI", 10, "bold"),
                anchor="w",
                bd=0,
                cursor="hand2",
                padx=15,
                pady=15,
                command=self.show_audit_logs
            )

            button.pack(
                fill="x",
                padx=9,
                pady=4
            )

        self.build_dashboard()

        self.build_customer_form()

        self.build_loan_form()

        self.build_records()

        self.show_page("Dashboard")

    # =====================================================
    # PAGE NAVIGATION
    # =====================================================

    def show_page(self, name):

        for page in self.pages.values():

            page.pack_forget()

        self.pages[name].pack(
            fill="both",
            expand=True
        )

        for page, button in self.nav_buttons.items():

            button.configure(
                bg=(
                    COLORS["primary"]
                    if page == name
                    else COLORS["sidebar"]
                )
            )

    # =====================================================
    # SECTION
    # =====================================================

    def section(self, parent, title):

        return tk.LabelFrame(
            parent,
            text=title,
            bg=COLORS["card"],
            fg=COLORS["sidebar"],
            font=("Segoe UI", 11, "bold"),
            padx=12,
            pady=12,
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )

    # =====================================================
    # ENTRY FIELD
    # =====================================================

    def add_field(
        self,
        parent,
        label,
        row,
        col,
        width=30,
        default=""
    ):

        tk.Label(
            parent,
            text=label,
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=("Segoe UI", 9, "bold")
        ).grid(
            row=row,
            column=col,
            sticky="w",
            padx=8,
            pady=7
        )

        entry = ttk.Entry(
            parent,
            width=width
        )

        entry.grid(
            row=row,
            column=col + 1,
            sticky="ew",
            padx=8,
            pady=7
        )

        if default:

            entry.insert(0, default)

        return entry

    # =====================================================
    # TREEVIEW
    # =====================================================

    def make_tree(
        self,
        parent,
        columns,
        headings,
        widths,
        height=8
    ):

        frame = tk.Frame(
            parent,
            bg=COLORS["card"]
        )

        frame.pack(
            fill="both",
            expand=True
        )

        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            height=height
        )

        for col, heading, width in zip(
            columns,
            headings,
            widths
        ):

            tree.heading(
                col,
                text=heading
            )

            tree.column(
                col,
                width=width,
                minwidth=90,
                anchor="center",
                stretch=False
            )

        ys = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=tree.yview
        )

        xs = ttk.Scrollbar(
            frame,
            orient="horizontal",
            command=tree.xview
        )

        tree.configure(
            yscrollcommand=ys.set,
            xscrollcommand=xs.set
        )

        tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        ys.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        xs.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        frame.grid_rowconfigure(
            0,
            weight=1
        )

        frame.grid_columnconfigure(
            0,
            weight=1
        )

        return tree

    # =====================================================
    # DASHBOARD
    # =====================================================

    def build_dashboard(self):

        page = self.pages["Dashboard"]

        tk.Label(
            page,
            text="Dashboard Overview",
            bg=COLORS["background"],
            fg=COLORS["sidebar"],
            font=("Segoe UI", 22, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=20
        )

        cards = tk.Frame(
            page,
            bg=COLORS["background"]
        )

        cards.pack(
            fill="x",
            padx=10
        )

        self.stats = {}

        card_data = [

            (
                "customers",
                "TOTAL CUSTOMERS",
                COLORS["primary"]
            ),

            (
                "loans",
                "TOTAL LOANS",
                "#8062A5"
            ),

            (
                "disbursed",
                "TOTAL DISBURSED",
                COLORS["success"]
            ),

            (
                "pending",
                "PENDING LOANS",
                COLORS["warning"]
            )

        ]

        for key, title, color in card_data:

            card = tk.Frame(
                cards,
                bg=COLORS["card"],
                bd=1,
                relief="solid",
                highlightbackground=COLORS["border"],
                highlightthickness=1
            )

            card.pack(
                side="left",
                fill="both",
                expand=True,
                padx=7,
                ipady=12
            )

            tk.Label(
                card,
                text=title,
                bg=COLORS["card"],
                fg=COLORS["muted"],
                font=("Segoe UI", 9, "bold")
            ).pack(pady=10)

            label = tk.Label(
                card,
                text="0",
                bg=COLORS["card"],
                fg=color,
                font=("Segoe UI", 21, "bold")
            )

            label.pack(pady=8)

            self.stats[key] = label

        box = self.section(
            page,
            "RECENT LOAN ACTIVITIES"
        )

        box.pack(
            fill="both",
            expand=True,
            padx=18,
            pady=18
        )

        self.dashboard_tree = self.make_tree(

            box,

            (
                "loan_id",
                "customer_id",
                "name",
                "approved",
                "disbursed",
                "date",
                "status"
            ),

            [
                "Loan ID",
                "Customer ID",
                "Customer Name",
                "Approved Amount",
                "Disbursed Amount",
                "Date",
                "Status"
            ],

            [
                90,
                120,
                180,
                150,
                150,
                130,
                130
            ],

            10

        )

    # =====================================================
    # CUSTOMER REGISTRATION
    # =====================================================

    def build_customer_form(self):

        page = self.pages["Customer Registration"]

        box = self.section(
            page,
            "CUSTOMER REGISTRATION & BANK DETAILS"
        )

        box.pack(
            fill="both",
            expand=True,
            padx=18,
            pady=18
        )

        self.customer_fields = {}

        fields = [

            ("Customer ID *", "customer_id"),

            ("Customer Name *", "customer_name"),

            ("Contact Number", "contact_number"),

            ("Aadhaar Number *", "aadhaar_number"),

            ("PAN Number *", "pan_number"),

            ("Address", "address"),

            ("Wife Name", "relative_name"),

            ("Wife Contact", "relative_contact"),

            ("Bank Name", "bank_name"),

            ("Account Holder", "account_holder"),

            ("Account Number", "account_number"),

            ("IFSC Code", "ifsc_code"),

            ("Branch Name", "branch_name")

        ]

        for i, (label, key) in enumerate(fields):

            row, col = divmod(i, 2)

            self.customer_fields[key] = self.add_field(
                box,
                label,
                row,
                col * 2,
                30
            )

            box.grid_columnconfigure(
                col * 2 + 1,
                weight=1
            )

        buttons = tk.Frame(
            box,
            bg=COLORS["card"]
        )

        buttons.grid(
            row=7,
            column=0,
            columnspan=4,
            pady=18
        )

        ttk.Button(
            buttons,
            text="SAVE CUSTOMER",
            style="Primary.TButton",
            command=self.save_customer
        ).pack(
            side="left",
            padx=5
        )

        ttk.Button(
            buttons,
            text="UPDATE CUSTOMER",
            command=self.update_customer
        ).pack(
            side="left",
            padx=5
        )

        if self.current_role == "Admin":

            ttk.Button(
                buttons,
                text="DELETE CUSTOMER",
                command=self.delete_customer
            ).pack(
                side="left",
                padx=5
            )

        ttk.Button(
            buttons,
            text="CLEAR",
            command=self.clear_customer_form
        ).pack(
            side="left",
            padx=5
        )

        tk.Label(
            box,
            text="Aadhaar: exactly 12 digits | PAN: 5 letters + 4 digits + 1 letter (ABCDE1234F)",
            bg=COLORS["card"],
            fg=COLORS["muted"]
        ).grid(
            row=8,
            column=0,
            columnspan=4,
            sticky="w",
            padx=8
        )

        tk.Label(
            box,
            text="Sensitive identity and bank information should be protected.",
            bg=COLORS["card"],
            fg=COLORS["danger"],
            font=("Segoe UI", 9, "bold")
        ).grid(
            row=9,
            column=0,
            columnspan=4,
            sticky="w",
            padx=8,
            pady=5
        )

    # =====================================================
    # CUSTOMER VALUES
    # =====================================================

    def get_customer_values(self):

        return {

            key: widget.get().strip()

            for key, widget in self.customer_fields.items()

        }

    # =====================================================
    # CUSTOMER VALIDATION
    # =====================================================

    def validate_customer(self, data):

        if not data["customer_id"] or not data["customer_name"]:

            messagebox.showwarning(
                "Validation",
                "Customer ID and Name are required."
            )

            return False

        if not re.fullmatch(
            r"\d{12}",
            data["aadhaar_number"]
        ):

            messagebox.showerror(
                "Invalid Aadhaar",
                "Enter exactly 12 digits."
            )

            return False

        data["pan_number"] = data["pan_number"].upper()

        if not re.fullmatch(
            r"[A-Z]{5}[0-9]{4}[A-Z]",
            data["pan_number"]
        ):

            messagebox.showerror(
                "Invalid PAN",
                "Enter PAN in ABCDE1234F format."
            )

            return False

        return True

    # =====================================================
    # SAVE CUSTOMER
    # =====================================================

    def save_customer(self):

        data = self.get_customer_values()

        if not self.validate_customer(data):
            return

        query = """

            INSERT INTO customers (

                customer_id,
                customer_name,
                address,
                contact_number,
                aadhaar_number,
                pan_number,
                relative_name,
                relative_contact,
                bank_name,
                account_holder,
                account_number,
                ifsc_code,
                branch_name,
                registration_date

            )

            VALUES (
                %s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s
            )

        """

        values = tuple(

            data[k]

            for k in [

                "customer_id",
                "customer_name",
                "address",
                "contact_number",
                "aadhaar_number",
                "pan_number",
                "relative_name",
                "relative_contact",
                "bank_name",
                "account_holder",
                "account_number",
                "ifsc_code",
                "branch_name"

            ]

        ) + (date.today(),)

        try:

            self.execute(
                query,
                values
            )

            self.log_action(
                f"Registered customer {data['customer_id']}"
            )

            messagebox.showinfo(
                "Success",
                "Customer registered successfully."
            )

            self.clear_customer_form()

            self.refresh_all()

        except Error as exc:

            messagebox.showerror(
                "Save Error",
                str(exc)
            )

    # =====================================================
    # UPDATE CUSTOMER
    # =====================================================

    def update_customer(self):

        data = self.get_customer_values()

        if not self.validate_customer(data):
            return

        query = """

            UPDATE customers SET

                customer_name=%s,
                address=%s,
                contact_number=%s,
                aadhaar_number=%s,
                pan_number=%s,
                relative_name=%s,
                relative_contact=%s,
                bank_name=%s,
                account_holder=%s,
                account_number=%s,
                ifsc_code=%s,
                branch_name=%s

            WHERE customer_id=%s

        """

        values = (

            data["customer_name"],
            data["address"],
            data["contact_number"],
            data["aadhaar_number"],
            data["pan_number"],
            data["relative_name"],
            data["relative_contact"],
            data["bank_name"],
            data["account_holder"],
            data["account_number"],
            data["ifsc_code"],
            data["branch_name"],
            data["customer_id"]

        )

        try:

            result = self.execute(
                query,
                values
            )

            self.log_action(
                f"Updated customer {data['customer_id']}"
            )

            messagebox.showinfo(
                "Updated",
                "Customer details updated."
            )

            self.refresh_all()

        except Error as exc:

            messagebox.showerror(
                "Update Error",
                str(exc)
            )

    # =====================================================
    # DELETE CUSTOMER
    # =====================================================

    def delete_customer(self):

        if self.current_role != "Admin":

            messagebox.showerror(
                "Permission Denied",
                "Only administrators can delete customers."
            )

            return

        customer_id = self.customer_fields[
            "customer_id"
        ].get().strip()

        if not customer_id:

            messagebox.showwarning(
                "Select Customer",
                "Enter a customer ID."
            )

            return

        if not messagebox.askyesno(
            "Confirm",
            f"Delete customer {customer_id}?"
        ):

            return

        try:

            self.execute(
                "DELETE FROM customers WHERE customer_id=%s",
                (customer_id,)
            )

            self.log_action(
                f"Deleted customer {customer_id}"
            )

            messagebox.showinfo(
                "Deleted",
                "Customer deleted."
            )

            self.clear_customer_form()

            self.refresh_all()

        except Error as exc:

            messagebox.showerror(
                "Delete Error",
                "Customer may have linked loan records.\n\n"
                + str(exc)
            )

    # =====================================================
    # CLEAR CUSTOMER FORM
    # =====================================================

    def clear_customer_form(self):

        for widget in self.customer_fields.values():

            widget.delete(
                0,
                tk.END
            )

    # =====================================================
    # SELECT CUSTOMER
    # =====================================================

    def select_customer(self, event=None):

        selected = self.customer_tree.selection()

        if not selected:
            return

        customer_id = self.customer_tree.item(
            selected[0],
            "values"
        )[0]

        rows = self.execute(
            """
            SELECT *
            FROM customers
            WHERE customer_id=%s
            """,
            (customer_id,),
            fetch=True
        )

        if not rows:
            return

        row = rows[0]

        self.clear_customer_form()

        for key, widget in self.customer_fields.items():

            widget.insert(
                0,
                row.get(key) or ""
            )

    # =====================================================
    # LOAN DISBURSEMENT FORM
    # =====================================================

    def build_loan_form(self):

        page = self.pages["Loan Disbursement"]

        box = self.section(
            page,
            "LOAN DISBURSEMENT DETAILS"
        )

        box.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=20
        )

        self.loan_fields = {}

        fields = [

            ("Customer ID *", "customer_id"),

            ("Approved Amount ₹ *", "approved_amount"),

            ("Disbursed Amount ₹ *", "disbursed_amount"),

            ("Disbursement Date", "disbursement_date"),

            ("Transaction Reference", "payment_reference")

        ]

        for row, (label, key) in enumerate(fields):

            default = (

                date.today().isoformat()

                if key == "disbursement_date"

                else ""

            )

            self.loan_fields[key] = self.add_field(
                box,
                label,
                row,
                0,
                30,
                default
            )

        tk.Label(
            box,
            text="Payment Mode",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=("Segoe UI", 9, "bold")
        ).grid(
            row=5,
            column=0,
            sticky="w",
            padx=8,
            pady=8
        )

        self.payment_mode = ttk.Combobox(
            box,
            values=[
                "Bank Transfer",
                "UPI",
                "Cheque",
                "Cash"
            ],
            state="readonly",
            width=30
        )

        self.payment_mode.grid(
            row=5,
            column=1,
            sticky="w",
            padx=8,
            pady=8
        )

        self.payment_mode.set(
            "Bank Transfer"
        )

        tk.Label(
            box,
            text="Loan Status",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=("Segoe UI", 9, "bold")
        ).grid(
            row=6,
            column=0,
            sticky="w",
            padx=8,
            pady=8
        )

        self.loan_status = ttk.Combobox(
            box,
            values=[
                "Disbursed",
                "Partially Disbursed",
                "Pending"
            ],
            state="readonly",
            width=30
        )

        self.loan_status.grid(
            row=6,
            column=1,
            sticky="w",
            padx=8,
            pady=8
        )

        self.loan_status.set(
            "Disbursed"
        )

        buttons = tk.Frame(
            box,
            bg=COLORS["card"]
        )

        buttons.grid(
            row=7,
            column=1,
            sticky="w",
            padx=8,
            pady=18
        )

        ttk.Button(
            buttons,
            text="SAVE DISBURSEMENT",
            style="Primary.TButton",
            command=self.save_loan
        ).pack(
            side="left",
            padx=5
        )

        ttk.Button(
            buttons,
            text="CLEAR",
            command=self.clear_loan_form
        ).pack(
            side="left",
            padx=5
        )

    # =====================================================
    # SAVE LOAN
    # =====================================================

    def save_loan(self):

        data = {

            key: widget.get().strip()

            for key, widget in self.loan_fields.items()

        }

        if not all([

            data["customer_id"],

            data["approved_amount"],

            data["disbursed_amount"]

        ]):

            messagebox.showwarning(
                "Validation",
                "Complete the required loan fields."
            )

            return

        try:

            approved = Decimal(
                data["approved_amount"]
            )

            disbursed = Decimal(
                data["disbursed_amount"]
            )

            if not approved.is_finite() or not disbursed.is_finite():

                raise ValueError(
                    "Enter valid monetary amounts."
                )

            if approved <= 0:

                raise ValueError(
                    "Approved amount must be positive."
                )

            if disbursed < 0 or disbursed > approved:

                raise ValueError(
                    "Disbursed amount cannot exceed approved amount."
                )

            date.fromisoformat(
                data["disbursement_date"]
            )

            customer = self.execute(
                """
                SELECT customer_id
                FROM customers
                WHERE customer_id=%s
                """,
                (data["customer_id"],),
                fetch=True
            )

            if not customer:

                messagebox.showwarning(
                    "Customer Not Found",
                    "Register the customer first."
                )

                return

            status = self.loan_status.get()

            if status == "Disbursed" and disbursed == 0:

                raise ValueError(
                    "Disbursed amount must be greater than zero."
                )

            if status == "Pending" and disbursed != 0:

                raise ValueError(
                    "Pending loan must have zero disbursed amount."
                )

            if status == "Partially Disbursed":

                if disbursed <= 0 or disbursed >= approved:

                    raise ValueError(
                        "Partial disbursement must be greater than zero "
                        "and less than the approved amount."
                    )

            self.execute(
                """
                INSERT INTO loans (

                    customer_id,
                    approved_amount,
                    disbursed_amount,
                    disbursement_date,
                    payment_mode,
                    payment_reference,
                    loan_status

                )

                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                (

                    data["customer_id"],

                    approved,

                    disbursed,

                    data["disbursement_date"],

                    self.payment_mode.get(),

                    data["payment_reference"],

                    status

                )
            )

            self.log_action(
                f"Recorded loan for customer {data['customer_id']}"
            )

            messagebox.showinfo(
                "Success",
                "Loan record saved successfully."
            )

            self.clear_loan_form()

            self.refresh_all()

        except (ValueError, InvalidOperation) as exc:

            messagebox.showerror(
                "Invalid Input",
                str(exc)
            )

        except Error as exc:

            messagebox.showerror(
                "Database Error",
                str(exc)
            )

    # =====================================================
    # CLEAR LOAN FORM
    # =====================================================

    def clear_loan_form(self):

        for widget in self.loan_fields.values():

            widget.delete(
                0,
                tk.END
            )

        self.loan_fields[
            "disbursement_date"
        ].insert(
            0,
            date.today().isoformat()
        )

        self.payment_mode.set(
            "Bank Transfer"
        )

        self.loan_status.set(
            "Disbursed"
        )

    # =====================================================
    # SEARCH AND RECORDS
    # =====================================================

    def build_records(self):

        page = self.pages["Search & Records"]

        top = tk.Frame(
            page,
            bg=COLORS["background"]
        )

        top.pack(
            fill="x",
            padx=18,
            pady=15
        )

        tk.Label(
            top,
            text="Search Customer:",
            bg=COLORS["background"],
            fg=COLORS["sidebar"],
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left"
        )

        self.search_entry = ttk.Entry(
            top,
            width=35
        )

        self.search_entry.pack(
            side="left",
            padx=10
        )

        self.search_entry.bind(
            "<Return>",
            lambda event: self.search_records()
        )

        ttk.Button(
            top,
            text="SEARCH",
            style="Primary.TButton",
            command=self.search_records
        ).pack(
            side="left"
        )

        ttk.Button(
            top,
            text="SHOW ALL",
            command=self.load_records
        ).pack(
            side="left",
            padx=6
        )

        customer_box = self.section(
            page,
            "CUSTOMER RECORDS"
        )

        customer_box.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=5
        )

        self.customer_tree = self.make_tree(

            customer_box,

            (
                "id",
                "name",
                "contact",
                "aadhaar",
                "pan",
                "wife",
                "wife_contact",
                "bank",
                "account"
            ),

            [

                "Customer ID",
                "Name",
                "Contact",
                "Aadhaar (12 digits)",
                "PAN (10 characters)",
                "Wife Name",
                "Wife Contact",
                "Bank",
                "Account"

            ],

            [
                110,
                170,
                130,
                175,
                135,
                150,
                140,
                140,
                150
            ],

            7

        )

        self.customer_tree.bind(
            "<<TreeviewSelect>>",
            self.select_customer
        )

        loan_box = self.section(
            page,
            "LOAN HISTORY"
        )

        loan_box.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=5
        )

        self.loan_tree = self.make_tree(

            loan_box,

            (
                "loan_id",
                "customer_id",
                "approved",
                "disbursed",
                "date",
                "mode",
                "status"
            ),

            [

                "Loan ID",
                "Customer ID",
                "Approved",
                "Disbursed",
                "Date",
                "Payment Mode",
                "Status"

            ],

            [
                90,
                120,
                150,
                150,
                120,
                140,
                130
            ],

            6

        )

    # =====================================================
    # SEARCH RECORDS
    # =====================================================

    def search_records(self):

        term = self.search_entry.get().strip()

        if not term:

            self.load_records()

            return

        like = f"%{term}%"

        rows = self.execute(
            """
            SELECT *
            FROM customers

            WHERE customer_id LIKE %s
            OR customer_name LIKE %s

            ORDER BY customer_name
            """,
            (like, like),
            fetch=True
        )

        self.populate_customer_tree(rows)

        ids = [

            row["customer_id"]

            for row in rows

        ]

        self.populate_loan_tree(ids)

    # =====================================================
    # LOAD RECORDS
    # =====================================================

    def load_records(self):

        rows = self.execute(
            """
            SELECT *
            FROM customers
            ORDER BY customer_name
            """,
            fetch=True
        )

        self.populate_customer_tree(rows)

        self.populate_loan_tree(None)

    # =====================================================
    # DISPLAY CUSTOMER RECORDS (FULL AADHAAR/PAN IN THIS TEST PROTOTYPE)
    # =====================================================

    def populate_customer_tree(self, rows):

        for item in self.customer_tree.get_children():

            self.customer_tree.delete(item)

        for index, row in enumerate(rows):

            aadhaar = row.get("aadhaar_number") or ""

            pan = row.get("pan_number") or ""

            account = row.get("account_number") or ""

            # Full Aadhaar and PAN are displayed in this prototype
            # because the user requested complete values in records.
            # Use only dummy data; production systems must mask/encrypt them.
            full_aadhaar = aadhaar if len(aadhaar) == 12 else ""
            full_pan = pan.upper() if len(pan) == 10 else ""

            masked_account = (

                "*" * max(0, len(account) - 4) + account[-4:]

                if account

                else ""

            )

            self.customer_tree.insert(

                "",

                "end",

                values=(

                    row["customer_id"],

                    row["customer_name"],

                    row.get("contact_number") or "",

                    full_aadhaar,

                    full_pan,

                    row.get("relative_name") or "",

                    row.get("relative_contact") or "",

                    row.get("bank_name") or "",

                    masked_account

                ),

                tags=(

                    "evenrow" if index % 2 == 0 else "oddrow",

                )

            )

        self.customer_tree.tag_configure(
            "evenrow",
            background=COLORS["card"]
        )

        self.customer_tree.tag_configure(
            "oddrow",
            background=COLORS["table_alt"]
        )

    # =====================================================
    # LOAN TREE
    # =====================================================

    def populate_loan_tree(self, customer_ids):

        for item in self.loan_tree.get_children():

            self.loan_tree.delete(item)

        if customer_ids is None:

            rows = self.execute(
                """
                SELECT *
                FROM loans
                ORDER BY loan_id DESC
                """,
                fetch=True
            )

        elif not customer_ids:

            rows = []

        else:

            placeholders = ",".join(
                ["%s"] * len(customer_ids)
            )

            rows = self.execute(
                f"""
                SELECT *
                FROM loans

                WHERE customer_id IN ({placeholders})

                ORDER BY loan_id DESC
                """,
                tuple(customer_ids),
                fetch=True
            )

        for row in rows:

            self.loan_tree.insert(

                "",

                "end",

                values=(

                    row["loan_id"],

                    row["customer_id"],

                    f"₹ {row['approved_amount']:,.2f}",

                    f"₹ {row['disbursed_amount']:,.2f}",

                    row["disbursement_date"],

                    row["payment_mode"] or "",

                    row["loan_status"]

                )

            )

    # =====================================================
    # DASHBOARD STATISTICS
    # =====================================================

    def refresh_dashboard(self):

        customer_count = self.execute(
            """
            SELECT COUNT(*) AS total
            FROM customers
            """,
            fetch=True
        )[0]["total"]

        loan_count = self.execute(
            """
            SELECT COUNT(*) AS total
            FROM loans
            """,
            fetch=True
        )[0]["total"]

        total = self.execute(
            """
            SELECT COALESCE(
                SUM(disbursed_amount),0
            ) AS total

            FROM loans
            """,
            fetch=True
        )[0]["total"]

        pending = self.execute(
            """
            SELECT COUNT(*) AS total
            FROM loans
            WHERE loan_status='Pending'
            """,
            fetch=True
        )[0]["total"]

        self.stats["customers"].config(
            text=str(customer_count)
        )

        self.stats["loans"].config(
            text=str(loan_count)
        )

        self.stats["disbursed"].config(
            text=f"₹ {total:,.2f}"
        )

        self.stats["pending"].config(
            text=str(pending)
        )

        for item in self.dashboard_tree.get_children():

            self.dashboard_tree.delete(item)

        rows = self.execute(
            """
            SELECT l.*, c.customer_name

            FROM loans l

            JOIN customers c

            ON l.customer_id=c.customer_id

            ORDER BY l.loan_id DESC

            LIMIT 20
            """,
            fetch=True
        )

        for row in rows:

            self.dashboard_tree.insert(

                "",

                "end",

                values=(

                    row["loan_id"],

                    row["customer_id"],

                    row["customer_name"],

                    f"₹ {row['approved_amount']:,.2f}",

                    f"₹ {row['disbursed_amount']:,.2f}",

                    row["disbursement_date"],

                    row["loan_status"]

                )

            )

    # =====================================================
    # REFRESH ALL
    # =====================================================

    def refresh_all(self):

        self.refresh_dashboard()

        self.load_records()

    # =====================================================
    # AUDIT LOGS
    # =====================================================

    def show_audit_logs(self):

        if self.current_role != "Admin":

            messagebox.showerror(
                "Permission Denied",
                "Only administrators can view audit logs."
            )

            return

        window = tk.Toplevel(self.root)

        window.title(
            "LoanPro | Administrator Audit Logs"
        )

        window.geometry("900x520")

        window.configure(
            bg=COLORS["background"]
        )

        box = self.section(
            window,
            "ADMINISTRATOR ACTIVITY HISTORY"
        )

        box.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=15
        )

        tree = self.make_tree(

            box,

            (
                "id",
                "user",
                "action",
                "time"
            ),

            (
                "Log ID",
                "Username",
                "Action",
                "Date and Time"
            ),

            (
                90,
                150,
                350,
                200
            ),

            15

        )

        rows = self.execute(
            """
            SELECT *
            FROM audit_logs

            ORDER BY log_id DESC

            LIMIT 500
            """,
            fetch=True
        )

        for row in rows:

            tree.insert(

                "",

                "end",

                values=(

                    row["log_id"],

                    row["username"],

                    row["action"],

                    row["log_time"]

                )

            )

    # =====================================================
    # LOGOUT
    # =====================================================

    def logout(self):

        if not messagebox.askyesno(
            "Logout",
            "Are you sure you want to logout?"
        ):

            return

        self.log_action("Logged out")

        self.current_user = None

        self.current_role = None

        self.show_login()

    # =====================================================
    # CLOSE APPLICATION
    # =====================================================

    def on_close(self):

        try:

            if self.conn and self.conn.is_connected():

                self.conn.close()

        finally:

            self.root.destroy()


root = tk.Tk()

app = None

root.protocol(
    "WM_DELETE_WINDOW",
    lambda: app.on_close() if app is not None else root.destroy()
)

app = LoanManagementApp(root)

try:
    if root.winfo_exists():
        root.mainloop()
except tk.TclError:
    pass
