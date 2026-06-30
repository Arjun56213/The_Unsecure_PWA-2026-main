import sqlite3 as sql
import time
import random
import html
import hashlib
import threading


# Lock to prevent race conditions when reading and writing the visitor log
visitor_log_lock = threading.Lock()


def hash_password(password):

    # Convert the actual password to bytes, resulting in the actual password never being stored as is and being stored as a hashed value
    return hashlib.sha256(password.encode()).hexdigest()


def insertUser(username, password, DoB):

    # Using a context manager ensures the connection is always closed properly, even if an error occurs
    with sql.connect("database_files/database.db") as con:
        cur = con.cursor()

        # Hash the password before storing so plain text is never saved to the database
        hashed_password = hash_password(password)
        cur.execute(
            "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
            (username, hashed_password, DoB),
        )
        con.commit()


def retrieveUsers(username, password):

    # Using a context manager ensures the connection is always closed properly, even if an error occurs
    with sql.connect("database_files/database.db") as con:
        cur = con.cursor()

        # Hash the input password before comparing so we never check plain text against the database
        hashed_password = hash_password(password)

        # Checking username and password in a single query prevents an attacker from
        # determining whether a username exists based on the timing of the response
        cur.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, hashed_password),
        )
        result = cur.fetchone()

        # Acquire lock before reading and writing to prevent simultaneous access corrupting the count
        with visitor_log_lock:
            with open("visitor_log.txt", "r") as file:
                number = int(file.read().strip())
                number += 1
            with open("visitor_log.txt", "w") as file:
                file.write(str(number))

        # Simulate response time of heavy app for testing purposes
        time.sleep(random.randint(80, 90) / 1000)

        if result == None:
            return False
        else:
            return True


def insertFeedback(feedback):

    # Using a context manager ensures the connection is always closed properly, even if an error occurs
    with sql.connect("database_files/database.db") as con:
        cur = con.cursor()

        # Parameterised query prevents SQL injection by treating input as data, not code
        cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
        con.commit()


def listFeedback():

    # Using a context manager ensures the connection is always closed properly, even if an error occurs
    with sql.connect("database_files/database.db") as con:
        cur = con.cursor()
        data = cur.execute("SELECT * FROM feedback").fetchall()

    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")

        # Escape all HTML special characters in feedback before writing to the template - This prevents injected scripts from executing in the browser
        f.write(f"{html.escape(row[1])}\n")
        f.write("</p>\n")
    f.close()