import sqlite3 as sql
import time
import random
import html
import hashlib


def hash_password(password):
    #convert the actual password to bytes, resulting in the actual password never being stored as is and being stored as a random assortment of bytes
    return hashlib.sha256(password.encode()).hexdigest()

def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
        # Hash the password before storing so plain text is never saved to the database
    hashed_password = hash_password(password)
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Parameterised query prevents SQL injection by treating input as data, not code
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cur.fetchone() == None:
        con.close()
        return False
    else:
        # Parameterised query prevents SQL injection by treating input as data, not code    
        # Hash the input password before comparing so we never check plain text against the database
        hashed_password = hash_password(password)
        cur.execute("SELECT * FROM users WHERE password = ?", (hashed_password,))
        # Plain text log of visitor count as requested by Unsecure PWA management
        with open("visitor_log.txt", "r") as file:
            number = int(file.read().strip())
            number += 1
        with open("visitor_log.txt", "w") as file:
            file.write(str(number))
        # Simulate response time of heavy app for testing purposes
        time.sleep(random.randint(80, 90) / 1000)
        if cur.fetchone() == None:
            con.close()
            return False
        else:
            con.close()
            return True


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Parameterised query prevents SQL injection by treating input as data, not code
    cur.execute(f"INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")

        #Escape all HTML special characters in feedback before writing to the template - This prevents injected script from executing in the browser
        f.write(f"{html.escape(row[1])}\n")
        f.write("</p>\n")
    f.close()
