import sqlite3

con=sqlite3.connect("school.db")
cur=con.cursor()
cur.execute("""
CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL
            password TEXT NOT NULL
            role TEXT NOT NULL
            class_name TEXT NOT NULL)""")

con.commit()
con.close()