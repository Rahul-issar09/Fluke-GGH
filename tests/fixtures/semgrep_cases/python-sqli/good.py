import sqlite3


async def create_student(conn, name):
    async with conn.cursor() as cur:
        await cur.execute("INSERT INTO students (name) VALUES (%(name)s)", {"name": name})


def find_user(db: sqlite3.Connection, name: str):
    return db.execute("SELECT id FROM users WHERE name = ?", (name,)).fetchall()


def count(db):
    return db.execute(f"SELECT COUNT(*) FROM users").fetchone()


def report(db):
    sql = "SELECT id, name " + "FROM users"
    return db.execute(sql)


def page(db, limit):
    return db.execute("SELECT * FROM items LIMIT ?", (int(limit),))


def log(message, user):
    print("user %s: %s" % (user, message))
