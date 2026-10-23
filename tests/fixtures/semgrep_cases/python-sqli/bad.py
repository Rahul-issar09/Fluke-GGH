import sqlite3

from aiohttp import web


async def create_student(conn, name):
    async with conn.cursor() as cur:
        await cur.execute("INSERT INTO students (name) VALUES ('%(name)s')" % {"name": name})  # ruleid: python-sqli


async def course(request):
    course_id = request.match_info["id"]
    query = "SELECT * FROM courses WHERE id = {}".format(course_id)
    async with request.app["db"].cursor() as cur:
        await cur.execute(query)  # ruleid: python-sqli
        return web.json_response(await cur.fetchall())


def find_user(db: sqlite3.Connection, name: str):
    return db.execute(f"SELECT id FROM users WHERE name = '{name}'").fetchall()  # ruleid: python-sqli


def search(db, term, order):
    sql = "SELECT * FROM items WHERE title LIKE '%" + term + "%'"
    sql += " ORDER BY " + order
    return db.execute(sql)  # ruleid: python-sqli


def bulk(db, table, rows):
    db.executemany("INSERT INTO " + table + " VALUES (?, ?)", rows)  # ruleid: python-sqli
