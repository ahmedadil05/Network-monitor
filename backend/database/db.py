"""
database/db.py
Database connection management for both SQLite and MySQL (WampServer).
"""
import os
import sqlite3
import logging
from flask import g, current_app

try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
except ImportError:
    mysql = None
    MySQLError = Exception

logger = logging.getLogger(__name__)


def get_db():
    """Return the database connection for the current app context."""
    if "db" not in g:
        db_type = current_app.config.get("DB_TYPE", "sqlite")

        if db_type == "mysql":
            if mysql is None:
                raise ImportError("mysql-connector-python is not installed")
            
            g.db = mysql.connector.connect(
                host=current_app.config["MYSQL_HOST"],
                user=current_app.config["MYSQL_USER"],
                password=current_app.config["MYSQL_PASSWORD"],
                database=current_app.config["MYSQL_DB"],
                autocommit=True
            )
            # Row factory for MySQL (returns dict-like objects)
            g.db.row_factory = lambda cursor, row: dict(zip(cursor.column_names, row))
        else:
            # Fallback to SQLite
            g.db = sqlite3.connect(
                current_app.config["DATABASE_PATH"],
                detect_types=sqlite3.PARSE_DECLTYPES
            )
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
            
    return g.db


def close_db(e=None):
    """Close the database connection at end of request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """Initialize the database schema."""
    db_type = app.config.get("DB_TYPE", "sqlite")
    
    if db_type == "mysql":
        _init_mysql(app)
    else:
        _init_sqlite(app)


def _init_sqlite(app):
    """Initialize SQLite database."""
    os.makedirs(os.path.dirname(app.config["DATABASE_PATH"]), exist_ok=True)
    with app.app_context():
        db = sqlite3.connect(app.config["DATABASE_PATH"])
        with open(app.config["DATABASE_SCHEMA"], "r") as f:
            db.executescript(f.read())
        db.commit()
        db.close()
    logger.info("SQLite database initialized at %s", app.config["DATABASE_PATH"])


def _init_mysql(app):
    """Initialize MySQL database."""
    if mysql is None:
        logger.error("MySQL connector not available.")
        return

    try:
        # First connect without database to create it if it doesn't exist
        conn = mysql.connector.connect(
            host=app.config["MYSQL_HOST"],
            user=app.config["MYSQL_USER"],
            password=app.config["MYSQL_PASSWORD"]
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {app.config['MYSQL_DB']}")
        cursor.execute(f"USE {app.config['MYSQL_DB']}")
        
        # Execute schema script
        with open(app.config["MYSQL_SCHEMA"], "r") as f:
            schema_sql = f.read()
            # MySQL connector doesn't support executescript, split by ';'
            # This is a simple splitter; might fail if ';' is inside strings
            for statement in schema_sql.split(';'):
                if statement.strip():
                    cursor.execute(statement)
        
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("MySQL database '%s' initialized on %s", app.config["MYSQL_DB"], app.config["MYSQL_HOST"])
    except MySQLError as e:
        logger.error("Error initializing MySQL: %s", e)


def query_db(query, args=(), one=False):
    """Execute a SELECT query and return results."""
    db_type = current_app.config.get("DB_TYPE", "sqlite")
    
    # Convert placeholders if MySQL
    if db_type == "mysql":
        query = query.replace('?', '%s')
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute(query, args)
        rv = cursor.fetchall()
        cursor.close()
    else:
        # SQLite
        db = get_db()
        cur = db.execute(query, args)
        rv = cur.fetchall()
        
    return (rv[0] if rv else None) if one else rv


def execute_db(query, args=()):
    """Execute an INSERT/UPDATE/DELETE and commit."""
    db_type = current_app.config.get("DB_TYPE", "sqlite")
    
    if db_type == "mysql":
        query = query.replace('?', '%s')
        db = get_db()
        cursor = db.cursor()
        cursor.execute(query, args)
        lastrowid = cursor.lastrowid
        db.commit()
        cursor.close()
    else:
        # SQLite
        db = get_db()
        cur = db.execute(query, args)
        lastrowid = cur.lastrowid
        db.commit()
        
    return lastrowid


def execute_many_db(query, args_list):
    """Execute many INSERTs (Batch) for performance."""
    db_type = current_app.config.get("DB_TYPE", "sqlite")
    
    if db_type == "mysql":
        query = query.replace('?', '%s')
        db = get_db()
        cursor = db.cursor()
        cursor.executemany(query, args_list)
        db.commit()
        cursor.close()
    else:
        db = get_db()
        db.executemany(query, args_list)
        db.commit()
