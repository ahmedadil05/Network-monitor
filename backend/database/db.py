"""
database/db.py
PostgreSQL connection management and schema initialization.
Uses psycopg2 for PostgreSQL connectivity.
"""
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import g, current_app
import os


def get_db():
    """Return the database connection for the current app context."""
    if "db" not in g:
        try:
            g.db = psycopg2.connect(
                current_app.config["DATABASE_URL"],
                cursor_factory=RealDictCursor
            )
        except psycopg2.OperationalError as e:
            current_app.logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise
    return g.db


def close_db(e=None):
    """Close the database connection at end of request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """Create tables from schema.sql if they do not exist."""
    try:
        db = psycopg2.connect(app.config["DATABASE_URL"])
        cursor = db.cursor()
        
        with open(app.config["DATABASE_SCHEMA"], "r") as f:
            schema_sql = f.read()
            # Execute the entire schema script
            cursor.execute(schema_sql)
        
        db.commit()
        cursor.close()
        db.close()
        app.logger.info("Database schema initialized successfully.")
    except psycopg2.Error as e:
        app.logger.error(f"Failed to initialize database schema: {e}")
        raise


def query_db(query, args=(), one=False):
    """Execute a SELECT query and return results."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(query, args)
    
    if one:
        result = cursor.fetchone()
        cursor.close()
        return result
    else:
        results = cursor.fetchall()
        cursor.close()
        return results


def execute_db(query, args=(), return_id=False):
    """Execute an INSERT/UPDATE/DELETE and commit. Optionally return the inserted ID."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(query, args)
    
    if return_id:
        # For INSERT ... RETURNING id queries
        result = cursor.fetchone()
        db.commit()
        cursor.close()
        return result[0] if result else None
    else:
        db.commit()
        cursor.close()
        return None
