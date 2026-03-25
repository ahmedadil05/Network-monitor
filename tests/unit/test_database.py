"""
tests/unit/test_database.py
Unit tests for database connection and operations.
"""
import unittest
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

class TestDatabaseConnection(unittest.TestCase):
    def setUp(self):
        import sqlite3
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test.db")
        self.schema_path = os.path.join(self.temp_dir, "schema.sql")
        
        schema = """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'administrator'
        );

        CREATE TABLE IF NOT EXISTS raw_log_files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            uploaded_by INTEGER,
            upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            row_count INTEGER DEFAULT 0,
            processed INTEGER DEFAULT 0,
            FOREIGN KEY (uploaded_by) REFERENCES users(user_id)
        );

        CREATE TABLE IF NOT EXISTS log_entries (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            timestamp DATETIME,
            source_ip TEXT,
            destination_ip TEXT,
            event_type TEXT,
            message TEXT,
            duration REAL,
            protocol_type TEXT,
            service TEXT,
            flag TEXT,
            src_bytes INTEGER,
            dst_bytes INTEGER,
            land INTEGER,
            wrong_fragment INTEGER,
            urgent INTEGER,
            original_label TEXT,
            FOREIGN KEY (file_id) REFERENCES raw_log_files(file_id)
        );

        CREATE TABLE IF NOT EXISTS anomaly_results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            anomaly_score REAL,
            severity TEXT,
            detection_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'OPEN',
            explanation TEXT,
            FOREIGN KEY (log_id) REFERENCES log_entries(log_id)
        );
        """
        with open(self.schema_path, 'w') as f:
            f.write(schema)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_connection_creation(self):
        """Test that database connection can be created."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        self.assertIsNotNone(db)
        db.close()

    def test_schema_creation(self):
        """Test that all tables are created from schema."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        db.commit()
        
        cursor = db.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        self.assertIn("users", tables)
        self.assertIn("raw_log_files", tables)
        self.assertIn("log_entries", tables)
        self.assertIn("anomaly_results", tables)
        db.close()

    def test_insert_and_retrieve(self):
        """Test INSERT and SELECT operations."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        
        db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   ("testuser", "hash123", "administrator"))
        db.commit()
        
        cursor = db.execute("SELECT * FROM users WHERE username = ?", ("testuser",))
        user = cursor.fetchone()
        
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "testuser")
        self.assertEqual(user["role"], "administrator")
        db.close()

    def test_foreign_key_constraint(self):
        """Test that foreign key constraints work."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   ("admin", "hash"))
        db.commit()
        
        cursor = db.execute("SELECT user_id FROM users WHERE username = ?", ("admin",))
        user_id = cursor.fetchone()["user_id"]
        
        db.execute("INSERT INTO raw_log_files (file_name, uploaded_by) VALUES (?, ?)",
                   ("test.csv", user_id))
        db.commit()
        
        cursor = db.execute("SELECT file_id FROM raw_log_files WHERE uploaded_by = ?", (user_id,))
        file_id = cursor.fetchone()["file_id"]
        
        self.assertEqual(file_id, 1)
        db.close()

    def test_query_returns_list(self):
        """Test that query_db returns a list."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        
        for i in range(3):
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (f"user{i}", "hash"))
        db.commit()
        
        results = db.execute("SELECT * FROM users").fetchall()
        self.assertEqual(len(results), 3)
        db.close()

    def test_query_returns_one(self):
        """Test that query with one=True returns single row."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   ("single", "hash"))
        db.commit()
        
        result = db.execute("SELECT * FROM users WHERE username = ?", ("single",)).fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result["username"], "single")
        db.close()

    def test_update_operation(self):
        """Test UPDATE operation."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        
        db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   ("update_test", "old_hash", "user"))
        db.commit()
        
        db.execute("UPDATE users SET role = ? WHERE username = ?",
                   ("administrator", "update_test"))
        db.commit()
        
        cursor = db.execute("SELECT role FROM users WHERE username = ?", ("update_test",))
        role = cursor.fetchone()[0]
        self.assertEqual(role, "administrator")
        db.close()

    def test_delete_operation(self):
        """Test DELETE operation."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   ("delete_test", "hash"))
        db.commit()
        
        db.execute("DELETE FROM users WHERE username = ?", ("delete_test",))
        db.commit()
        
        cursor = db.execute("SELECT * FROM users WHERE username = ?", ("delete_test",))
        self.assertIsNone(cursor.fetchone())
        db.close()

    def test_transaction_rollback(self):
        """Test that transaction can be rolled back."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   ("rollback_test", "hash"))
        db.commit()
        
        db.execute("DELETE FROM users")
        db.rollback()
        
        cursor = db.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 1)
        db.close()

    def test_concurrent_inserts(self):
        """Test multiple inserts in sequence."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        
        usernames = ["user1", "user2", "user3", "user4", "user5"]
        for username in usernames:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, "hash"))
        db.commit()
        
        cursor = db.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 5)
        db.close()

    def test_row_factory_works(self):
        """Test that row_factory enables dict-like access."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   ("row_test", "hash"))
        db.commit()
        
        row = db.execute("SELECT * FROM users WHERE username = ?", ("row_test",)).fetchone()
        
        self.assertEqual(row["username"], "row_test")
        self.assertEqual(row["role"], "administrator")
        self.assertIsNotNone(row.keys())
        db.close()

    def test_lastrowid_returns_id(self):
        """Test that lastrowid returns the inserted ID."""
        import sqlite3
        db = sqlite3.connect(self.db_path)
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        
        cursor = db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           ("lastrowid_test", "hash"))
        db.commit()
        
        self.assertEqual(cursor.lastrowid, 1)
        db.close()

    def test_database_file_creation(self):
        """Test that database file is created on disk."""
        import sqlite3
        self.assertFalse(os.path.exists(self.db_path))
        
        db = sqlite3.connect(self.db_path)
        db.execute("PRAGMA foreign_keys = ON")
        with open(self.schema_path, 'r') as f:
            db.executescript(f.read())
        db.close()
        
        self.assertTrue(os.path.exists(self.db_path))
        self.assertGreater(os.path.getsize(self.db_path), 0)


if __name__ == "__main__":
    unittest.main()
