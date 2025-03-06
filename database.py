import sqlite3
import logging

class Database:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()

    def close(self):
        self.conn.close()

    def add(self, table, **columns):
        columns_names = ', '.join(columns.keys())
        placeholders = ', '.join(['?' for _ in columns])
        sql = f"INSERT INTO {table} ({columns_names}) VALUES ({placeholders})"
        return self.execute(sql, tuple(columns.values()))
    
    def execute(self, sql, params=()):
        logging.debug(f"Executing SQL command {sql, params}")
        try:
            self.cursor.execute(sql, params)
            self.conn.commit()
            return True
        except sqlite3.Error:
            return False

    def contains(self, table, column, value):
        try:
            self.cursor.execute(f"SELECT 1 FROM {table} WHERE {column} = ?", (value,))
            return self.cursor.fetchone() is not None
        except sqlite3.Error:
            return False

    def create_table(self, table_name, columns):
        column_definitions = ", ".join(f"{col} {dtype}" for col, dtype in columns.items())
        sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({column_definitions})"
        self.execute(sql)