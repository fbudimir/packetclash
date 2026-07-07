import psycopg2
from psycopg2 import pool
import time
import os
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)

# DB url from docker-compose
DB_URL = os.environ.get('DB_URL', 'postgresql://admin:password@postgres-db:5432/bank_db')

try:
    db_pool = pool.ThreadedConnectionPool(1, 50, DB_URL)
except Exception as e:
    print(f"Error creating connection pool: {e}")
    db_pool = None

@app.errorhandler(pool.PoolError)
def handle_pool_exhausted(e):
    return jsonify({"status": "error", "message": "Pool exhausted"}), 503

def get_db_connection():
    if db_pool:
        return db_pool.getconn()
    return psycopg2.connect(DB_URL)

def release_db_connection(conn):
    if db_pool:
        db_pool.putconn(conn)
    else:
        conn.close()

def init_db():
    conn = get_db_connection()
    conn.autocommit = True
    cursor = conn.cursor()
    
    # table creation if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY, 
            balance FLOAT
        )
    ''')
    
    # reset state for testing
    cursor.execute('''
        INSERT INTO accounts (id, balance) 
        VALUES (1, 1000.0) 
        ON CONFLICT (id) DO UPDATE SET balance = 1000.0
    ''')
    
    release_db_connection(conn)
    print("DB initialized (Postgres)")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/balance', methods=['GET'])
def get_balance():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM accounts WHERE id = 1")
    balance = float(cursor.fetchone()[0])
    release_db_connection(conn)
    return jsonify({"balance": balance})

@app.route('/api/deposit', methods=['POST'])
def deposit():

    data = request.json
    amount = float(data.get('amount', 0))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE accounts SET balance = balance + %s WHERE id = 1", (amount,))
    conn.commit()
    
    cursor.execute("SELECT balance FROM accounts WHERE id = 1")
    new_balance = float(cursor.fetchone()[0])
    release_db_connection(conn)
    
    return jsonify({"status": "success", "msg": f"Deposited {amount}€", "new_balance": new_balance}), 200

# READ-MODIFY-WRITE
@app.route('/api/withdraw/rmw', methods=['POST'])
def withdraw():
    data = request.json
    amount = float(data.get('amount', 0))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # postgres starts transaction automatically at first execute() if autocommit not true
    cursor.execute("SELECT balance FROM accounts WHERE id = 1")
    balance = float(cursor.fetchone()[0])

    # race window
    time.sleep(0.01)

    if balance >= amount:
        new_balance = balance - amount
        # rmw: overwrite the amount in database with what we calculated in python
        cursor.execute("UPDATE accounts SET balance = %s WHERE id = 1", (new_balance,))
        conn.commit()
        release_db_connection(conn)
        return jsonify({"status": "success", "withdrawn": amount, "remaining": new_balance}), 200
    
    release_db_connection(conn)
    return jsonify({"status": "failed", "error": "Insufficient funds"}), 400


# check-then-act
@app.route('/api/withdraw/sql-vulnerable', methods=['POST'])
def withdraw_sql_vulnerable():
    data = request.json
    amount = float(data.get('amount', 0))

    print(f"[bank] Worker PID={os.getpid()} handling withdrawal", flush=True)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT balance FROM accounts WHERE id = 1")
    balance = float(cursor.fetchone()[0])

    # race window
    time.sleep(0.01)

    if balance >= amount:
        # relative update, but decision in if was made based on old data
        cursor.execute("UPDATE accounts SET balance = balance - %s WHERE id = 1", (amount,))
        conn.commit()
        
        cursor.execute("SELECT balance FROM accounts WHERE id = 1")
        new_balance = float(cursor.fetchone()[0])
        release_db_connection(conn)
        return jsonify({"status": "success", "withdrawn": amount, "remaining": new_balance}), 200

    conn.commit()
    release_db_connection(conn)
    return jsonify({"status": "failed", "error": "Insufficient funds"}), 400

# ATOMIC SQL
@app.route('/api/withdraw/sql-atomic', methods=['POST'])
def withdraw_sql_atomic():
    data = request.json
    amount = float(data.get('amount', 0))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    time.sleep(0.01)

    # atomic query, db checks condition at moment of writing
    cursor.execute("""
        UPDATE accounts 
        SET balance = balance - %s 
        WHERE id = 1 AND balance >= %s
        RETURNING balance
    """, (amount, amount))
    
    row = cursor.fetchone()
    conn.commit()

    if row:
        new_balance = float(row[0])
        release_db_connection(conn)
        return jsonify({"status": "success", "withdrawn": amount, "remaining": new_balance}), 200

    release_db_connection(conn)
    return jsonify({"status": "failed", "error": "Insufficient funds"}), 400

if __name__ == '__main__':
    # wait for postgres container to start, just in case
    time.sleep(3)
    init_db()
    app.run(host='0.0.0.0', port=5000, threaded=True)