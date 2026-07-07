import redis
import time
import os
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)

# DB url from docker-compose
redis_host = os.getenv('REDIS_HOST', 'localhost')
r = redis.Redis(host=redis_host, port=6379, db=0, decode_responses=True)

# init, runs when module is imported
def init_redis():
    # set value only if key doesn't exist yet
    r.setnx('balance', 1000)

init_redis() 






@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/balance', methods=['GET'])
def get_balance():
    balance = r.get('balance')
    return jsonify({"balance": float(balance or 0)})

@app.route('/api/deposit', methods=['POST'])
def deposit():
    amount = float(request.json.get('amount', 0))
    new_balance = r.incrbyfloat('balance', amount)
    return jsonify({"status": "success", "new_balance": new_balance}), 200




# RMW
@app.route('/api/withdraw/rmw', methods=['POST'])
def redis_rmw():
    data = request.json
    amount = float(data.get('amount', 0))
    
    balance = float(r.get('balance') or 0)
    
    if balance >= amount:

        new_balance = balance - amount
        r.set('balance', new_balance)
        return jsonify({"status": "success", "withdrawn": amount, "remaining": new_balance}), 200
    
    return jsonify({"status": "failed", "error": "Insufficient funds"}), 400

# CHECK-THEN-ACT
@app.route('/api/withdraw/redis-vulnerable', methods=['POST'])
def redis_vulnerable():
    data = request.json
    amount = float(data.get('amount', 0))
    
    balance = float(r.get('balance') or 0)
    
    if balance >= amount:
        
        new_balance = r.incrbyfloat('balance', -amount)
        return jsonify({"status": "success", "withdrawn": amount, "remaining": new_balance}), 200
        
    return jsonify({"status": "failed", "error": "Insufficient funds"}), 400

# LOCK
@app.route('/api/withdraw/redis-atomic', methods=['POST'])
def redis_lock_atomic():
    data = request.json
    amount = float(data.get('amount', 0))
    
    # creates key-value pair balance_lock which prevents parallel access, others wait if balance_lock exists
    # timeout ensures lock is released even if application crashes
    with r.lock('balance_lock', timeout=5):
        balance = float(r.get('balance') or 0)
        
        if balance >= amount:
            r.set('balance', balance - amount)
            return jsonify({"status": "success", "withdrawn": amount, "remaining": balance - amount}), 200
            
    return jsonify({"status": "failed", "error": "Insufficient funds"}), 400
