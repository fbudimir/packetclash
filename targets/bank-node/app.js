const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

const DB_URL = process.env.DB_URL || 'postgresql://admin:password@postgres-db:5432/bank_db';
const PORT   = parseInt(process.env.PORT || '5003', 10);

// db pool
const pool = new Pool({ connectionString: DB_URL, max: 50 });

// db init
async function initDb() {
  let retries = 12;
  while (retries > 0) {
    try {
      const client = await pool.connect();
      try {
        await client.query(`
          CREATE TABLE IF NOT EXISTS accounts_node (
            id      INTEGER PRIMARY KEY,
            balance FLOAT NOT NULL
          )
        `);
        await client.query(`
          INSERT INTO accounts_node (id, balance)
          VALUES (1, 1000.0)
          ON CONFLICT (id) DO UPDATE SET balance = 1000.0
        `);
      } finally {
        client.release();
      }
      console.log('[bank-node] DB initialized');
      return;
    } catch (err) {
      console.log(`[bank-node] DB not ready (${retries} attempts left): ${err.message}`);
      retries--;
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  console.error('[bank-node] Could not connect to DB after 12 attempts');
  process.exit(1);
}




app.get('/api/balance', async (req, res) => {
  try {
    const r = await pool.query('SELECT balance FROM accounts_node WHERE id = 1');
    res.json({ balance: parseFloat(r.rows[0].balance) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/deposit', async (req, res) => {
  try {
    const amount = parseFloat(req.body.amount);
    const r = await pool.query(
      'UPDATE accounts_node SET balance = balance + $1 WHERE id = 1 RETURNING balance',
      [amount]
    );
    res.json({ status: 'success', deposited: amount, balance: parseFloat(r.rows[0].balance) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// RMW
app.post('/api/withdraw/rmw', async (req, res) => {
  const amount = parseFloat(req.body.amount);
  const client = await pool.connect();
  try {
    const sel = await client.query('SELECT balance FROM accounts_node WHERE id = 1');
    const balance = parseFloat(sel.rows[0].balance);

    await new Promise(r => setTimeout(r, 10));
    
    if (balance >= amount) {

      const newBalance = balance - amount;
      await client.query('UPDATE accounts_node SET balance = $1 WHERE id = 1', [newBalance]);
      res.json({ status: 'success', withdrawn: amount, remaining: newBalance });

    } else {
      res.status(400).json({ error: 'Insufficient funds' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// CHECK-THEN-ACT
app.post('/api/withdraw/sql-vulnerable', async (req, res) => {
  const amount = parseFloat(req.body.amount);
  const client = await pool.connect();
  try {
    const sel = await client.query('SELECT balance FROM accounts_node WHERE id = 1');
    const balance = parseFloat(sel.rows[0].balance);

    await new Promise(r => setTimeout(r, 10));
    
    if (balance >= amount) {
      await client.query('UPDATE accounts_node SET balance = balance - $1 WHERE id = 1', [amount]);
      res.json({ status: 'success', withdrawn: amount, remaining: balance - amount });
    } else {
      res.status(400).json({ error: 'Insufficient funds' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ATOMIC
app.post('/api/withdraw/sql-atomic', async (req, res) => {
  const amount = parseFloat(req.body.amount);
  const client = await pool.connect();
  try {

    await new Promise(r => setTimeout(r, 10));

    const r = await client.query(
      'UPDATE accounts_node SET balance = balance - $1 WHERE id = 1 AND balance >= $2 RETURNING balance',
      [amount, amount]
    );

    if (r.rowCount > 0) {
      res.json({ status: 'success', withdrawn: amount, remaining: parseFloat(r.rows[0].balance) });
    } else {
      res.status(400).json({ error: 'Insufficient funds' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});





initDb().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[bank-node] Listening on http://0.0.0.0:${PORT} (Express)`);
  });
});
