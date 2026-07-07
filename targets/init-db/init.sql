CREATE DATABASE bank_db;

-- connect to bank_db and create table
\c bank_db;
CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,
    balance DECIMAL(10, 2) NOT NULL
);
INSERT INTO accounts (id, balance) VALUES (1, 1000.00);
