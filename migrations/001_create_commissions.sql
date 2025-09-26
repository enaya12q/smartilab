-- Run this SQL on your database if not using SQLAlchemy create_all()
CREATE TABLE IF NOT EXISTS commissions (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  from_user_id VARCHAR(36),
  amount NUMERIC(18,8) NOT NULL,
  created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT (now())
);
