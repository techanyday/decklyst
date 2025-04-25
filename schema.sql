-- Users table with Google OAuth support
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,  -- Not used with OAuth, but kept for flexibility
    verified BOOLEAN DEFAULT TRUE,  -- Always true with OAuth
    tier TEXT DEFAULT 'free' CHECK(tier IN ('free', 'paid')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Payment history table
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    payment_type TEXT NOT NULL,
    reference TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL,
    channel TEXT,
    mobile_number TEXT,
    transaction_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
