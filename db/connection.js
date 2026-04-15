const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
    host:               process.env.DB_HOST     || 'localhost',
    port:               parseInt(process.env.DB_PORT || '3306'),
    user:               process.env.DB_USER     || 'root',
    password:           process.env.DB_PASSWORD || 'yuan@123',
    database:           process.env.DB_NAME     || 'threatpulse',
    waitForConnections: true,
    connectionLimit:    10,
    queueLimit:         0,
    charset:            'utf8mb4',
    timezone:           'Z',          // store/return UTC
});

// Verify connectivity on startup
pool.getConnection()
    .then(conn => {
        console.log('[DB] Connected to MySQL — threatpulse database');
        conn.release();
    })
    .catch(err => {
        console.error('[DB] Connection failed:', err.message);
        process.exit(1);
    });

module.exports = pool;
