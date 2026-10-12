require('dotenv').config();
const pool = require('./src/adapters/database/mysql.pool');

async function testConnection() {
    try {
        const [rows] = await pool.query(
            'SELECT DATABASE() AS databaseName'
        );

        console.log('Conexión exitosa:', rows[0].databaseName);
    } catch (error) {
        console.error('Error de conexión:', error.message);
        process.exitCode = 1;
    } finally {
        await pool.end();
    }
}

testConnection();