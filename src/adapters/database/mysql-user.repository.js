const pool = require('./mysql.pool');
const UserRepository = require('../../ports/user.repository');

class MySQLUserRepository extends UserRepository {
    async findByEmail(email) {
        const [rows] = await pool.execute(
            `SELECT id, name, email, password_hash, role, is_active
       FROM users
       WHERE email = ?
       LIMIT 1`,
            [email]
        );

        return rows[0] || null;
    }

    async create(user) {
        const [result] = await pool.execute(
            `INSERT INTO users (name, email, password_hash, role)
       VALUES (?, ?, ?, ?)`,
            [
                user.name,
                user.email,
                user.passwordHash,
                user.role || 'user',
            ]
        );

        return this.findById(result.insertId);
    }

    async findById(id) {
        const [rows] = await pool.execute(
            `SELECT id, name, email, role, is_active
       FROM users
       WHERE id = ?
       LIMIT 1`,
            [id]
        );

        return rows[0] || null;
    }
}

module.exports = MySQLUserRepository;