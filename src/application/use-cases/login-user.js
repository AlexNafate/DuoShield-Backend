const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

class LoginUser {
    constructor(userRepository) {
        this.userRepository = userRepository;
    }

    async execute({ email, password }) {
        if (
            typeof email !== 'string' ||
            typeof password !== 'string' ||
            !email.trim() ||
            !password
        ) {
            throw new Error('Correo y contraseña son obligatorios');
        }

        const normalizedEmail = email.trim().toLowerCase();
        const user = await this.userRepository.findByEmail(normalizedEmail);

        // Mensaje genérico para no revelar si el correo existe.
        if (!user || !user.is_active) {
            throw new Error('Credenciales incorrectas');
        }

        const passwordMatches = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatches) {
            throw new Error('Credenciales incorrectas');
        }

        if (!process.env.JWT_SECRET) {
            throw new Error('La configuración de autenticación no está disponible');
        }

        const token = jwt.sign(
            {
                sub: String(user.id),
                role: user.role,
            },
            process.env.JWT_SECRET,
            {
                expiresIn: process.env.JWT_EXPIRES_IN || '15m',
                issuer: 'duoshield-api',
                audience: 'duoshield-client',
            }
        );

        return {
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
            },
        };
    }
}

module.exports = LoginUser;