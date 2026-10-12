const bcrypt = require('bcrypt');

class RegisterUser {
    constructor(userRepository) {
        this.userRepository = userRepository;
    }

    async execute({ name, email, password }) {
        if (
            typeof name !== 'string' ||
            typeof email !== 'string' ||
            typeof password !== 'string'
        ) {
            throw new Error('Todos los campos son obligatorios');
        }

        name = name.trim();
        email = email.trim().toLowerCase();

        if (name.length < 2 || name.length > 100) {
            throw new Error('El nombre debe tener entre 2 y 100 caracteres');
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            throw new Error('El correo electrónico no es válido');
        }

        if (password.length < 12 || password.length > 72) {
            throw new Error('La contraseña debe tener entre 12 y 72 caracteres');
        }

        const existingUser = await this.userRepository.findByEmail(email);

        if (existingUser) {
            throw new Error('El correo electrónico ya está registrado');
        }

        const passwordHash = await bcrypt.hash(password, 12);

        return this.userRepository.create({
            name,
            email,
            passwordHash,
            role: 'user',
        });
    }
}

module.exports = RegisterUser;
