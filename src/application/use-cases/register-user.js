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

        if (password.length < 6 || password.length > 8) {
            throw new Error('La contraseña debe tener entre 6 y 8 caracteres');
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