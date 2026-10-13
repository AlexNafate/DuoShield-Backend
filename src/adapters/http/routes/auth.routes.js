const express = require('express');
const rateLimit = require('express-rate-limit');

const MySQLUserRepository = require('../../database/mysql-user.repository');
const RegisterUser = require('../../../application/use-cases/register-user');
const LoginUser = require('../../../application/use-cases/login-user');

const router = express.Router();
const userRepository = new MySQLUserRepository();

const registerUser = new RegisterUser(userRepository);
const loginUser = new LoginUser(userRepository);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    error: 'Demasiados intentos. Intenta de nuevo más tarde.',
  },
});

router.get('/test', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Rutas de autenticación cargadas correctamente',
  });
});

router.post('/register', async (req, res) => {
  try {
    const user = await registerUser.execute(req.body);

    return res.status(201).json({
      message: 'Usuario registrado correctamente',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    const erroresValidacion = [
      'El correo electrónico ya está registrado',
      'Todos los campos son obligatorios',
      'El correo electrónico no es válido',
      'El nombre debe tener entre 2 y 100 caracteres',
      'La contraseña debe tener entre 6 y 8 caracteres',
    ];

    if (erroresValidacion.includes(error.message)) {
      return res.status(400).json({
        error: error.message,
      });
    }

    console.error('Error al registrar usuario:', error);

    return res.status(500).json({
      error: 'No se pudo registrar el usuario',
    });
  }
});

router.post('/login', loginLimiter, async (req, res) => {
  try {
    const result = await loginUser.execute(req.body);

    return res.status(200).json(result);
  } catch (error) {
    if (
      error.message === 'Credenciales incorrectas' ||
      error.message === 'Correo y contraseña son obligatorios'
    ) {
      return res.status(401).json({
        error: 'Credenciales incorrectas',
      });
    }

    if (error.message.includes('obligatorios')) {
      return res.status(400).json({
        error: error.message,
      });
    }

    console.error('Error al iniciar sesión:', error);

    return res.status(500).json({
      error: 'No se pudo iniciar sesión',
    });
  }
});

module.exports = router;