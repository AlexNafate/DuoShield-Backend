const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({
      error: 'Acceso no autorizado: No se proporcionó token de autenticación (Zero Trust)',
      code: 'TOKEN_MISSING',
    });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({
      error: 'Formato de token inválido. Formato requerido: Bearer <token>',
      code: 'TOKEN_MALFORMED',
    });
  }

  const token = parts[1];

  if (!process.env.JWT_SECRET) {
    console.error('Error de configuración: JWT_SECRET no está definido');
    return res.status(500).json({
      error: 'Error interno de configuración de seguridad',
    });
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET,
    {
      issuer: 'duoshield-api',
      audience: 'duoshield-client',
    },
    (err, decoded) => {
      if (err) {
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({
            error: 'Sesión expirada: El token ha caducado. Inicie sesión nuevamente.',
            code: 'TOKEN_EXPIRED',
          });
        }
        return res.status(403).json({
          error: 'Token inválido o manipulado. Verificación Zero Trust fallida.',
          code: 'TOKEN_INVALID',
        });
      }

      req.user = decoded;
      next();
    }
  );
}

module.exports = authenticateToken;
