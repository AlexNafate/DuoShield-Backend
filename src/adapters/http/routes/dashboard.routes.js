const express = require('express');
const router = express.Router();
const authenticateToken = require('../middleware/auth.middleware');
const MySQLUserRepository = require('../../database/mysql-user.repository');

const userRepository = new MySQLUserRepository();

// Ruta protegida con JWT - Principio Zero Trust: Validar token en cada peticin
router.get('/stats', authenticateToken, async (req, res) => {
  try {
    const userId = Number(req.user.sub);
    const user = await userRepository.findById(userId);

    if (!user) {
      return res.status(404).json({
        error: 'Usuario no encontrado en la base de datos',
      });
    }

    const clientIp =
      req.headers['x-forwarded-for'] ||
      req.socket.remoteAddress ||
      '127.0.0.1';

    return res.status(200).json({
      success: true,
      message: 'Acceso autorizado - Verificacin Zero Trust exitosa',
      timestamp: new Date().toISOString(),
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isActive: Boolean(user.is_active),
      },
      zeroTrustAudit: {
        authenticated: true,
        tokenSubject: req.user.sub,
        tokenIssuer: req.user.iss,
        tokenAudience: req.user.aud,
        tokenExpiresAt: new Date(req.user.exp * 1000).toISOString(),
        requestIp: clientIp,
        validationPolicy: 'Continua por peticin (Zero Trust)',
        backendVpcStatus: 'Aislado en Red Privada (Sin salida a Internet)',
      },
      securityControls: [
        { name: 'Autenticacin Continua JWT', status: 'Activo', detail: 'Firma HS256 vlida' },
        { name: 'Defensa en Profundidad', status: 'Activo', detail: 'Multi-capa (Nginx, UFW, Node, MySQL)' },
        { name: 'Seguridad Perimetral WAF', status: 'Preparado', detail: 'Filtro SQLi, XSS, Rate Limiting' },
        { name: 'Hardening de Host', status: 'Activo', detail: 'UFW habilitado, puertos cerrados' },
        { name: 'Proteccin Anti Fuerza Bruta', status: 'Activo', detail: 'Fail2ban monitoreando logs' },
      ],
      systemMetrics: {
        uptimeSeconds: Math.floor(process.uptime()),
        nodeVersion: process.version,
        memoryUsageMb: (process.memoryUsage().rss / 1024 / 1024).toFixed(2),
      },
    });
  } catch (error) {
    console.error('Error al obtener datos del dashboard protegido:', error);
    return res.status(500).json({
      error: 'Error interno del servidor al procesar el dashboard',
    });
  }
});

// Endpoint pblico de prueba para demostrar fallo de autenticacin en el reporte
router.get('/public-check', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Endpoint pblico accesible sin autenticacin',
  });
});

module.exports = router;
