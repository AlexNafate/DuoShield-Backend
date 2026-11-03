const express = require('express');
const router = express.Router();
const authenticateToken = require('../middleware/auth.middleware');
const MySQLUserRepository = require('../../database/mysql-user.repository');
const fs = require('fs');
const path = require('path');

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

// Endpoint público de prueba para demostrar fallo de autenticación en el reporte
router.get('/public-check', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Endpoint público accesible sin autenticación',
  });
});

// ── IDS Alerts: lee las últimas alertas de Suricata (fast.log) ──────────────
// Protegido con JWT - solo usuarios autenticados pueden ver las alertas IDS
router.get('/ids-alerts', authenticateToken, (req, res) => {
  const LOG_PATH = '/var/log/suricata/fast.log';
  const MAX_LINES = 50;

  try {
    if (!fs.existsSync(LOG_PATH)) {
      return res.status(200).json({
        success: true,
        source: 'suricata-backend',
        alerts: [],
        message: 'Log de Suricata no encontrado en este servidor.',
      });
    }

    // Leer las últimas líneas del log
    const content = fs.readFileSync(LOG_PATH, 'utf8');
    const lines = content.split('\n').filter(l => l.trim() !== '');
    const lastLines = lines.slice(-MAX_LINES).reverse();

    // Parsear cada línea del fast.log de Suricata
    // Formato: MM/DD/YYYY-HH:MM:SS.us  [**] [gid:sid:rev] msg [**] [Classification: ...] [Priority: N] {PROTO} src -> dst
    const alerts = lastLines.map((line, idx) => {
      const tsMatch   = line.match(/^(\d{2}\/\d{2}\/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)/);
      const msgMatch  = line.match(/\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.+?)\s+\[\*\*\]/);
      const prioMatch = line.match(/\[Priority:\s*(\d+)\]/);
      const protoMatch= line.match(/\{(\w+)\}/);
      const ipMatch   = line.match(/\}\s+([\d\.]+)(?::\d+)?\s+->\s+([\d\.]+)/);

      const severity = prioMatch
        ? (prioMatch[1] === '1' ? 'CRÍTICO' : prioMatch[1] === '2' ? 'ALTO' : 'MEDIO')
        : 'INFO';

      return {
        id: idx,
        timestamp: tsMatch ? tsMatch[1] : 'Desconocido',
        message: msgMatch ? msgMatch[1].trim() : line.substring(0, 80),
        severity,
        protocol: protoMatch ? protoMatch[1] : 'UNKNOWN',
        srcIp: ipMatch ? ipMatch[1] : '?',
        dstIp: ipMatch ? ipMatch[2] : '?',
        raw: line,
      };
    });

    return res.status(200).json({
      success: true,
      source: 'suricata-backend',
      total: alerts.length,
      timestamp: new Date().toISOString(),
      alerts,
    });
  } catch (err) {
    console.error('Error al leer log de Suricata:', err.message);
    return res.status(500).json({
      success: false,
      error: 'No se pudo leer el log de Suricata.',
    });
  }
});

module.exports = router;
