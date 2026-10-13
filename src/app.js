require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const authRoutes = require('./adapters/http/routes/auth.routes');
const dashboardRoutes = require('./adapters/http/routes/dashboard.routes');

app.disable('x-powered-by');
app.use(helmet());

// Configuracin de CORS flexible para desarrollo y produccin (Nginx / Peering)
const allowedOrigin = process.env.FRONTEND_URL;
app.use(cors({
  origin: allowedOrigin ? [allowedOrigin, 'http://localhost:5173'] : true,
  credentials: true,
}));

app.use(express.json({ limit: '10kb' }));

// Rutas pblicas y de autenticacin
app.use('/api/auth', authRoutes);

// Rutas protegidas del Dashboard con verificacin continua JWT
app.use('/api/dashboard', dashboardRoutes);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
});

app.use('/api', apiLimiter);

app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    servicio: 'DuoShield API',
    arquitectura: 'Zero Trust & Defensa en Profundidad',
    timestamp: new Date().toISOString(),
  });
});

const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, () => {
  console.log(`DuoShield API escuchando en http://localhost:${PORT}`);
});
