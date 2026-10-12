require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const authRoutes = require('./adapters/http/routes/auth.routes');

app.disable('x-powered-by');
app.use(helmet());

app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
}));

app.use(express.json({ limit: '10kb' }));
app.use('/api/auth', authRoutes);

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
        message: 'API de DuoShield funcionando',
    });
});

const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, () => {
    console.log(`DuoShield API escuchando en http://localhost:${PORT}`);
});
