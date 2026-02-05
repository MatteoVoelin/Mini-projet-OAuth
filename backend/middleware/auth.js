const jwt = require('jsonwebtoken');
const { findUserById } = require('../models/User'); // Importe la fonction de recherche par ID

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        error: 'Access token requis',
        message: 'Vous devez être connecté'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const db = req.app.locals.db;

    // Récupérer l'utilisateur (on utilise ici l'ID stocké dans le token)
    // On passe 'db' si on utilise le driver natif comme dans le TODO 1
    const user = await findUserById(db, decoded.userId);

    if (!user) {
      return res.status(404).json({
        error: 'Utilisateur non trouvé'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expiré' });
    }
    res.status(403).json({ error: 'Token invalide' });
  }
};

module.exports = { authenticateToken };