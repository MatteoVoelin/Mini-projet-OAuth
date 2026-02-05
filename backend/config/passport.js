const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { findUserByGoogleId, createUserFromGoogle } = require('../models/User');

// =============================================================================
// TODO 1: Configuration de la stratégie Google OAuth 2.0
// =============================================================================

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    passReqToCallback: true // Permet d'accéder à req.app.locals.db dans le callback
  },
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      // a. Récupérer db depuis req.app.locals.db
      const db = req.app.locals.db;

      // b. Chercher l'utilisateur par googleId (profile.id)
      let user = await findUserByGoogleId(db, profile.id);

      // c. Si l'utilisateur n'existe pas, le créer
      if (!user) {
        user = await createUserFromGoogle(db, {
          googleId: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName,
          picture: profile.photos[0].value
        });
      }

      // d. Appeler done(null, user) pour retourner l'utilisateur
      return done(null, user);
    } catch (error) {
      // e. En cas d'erreur
      return done(error, null);
    }
  }
));

// ⚠️ PAS de serializeUser/deserializeUser car on utilise JWT (stateless)
module.exports = passport;