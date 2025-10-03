const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const User = require('../models/users');

passport.use(new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password',
    session: false
  },
  async (email, password, done) => {
    // TEMP debug (remove once stable)
    console.log('Passport login attempt:', email);

    try {
      const normEmail = (email || '').toLowerCase().trim();
      const user = await User.findOne({ email: normEmail });
      if (!user) {
        return done(null, false, { message: 'Incorrect email.' });
      }
      if (typeof user.validPassword !== 'function' || !user.validPassword(password)) {
        return done(null, false, { message: 'Incorrect password.' });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));