const jwt = require('jsonwebtoken');
const User = require('./models/userlog');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    User.findById(user.id, (err, user) => {
      if (err) {
        return res.sendStatus(500);
      }

      req.user = user;
      next();
    });
  });
}

module.exports = authenticateToken;
