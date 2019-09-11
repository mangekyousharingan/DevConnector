const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function (req, res, next) {
//  GET Token
  const token = req.header('x-auth-token');

//  check if no token
  if (!token) {
    return res.status(404).json({msg: 'No token!'})
  }

//  verify token
  try {
    const decoded = jwt.verify(token, config.get('jwtSecret'));
    req.user = decoded.user;
    next();
  } catch (e) {
    res.status(401).json({msg: 'Token is not valid!'})
  }
};