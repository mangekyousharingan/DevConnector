const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const User = require('../../models/User');
const { check, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const config = require('config');
const bcrypt = require('bcryptjs');


// @route  GET api/auth
// @desc   Test auth route
// @access Public
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (e) {
    console.error(e);
    res.status(500).json({msg: 'Internal Server Error!'})
  }
});

// @route  POST api/auth
// @desc   Authenticate user
// @access Public
router.post('/',
  [
    check('email', 'Please enter a valid email').isEmail(),
    check('password', 'Please is required').exists()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({errors: errors.array()})
    }

    const { email, password } = req.body;

    try {
      // Check if user exists
      let user = await User.findOne({
        email
      });
      if (!user) {
        return res.status(400).json({
          errors: [{
            msg: 'Invalid credentials!'
          }]
        })
      }
      // Return JWT
      const payload = {
        user: {
          id: user.id
        }
      };

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(400).json({
          errors: [{
            msg: 'Invalid credentials!'
          }]
        })
      }

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        {expiresIn: 360000},
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        });
    } catch (error) {
      console.error(error.message);
      res.status(500).message('Internal Server Error!')
    }
  });

module.exports = router;