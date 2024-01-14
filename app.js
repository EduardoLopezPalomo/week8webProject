const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = 3000;
const mongoDB = "mongodb://127.0.0.1:27017/testdb";
process.env.SECRET = 'secret-key';


mongoose.connect(mongoDB);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error"));
app.use(express.json());
app.use(passport.initialize());

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

const todoSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [{ type: String }]
});
  
const Todo = mongoose.model('Todo', todoSchema);

userSchema.pre('save', function(next) {
  const user = this;
  if (!user.isModified('password')) return next();

  bcrypt.hash(user.password, 10, (err, hash) => {
    if (err) return next(err);
    user.password = hash;
    next();
  });
});

const User = mongoose.model('User', userSchema);

app.post('/api/user/register',[body('email').isEmail(), body('password').isStrongPassword({ minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 })], async (req, res) => {
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid registration data', details: errors.array() });
    }
  
    try {
        const { email, password } = req.body;
  
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return res.status(403).json({ error: 'Email is already in use' });
        }
  
        const newUser = new User({ email, password });
        await newUser.save();
  
        res.status(200).json({ message: 'Registration successful' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
      }
    }
  );

app.post('/api/user/login', async (req, res) => {
    try {
      const { email, password } = req.body;
  
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
  
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
  
      const token = jwt.sign({ email: user.email }, process.env.SECRET, { expiresIn: '1h' });
  
      res.status(200).json({ token });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRET
  };
  
  passport.use(new JwtStrategy(jwtOptions, async (payload, done) => {
    try {
      const user = await User.findOne({ email: payload.email });
      if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    } catch (error) {
      return done(error, false);
    }
  }));

app.get('/api/private', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({ email: req.user.email });
});

app.post('/api/todos', passport.authenticate('jwt', { session: false }), [body('items').isArray()], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Invalid todo data', details: errors.array() });
    }
  
    try {
        const { items } = req.body;
        const userId = req.user._id;
  
        let existingTodo = await Todo.findOne({ user: userId });
  
        if (!existingTodo) {
          existingTodo = new Todo({ user: userId, items });
        } else {
          existingTodo.items = existingTodo.items.concat(items);
        }
  
        await existingTodo.save();
  
        res.status(200).json({ message: 'Todo list updated successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));
