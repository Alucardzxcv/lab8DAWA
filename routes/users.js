const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const router = express.Router();
const { validationResult } = require('express-validator');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: (value) => {
        // Expresión regular para validar el formato de correo electrónico
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
      },
      message: 'Correo electrónico inválido'
    }
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  }
});




// Hook para realizar el hash de la contraseña antes de guardar el documento
userSchema.pre('save', async function (next) {
  const user = this;

  if (!user.isModified('password')) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(user.password, salt);
    user.password = hashedPassword;
    next();
  } catch (error) {
    return next(error);
  }
});
// Método para comparar contraseñas
userSchema.methods.comparePassword = async function (password) {
  try {
    return await bcrypt.compare(password, this.password);
  } catch (error) {
    throw error;
  }
};


const User = mongoose.model('User', userSchema);
module.exports = User;


router.get('/', async (req, res) => {
  const users = await User.find();
  res.render('index', { users });
});

router.post('/', async (req, res) => {
  const newUser = new User(req.body);
  await newUser.save();
  res.redirect('/users');
});

router.get('/edit/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.render('partials/edit', { user });
});

router.post('/update/:id', async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, req.body);
  res.redirect('/users');
});

router.get('/delete/:id', async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.redirect('/users');
});

module.exports = router;
