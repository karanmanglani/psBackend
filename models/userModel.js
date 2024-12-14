const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

// XOR-based Encryption
const SIMPLE_KEY = "mySimpleEncryptionKey";

function encrypt(text) {
  const key = Buffer.from(SIMPLE_KEY);
  const textBuffer = Buffer.from(text, 'utf8');
  const encrypted = textBuffer.map((byte, i) => byte ^ key[i % key.length]);
  return encrypted.toString('base64');
}

function decrypt(encodedText) {
  const key = Buffer.from(SIMPLE_KEY);
  const encryptedBuffer = Buffer.from(encodedText, 'base64');
  const decrypted = encryptedBuffer.map((byte, i) => byte ^ key[i % key.length]);
  return decrypted.toString('utf8');
}

// Validators
async function emailValidator(value) {
  if (value && !validator.isEmail(value)) {
    throw new Error('Please provide a valid email address.');
  }
  if (value) {
    const existingUser = await mongoose.models.User.findOne({ email: value });
    if (existingUser) {
      throw new Error('Email is already registered. Please use a different email.');
    }
  }
  return true;
}

async function phoneValidator(value) {
  if (value) {
    const existingUser = await mongoose.models.User.findOne({ phone: value });
    if (existingUser) {
      throw new Error('Phone number is already registered. Please use a different phone number.');
    }
  }
  return true;
}

// User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please tell us your name!']
  },
  username: {
    type: String,
    required: [true, 'Please provide a username'],
    unique: true
  },
  email: {
    type: String,
    unique: false,
    validate: {
      validator: emailValidator,
      message: '{VALUE} is not a valid email or it already exists.'
    },
    lowercase: true,
    required: false,
  },
  phone: {
    type: String,
    validate: {
      validator: phoneValidator,
      message: '{VALUE} is not a valid phone number or it already exists.'
    },
    default: null
  },
  address: {
    type: String,
    default: null,
  },
  permissions: {
    email: { type: Boolean, default: false },
    phone: { type: Boolean, default: false },
    address: { type: Boolean, default: false }
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!'
    }
  },
  ipAddress: {
    type: String,
    default: null,
  },
});

// Middleware to hash password and encrypt phone before saving
userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
    this.passwordConfirm = undefined;
  }
  if (this.isModified('phone') && this.phone) {
    this.phone = encrypt(this.phone);
  }
  next();
});

// Instance method to decrypt phone number
userSchema.methods.getDecryptedPhone = function () {
  if (this.phone) {
    return decrypt(this.phone);
  }
  return null;
};

// Instance method to check password correctness
userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

const User = mongoose.model('User', userSchema);
module.exports = User;