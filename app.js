const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const Book = require('./models/Book');
const authenticateToken = require('./authMiddleware');

const router = express.Router();

// User registration
router.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  User.findOne().or([{ username }, { email }])
    .then(existingUser => {
      if (existingUser) {
        return res.status(409).json({ message: 'Username or email already exists' });
      }

      return bcrypt.hash(password, 10);
    })
    .then(hashedPassword => {
      const newUser = new User({
        username,
        email,
        password: hashedPassword,
      });

      return newUser.save();
    })
    .then(() => {
      res.status(201).json({ message: 'User registered successfully' });
    })
    .catch(error => {
      res.status(500).json({ message: 'Internal server error' });
    });
});

// User login
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username })
    .then(user => {
      if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      return bcrypt.compare(password, user.password)
        .then(passwordMatch => {
          if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
          }

          const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY);
          res.json({ token });
        });
    })
    .catch(error => {
      res.status(500).json({ message: 'Internal server error' });
    });
});

// Get all books
router.get('/books', authenticateToken, (req, res) => {
  Book.find()
    .then(books => {
      res.json(books);
    })
    .catch(error => {
      res.status(500).json({ message: 'Internal server error' });
    });
});

// Create a new book
router.post('/books', authenticateToken, (req, res) => {
  const { title, author, price, rating } = req.body;

  const newBook = new Book({
    title,
    author,
    price,
    rating,
  });

  newBook.save()
    .then(() => {
      res.status(201).json({ message: 'Book created successfully' });
    })
    .catch(error => {
      res.status(500).json({ message: 'Internal server error' });
    });
});

// Get a book by ID
router.get('/books/:id', authenticateToken, (req, res) => {
  Book.findById(req.params.id)
    .then(book => {
      if (!book) {
        return res.status(404).json({ message: 'Book not found' });
      }

      res.json(book);
    })
    .catch(error => {
      res.status(500).json({ message: 'Internal server error' });
    });
});

// Update a book by ID
router.put('/books/:id', authenticateToken, (req, res) => {
  const { title, author, price, rating } = req.body;

  Book.findByIdAndUpdate(
    req.params.id,
    { title, author, price, rating },
    { new: true }
  )
    .then(updatedBook => {
      if (!updatedBook) {
        return res.status(404).json({ message: 'Book not found' });
      }

      res.json({ message: 'Book updated successfully' });
    })
    .catch(error => {
      res.status(500).json({ message: 'Internal server error' });
    });
});

// Delete a book by ID
router.delete('/books/:id', authenticateToken, (req, res) => {
  Book.findByIdAndRemove(req.params.id)
    .then(deletedBook => {
      if (!deletedBook) {
        return res.status(404).json({ message: 'Book not found' });
      }

      res.json({ message: 'Book deleted successfully' });
    })
    .catch(error => {
      res.status(500).json({ message: 'Internal server error' });
    });
});

module.exports = router;
