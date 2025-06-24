const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'rapidread_secret_key';
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://Orange123:Orange123@cluster0.hhguvm7.mongodb.net/Bookstore?retryWrites=true&w=majority';

// ✅ CORS Configuration
app.use(cors({
  origin: ['http://localhost:5500', 'http://127.0.0.1:5500', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.static('public')); // For serving static files

// 📁 Serve static files (images)
app.use('/images', express.static(path.join(__dirname, 'images')));

// MongoDB connection
let db;

MongoClient.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(client => {
  db = client.db('Bookstore');
  console.log('✅ Connected to MongoDB');
  
  // Initialize sample data if needed
  // initializeSampleData();

  app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
  });
})
.catch(err => {
  console.error('❌ MongoDB connection failed:', err);
  process.exit(1);
});

// 🔐 JWT verification middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification failed:', err);
    res.status(401).json({ message: 'Invalid token' });
  }
};

// 📝 Input validation middleware
const validateRegistration = (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;
  
  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  
  if (firstName.trim().length < 2) {
    return res.status(400).json({ message: 'First name must be at least 2 characters' });
  }
  
  if (lastName.trim().length < 2) {
    return res.status(400).json({ message: 'Last name must be at least 2 characters' });
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Please provide a valid email address' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }
  
  next();
};

const validateLogin = (req, res, next) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  
  next();
};

// 🏠 Root route
app.get('/', (req, res) => {
  res.json({ 
    message: 'RapidReads API Server', 
    version: '1.0.0',
    status: 'Running',
    endpoints: {
      auth: {
        register: 'POST /auth/register',
        login: 'POST /auth/login'
      },
      products: {
        all: 'GET /collection/Products',
        search: 'GET /collection/Products/search?q=searchterm'
      },
      chatbot: 'POST /chatbot/respond'
    }
  });
});

// 👤 AUTHENTICATION ROUTES

// Register route
app.post('/auth/register', validateRegistration, async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    // Check if user already exists
    const userExists = await db.collection('Users').findOne({ email: email.toLowerCase() });
    if (userExists) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const result = await db.collection('Users').insertOne({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: email.toLowerCase(),
      password: hashedPassword,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: result.insertedId, 
        email: email.toLowerCase(),
        firstName: firstName.trim(),
        lastName: lastName.trim()
      }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        _id: result.insertedId,
        firstName: firstName.trim(),
        lastName: lastName.trim(),
        email: email.toLowerCase(),
      },
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Registration failed', error: err.message });
  }
});

// Login route
app.post('/auth/login', validateLogin, async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user
    const user = await db.collection('Users').findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Update last login
    await db.collection('Users').updateOne(
      { _id: user._id },
      { $set: { lastLogin: new Date() } }
    );

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user._id, 
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login failed', error: err.message });
  }
});

// 📚 PRODUCTS ROUTES

// Get all products
app.get('/collection/Products', async (req, res) => {
  try {
    const products = await db.collection('Products').find({}).toArray();
    res.json(products);
  } catch (err) {
    console.error('Error fetching products:', err);
    res.status(500).json({ message: 'Failed to fetch products', error: err.message });
  }
});

// Search products
app.get('/collection/Products/search', async (req, res) => {
  const { q } = req.query;
  
  if (!q || q.trim().length === 0) {
    return res.status(400).json({ message: 'Search query is required' });
  }

  try {
    const searchRegex = new RegExp(q, 'i'); // Case-insensitive search
    
    const products = await db.collection('Products').find({
      $or: [
        { title: searchRegex },
        { author: searchRegex },
        { genre: searchRegex },
        { description: searchRegex }
      ]
    }).toArray();
    
    res.json(products);
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ message: 'Search failed', error: err.message });
  }
});

// Get single product
app.get('/collection/Products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Try to find by custom id first, then by MongoDB _id
    let product = await db.collection('Products').findOne({ id: parseInt(id) });
    
    if (!product && ObjectId.isValid(id)) {
      product = await db.collection('Products').findOne({ _id: new ObjectId(id) });
    }
    
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    
    res.json(product);
  } catch (err) {
    console.error('Error fetching product:', err);
    res.status(500).json({ message: 'Failed to fetch product', error: err.message });
  }
});

// 🛒 CART & ORDER ROUTES (Protected)

// Add to cart (if you want to store cart in database)
app.post('/cart/add', verifyToken, async (req, res) => {
  const { productId, quantity = 1 } = req.body;
  const userId = req.user.id;

  try {
    // Check if product exists and has inventory
    const product = await db.collection('Products').findOne({ id: parseInt(productId) });
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    if (product.AvailableInventory < quantity) {
      return res.status(400).json({ message: 'Insufficient inventory' });
    }

    // Add to user's cart
    const cartItem = {
      userId: new ObjectId(userId),
      productId: parseInt(productId),
      quantity,
      addedAt: new Date()
    };

    await db.collection('Cart').insertOne(cartItem);
    
    // Update inventory
    await db.collection('Products').updateOne(
      { id: parseInt(productId) },
      { $inc: { AvailableInventory: -quantity } }
    );

    res.json({ message: 'Product added to cart successfully' });
  } catch (err) {
    console.error('Add to cart error:', err);
    res.status(500).json({ message: 'Failed to add to cart', error: err.message });
  }
});

// 🤖 CHATBOT ROUTE
app.post('/chatbot/respond', async (req, res) => {
  const { message } = req.body;
  
  if (!message || message.trim().length === 0) {
    return res.status(400).json({ message: 'Message is required' });
  }

  try {
    const lowerMessage = message.toLowerCase();
    let response = "I'm here to help! You can ask me about our books, prices, shipping, or anything else about RapidReads.";
    
    // Simple keyword-based responses
    const responses = {
      'hello': 'Hello! Welcome to RapidReads! How can I help you find your next great book today?',
      'hi': 'Hi there! I\'m here to help you with anything related to our bookstore. What can I do for you?',
      'books': 'We have an amazing collection of books across many genres including Fantasy, Fiction, Classics, Self-help, and more! What type of book interests you?',
      'genres': 'Our books cover many genres: Fantasy, Historical, Fiction, Self-help, Philosophical, Adventure, Classic, Commentary, Literature, and Political fiction.',
      'price': 'Our books are competitively priced, ranging from 34 AED to 95 AED. You can sort by price on our products page to find books within your budget!',
      'shipping': 'We offer fast delivery across the UAE, usually within 2-3 business days. Orders are processed quickly and shipped with care.',
      'delivery': 'We provide reliable delivery services throughout the UAE. Most orders arrive within 2-3 business days.',
      'help': 'I can help you with: finding books, information about genres, pricing details, shipping info, account questions, and general bookstore inquiries!',
      'account': 'For account-related questions, you can register or login on our site. If you have specific account issues, please contact our support team.',
      'authors': 'We feature books from renowned authors like J.K. Rowling, Harper Lee, James Clear, Paulo Coelho, and many more classic and contemporary writers.',
      'bestseller': 'Some of our popular books include Harry Potter series, To Kill a Mockingbird, Atomic Habits, and The Alchemist. Check out our full collection!',
      'recommend': 'I\'d be happy to recommend books! What genre do you enjoy? Are you looking for fiction, self-help, classics, or something else?',
      'search': 'You can search for books by title, author, or genre using the search bar on our products page. Try searching for your favorite author or genre!',
      'inventory': 'We keep our inventory updated in real-time. If a book shows as available on the product page, it\'s ready to ship!',
      'contact': 'You can reach our support team at support@rapidread.com or call +971-555-123456 for any assistance.',
      'thanks': 'You\'re very welcome! I\'m glad I could help. Happy reading, and enjoy your books from RapidReads!',
      'bye': 'Goodbye! Thanks for visiting RapidReads. Come back anytime for more great books. Happy reading!'
    };
    
    // Check for keyword matches
    for (let keyword in responses) {
      if (lowerMessage.includes(keyword)) {
        response = responses[keyword];
        break;
      }
    }
    
    // Special handling for specific questions
    if (lowerMessage.includes('how many') || lowerMessage.includes('count')) {
      try {
        const productCount = await db.collection('Products').countDocuments();
        response = `We currently have ${productCount} books available in our collection across various genres!`;
      } catch (err) {
        response = "We have a great selection of books available! Browse our products page to see our full collection.";
      }
    }
    
    res.json({ response });
  } catch (err) {
    console.error('Chatbot error:', err);
    res.status(500).json({ 
      response: "I'm sorry, I'm having some technical difficulties right now. Please try again in a moment!" 
    });
  }
});

// 📊 ADMIN ROUTES (Protected)
app.get('/admin/stats', verifyToken, async (req, res) => {
  try {
    const userCount = await db.collection('Users').countDocuments();
    const productCount = await db.collection('Products').countDocuments();
    
    res.json({
      users: userCount,
      products: productCount,
      serverStatus: 'Running'
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ message: 'Failed to fetch stats', error: err.message });
  }
});

// 🗃️ Initialize sample data
// async function initializeSampleData() {
//   try {
//     // Check if products already exist
//     const productCount = await db.collection('Products').countDocuments();
    
//     if (productCount === 0) {
//       console.log('📚 Initializing sample product data...');
      
//       const sampleProducts = [
//         {
//           id: 201,
//           title: "Harry Potter and the Order of the Phoenix",
//           author: "J.K. Rowling",
//           genre: "Fantasy",
//           price: 57,
//           image: "book1.jpeg",
//           AvailableInventory: 7,
//           description: "The fifth book in the Harry Potter series follows Harry's fifth year at Hogwarts School of Witchcraft and Wizardry."
//         },
//         {
//           id: 202,
//           title: "A Long Petal of the Sea",
//           author: "Isabel Allende",
//           genre: "Historical",
//           price: 66,
//           image: "book2.jpg",
//           AvailableInventory: 6,
//           description: "A sweeping novel that tells the story of Victor Dalmau, a young doctor, and Roser, a pregnant young woman, who flee the Spanish Civil War for Chile."
//         },
//         {
//           id: 203,
//           title: "Dear Edward: A Read with Jenna Pick",
//           author: "Ann Napolitano",
//           genre: "Fiction",
//           price: 51,
//           image: "book3.jpg",
//           AvailableInventory: 8,
//           description: "A transcendent coming-of-age story about the sole survivor of a plane crash."
//         },
//         {
//           id: 204,
//           title: "To Kill a Mockingbird",
//           author: "Harper Lee",
//           genre: "Fiction",
//           price: 55,
//           image: "book4.jpg",
//           AvailableInventory: 5,
//           description: "Harper Lee's timeless classic explores themes of racial injustice and moral growth through the eyes of Scout Finch in 1930s Alabama."
//         },
//         {
//           id: 205,
//           title: "Atomic Habits",
//           author: "James Clear",
//           genre: "Self help",
//           price: 66,
//           image: "book5.jpg",
//           AvailableInventory: 10,
//           description: "James Clear presents a comprehensive guide to building good habits and breaking bad ones."
//         },
//         {
//           id: 206,
//           title: "The Alchemist",
//           author: "Paulo Coelho",
//           genre: "Philosophical",
//           price: 53,
//           image: "book6.jpg",
//           AvailableInventory: 10,
//           description: "Paulo Coelho's philosophical novel follows Santiago, a young shepherd, on his journey to find treasure."
//         },
//         {
//           id: 207,
//           title: "Famous Five: Five Go Off to Camp",
//           author: "Enid Blyton",
//           genre: "Adventure",
//           price: 34,
//           image: "book7.jpg",
//           AvailableInventory: 8,
//           description: "Join the Famous Five on another exciting adventure as they go camping and discover mysterious happenings."
//         },
//         {
//           id: 208,
//           title: "Little Women",
//           author: "Louisa May Alcott",
//           genre: "Classic",
//           price: 65,
//           image: "book8.jpg",
//           AvailableInventory: 9,
//           description: "Louisa May Alcott's beloved novel follows the lives of the four March sisters as they grow from childhood to womanhood."
//         },
//         {
//           id: 209,
//           title: "Middlemarch",
//           author: "George Eliot",
//           genre: "Commentary",
//           price: 95,
//           image: "book9.jpg",
//           AvailableInventory: 6,
//           description: "George Eliot's masterpiece is set in the fictional town of Middlemarch and follows the lives of several characters."
//         },
//         {
//           id: 210,
//           title: "Mrs Dalloway",
//           author: "Virginia Woolf",
//           genre: "Literature",
//           price: 55,
//           image: "book10.jpg",
//           AvailableInventory: 9,
//           description: "Virginia Woolf's modernist novel follows Clarissa Dalloway through a single day in post-World War I London."
//         },
//         {
//           id: 211,
//           title: "Continental Drift",
//           author: "Russell Banks",
//           genre: "Political",
//           price: 56,
//           image: "book11.jpg",
//           AvailableInventory: 8,
//           description: "Russell Banks' powerful novel tells the parallel stories of a New Hampshire oil burner repairman and a Haitian refugee."
//         },
//         {
//           id: 212,
//           title: "The Little Prince",
//           author: "Antoine de Saint-Exupéry",
//           genre: "Adventure",
//           price: 62,
//           image: "book12.jpg",
//           AvailableInventory: 10,
//           description: "Antoine de Saint-Exupéry's beloved tale of a pilot who meets a young prince from another planet."
//         }
//       ];
      
//       await db.collection('Products').insertMany(sampleProducts);
//       console.log('✅ Sample product data initialized');
//     }
//   } catch (err) {
//     console.error('Error initializing sample data:', err);
//   }
// }

// 🚫 Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 🔍 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    message: 'Route not found',
    availableRoutes: {
      auth: ['/auth/register', '/auth/login'],
      products: ['/collection/Products', '/collection/Products/search'],
      chatbot: ['/chatbot/respond']
    }
  });
});

// 🛑 Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down server gracefully...');
  process.exit(0);
});

module.exports = app;