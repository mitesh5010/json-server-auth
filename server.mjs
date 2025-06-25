import { create, router as _router, defaults } from 'json-server';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import auth from 'json-server-auth';
import fs from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

// Create server instance
const server = create();
const router = _router('db.json');
const middlewares = defaults();

// Security configuration
const SECRET_KEY = "your_secret_key_should_be_long_and_complex";
const expiresIn = "1h";

// Helper functions
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Access denied: No token provided." });
  }
  try {
    jwt.verify(token, SECRET_KEY);
    next();
  } catch (err) {
    res.status(401).json({ message: "Access denied: Invalid token." });
  }
}

// Persistent data saving
setInterval(() => {
  const dbPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'db.json');
  fs.writeFileSync(dbPath, JSON.stringify(router.db.getState(), null, 2));
  console.log('Database saved at', new Date().toISOString());
}, 5000);

// Middleware setup
server.db = router.db;
server.use(bodyParser.json());
server.use(middlewares);
server.use(auth);

// Authentication endpoints
server.post("/login", (req, res) => {
  const { email, password } = req.body;
  
  if (!email?.trim() || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  const user = router.db.get("users").find({ email, password }).value();
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = createToken({ id: user.id, email: user.email });
  res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
});

server.post("/register", (req, res) => {
  const { email, password, name } = req.body;
  
  if (!email?.trim() || !password || !name?.trim()) {
    return res.status(400).json({ message: "All fields are required" });
  }

  if (router.db.get("users").find({ email }).value()) {
    return res.status(400).json({ message: "User already exists" });
  }

  const newUser = { 
    id: Date.now(), 
    email, 
    password, 
    name,
    created_at: new Date().toISOString() 
  };
  
  router.db.get("users").push(newUser).write();
  const token = createToken({ id: newUser.id, email: newUser.email });
  
  res.status(201).json({ 
    token, 
    user: { id: newUser.id, email: newUser.email, name: newUser.name } 
  });
});

// Protected routes
server.use("/users", verifyToken);
server.use("/600/forms", verifyToken);
server.use("/600/responses", verifyToken);

// JSON Server router
server.use(router);

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Database file: ${path.resolve('db.json')}`);
});