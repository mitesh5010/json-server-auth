import jsonServer from "json-server";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";

const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();

const SECRET_KEY = "your_secret_key";
const expiresIn = "1h";

function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied: No token provided." });
  }
  try {
    jwt.verify(token, SECRET_KEY);
    next();
  } catch (err) {
    res.status(401).json({ message: "Access denied: Invalid token." });
  }
}

server.use(bodyParser.json());
server.use(middlewares);

// Authentication endpoints
server.post("/login", (req, res) => {
  const email = req.body.email?.trim();
  const password = req.body.password;

  if (!email || !password) {
    return res.status(400).json({ "message": "Email and password is required to login!" });
  }
  const user = router.db.get("users").find({ email, password }).value();

  if (!user) {
    return res.status(401).json({ message: "Invalid email or password" });
  }

  const token = createToken({ id: user.id, email: user.email });
  res.status(200).json({ token, user });
});

server.post("/register", (req, res) => {
  const email = req.body.email?.trim();
  const password = req.body.password;
  const name = req.body.name?.trim();

  if (!email || !password || !name) {
    return res.status(400).json({ "message": "Email, name and password is required to register!" });
  }

  const existingUser = router.db.get("users").find({ email }).value();

  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  const newUser = { id: Date.now(), email, password, name };
  router.db.get("users").push(newUser).write();

  const token = createToken({ id: newUser.id, email: newUser.email });
  res.status(201).json({ token, user: newUser });
});

// Protect all /groups routes
server.use("/users", verifyToken);

// Use JSON Server's router
server.use(router);
server.use("/forms", verifyToken);       // secure form routes
server.use("/responses", verifyToken); 

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`JSON Server is running on http://localhost:${PORT}`);
});
