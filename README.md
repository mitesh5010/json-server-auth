# JSON-Server-Auth

A simple setup for using **JSON Server** with authentication, enabling basic API mocking and user authentication functionality.

## Features

- Mock API for CRUD operations.
- Basic authentication with JWT for login and registration.
- Protected endpoints with JWT token.

## Getting Started

### Prerequisites

- **Node.js** and **npm** installed. If not, download and install from [Node.js](https://nodejs.org/).

### Steps:

1. **Clone the repository and start the project**:
   ```bash
   git clone https://github.com/mitesh5010/json-server-auth.git
   cd json-server-auth
   npm install
   npm start
   ```
2. **After Setup**:
   Test Authentication:

   `You can now access the authentication endpoints:`
   - POST /register to register a new user.
   - POST /login to authenticate and get a JWT token.
   - Use the JWT token in the Authorization header for protected routes.

   `CRUD Operations:`
   - The server exposes mock CRUD operations on your mock data stored in db.json. For example:
     - GET /posts to fetch posts.
     - POST /posts to create a new post.
     - PUT /posts/:id to update a post.
     - DELETE /posts/:id to delete a post.
   
   `Modify the Data:`
   - You can adjust the mock data in db.json to simulate different API responses or extend your mock server's functionality.

   `Troubleshooting:`
   - Ensure JSON Server is Installed: If you encounter an error saying Cannot find package 'json-server', ensure you have run npm install to install all dependencies.

   `JWT Authentication:`
   - If JWT token-related errors occur, check your JWT secret configuration in server.mjs
