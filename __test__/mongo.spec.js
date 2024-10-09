const app = require('../server');
const request = require('supertest');
const mongoose = require('mongoose');
const User = require('../mongoose/models/user');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Clear the database after each test
afterEach(async () => {
    await User.deleteMany();
});

afterAll(async () => {
    // Close the mongoose connection after all tests are done
    await mongoose.connection.close();
});

describe("User Auth Routes", () => {
    
    describe("POST /api/signup", () => {
        it("should create a new user and return 201", async () => {
            const response = await request(app)
                .post('/api/signup')
                .send({
                    name: "Test User",
                    email: "testuser@example.com",
                    password: "password123"
                });
            
            expect(response.statusCode).toBe(201);
            expect(response.body.success).toBe(true);
            expect(response.body.data).toHaveProperty('email', 'testuser@example.com');
        });

        it("should return 400 if the email already exists", async () => {
            const user = new User({
                name: "Existing User",
                email: "existing@example.com",
                password: await bcrypt.hash('password123', 10),
            });
            await user.save();

            const response = await request(app)
                .post('/api/signup')
                .send({
                    name: "Existing User",
                    email: "existing@example.com",
                    password: "password123"
                });
            
            expect(response.statusCode).toBe(400);
            expect(response.body.msg).toBe("User already exists with this email");
        });
    });

    describe("POST /api/login", () => {
        it("should login a user and return a JWT token", async () => {
            //const password = await bcrypt.hash('password123', 10);
            const user = new User({ name: "Login User", email: "login@example.com", password: "password123" });
            await user.save();

            const response = await request(app)
                .post('/api/login')
                .send({
                    email: "login@example.com",
                    password: "password123"
                });
            
            expect(response.statusCode).toBe(200);
            expect(response.body.msg).toBe("Logged in successfully");
            expect(response.body.accessToken).toBeDefined();
        });

        it("should return 400 if credentials are invalid", async () => {
            //const password = await bcrypt.hash('password123', 10);
            const user = new User({ name: "Login User", email: "login@example.com", password: "password123" });
            await user.save();

            const response = await request(app)
                .post('/api/login')
                .send({
                    email: "login@example.com",
                    password: "wrongpassword"
                });
            
            expect(response.statusCode).toBe(400);
            expect(response.body.msg).toBe("Invalid credentials");
        });
    });

    describe("GET /api/profile", () => {
        it("should return the user profile when authenticated with JWT", async () => {
            // Create a user and generate a JWT
            const password = await bcrypt.hash('password123', 10);
            const user = new User({ name: "Profile User", email: "profile@example.com", password });
            await user.save();
            
            const token = jwt.sign({ _id: user._id, email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });

            const response = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${token}`);
            
            expect(response.statusCode).toBe(200);
            expect(response.body).toHaveProperty('email', 'profile@example.com');
            expect(response.body).not.toHaveProperty('password');  // Password should be excluded
        });

        it("should return 401 if no JWT is provided", async () => {
            const response = await request(app).get('/api/profile');
            expect(response.statusCode).toBe(401);
        });
    });
});