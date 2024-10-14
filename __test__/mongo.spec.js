const app = require('../server');
const request = require('supertest');
const mongoose = require('mongoose');
const User = require('../mongoose/models/user');
const RefreshToken = require('../mongoose/models/refreshToken'); 
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { disconnectDB } = require('../mongoose/connection');
const BlacklistedToken = require('../mongoose/models/BlacklistedToken')

afterEach(async () => {
    await User.deleteMany();
});

afterAll(async () => {
    await disconnectDB();
    console.log("Disconnected from in-memory MongoDB");
});

describe("User Routes", () => {
    
    describe("POST /api/signup", () => {
        it("should create a new user and return 201", async () => {
            const response = await request(app)
                .post('/api/signup')
                .send({
                    name: "Test User",
                    email: "testuser@example.com",
                    password: "Password123"
                });
            
            expect(response.statusCode).toBe(201);
            expect(response.body.success).toBe(true);
            expect(response.body.data).toHaveProperty('email', 'testuser@example.com');
        });

        it("should return 400 if the email already exists", async () => {
            const user = new User({
                name: "Existing User",
                email: "existing@example.com",
                password: await bcrypt.hash('Password123', 10),
            });
            await user.save();

            const response = await request(app)
                .post('/api/signup')
                .send({
                    name: "Existing User",
                    email: "existing@example.com",
                    password: "Password123"
                });
            
            expect(response.statusCode).toBe(400);
            expect(response.body.message).toBe("User already registered!");
        });
    });

    describe("POST /api/login", () => {
        describe("Logging with valid credentials", () => {
            it("should login a user and return a JWT token", async () => {
                const user = new User({ name: "Login User", email: "login@example.com", password: "Password123" });
                await user.save();

                const response = await request(app)
                    .post('/api/login')
                    .send({
                        email: "login@example.com",
                        password: "Password123"
                    });
                
                expect(response.statusCode).toBe(200);
                expect(response.body.msg).toBe("Logged in successfully");
                expect(response.body.accessToken).toBeDefined();
            });
        })
            it("should return 400 if credentials are invalid", async () => {
                const user = new User({ name: "Login User", email: "login@example.com", password: "Password123" });
                await user.save();

                const response = await request(app)
                    .post('/api/login')
                    .send({
                        email: "login@example.com",
                        password: "Wrongpassword1"
                    });
                
                expect(response.body.message).toBe("Access Denied");
            });
    });

    describe("GET /api/profile", () => {
        it("should return the user profile when authenticated with JWT", async () => {
            // Create a user and generate a JWT
            //const password = await bcrypt.hash('Password123', 10);
            const user = new User({ name: "Profile User", email: "profile@example.com", password: "Password123", agents: [{random: "gjsgkjgaiugeavjvgsguagjkdvkjlagv"}] });
            await user.save();
            
            const token = jwt.sign({ _id: user._id, random: "gjsgkjgaiugeavjvgsguagjkdvkjlagv"}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '24h' });

            const response = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${token}`);
            
            expect(response.statusCode).toBe(200);
            expect(response.body).toHaveProperty('email', 'profile@example.com');
            expect(response.body).not.toHaveProperty('password');  // Password should be excluded
        });
        it("should return status code 401 when authenticated with invalid JWT", async () => {
            // Create a user and generate a JWT
            //const password = await bcrypt.hash('Password123', 10);
            const user = new User({ name: "Profile User", email: "profile@example.com", password: "Password123", agents: [{random: "gjsgkjgaiugeavjvgsguagjkdvkjlagv"}] });
            await user.save();
            
            const token = jwt.sign({ _id: user._id, random: "hello"}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '24h' });

            const response = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${token}`);
            
            expect(response.statusCode).toBe(401);
        });

        it("should return 401 if no JWT is provided", async () => {
            const response = await request(app).get('/api/profile');
            expect(response.statusCode).toBe(401);
        });
    });
    describe("POST /api/renewAccessToken", () => {
        it("should renew access and refresh token with a valid refresh token", async () => {
            const user = new User({
                name: "Token User",
                email: "tokenuser@ex.com",
                password: "Password123",
            });
            await user.save();

            const loginResponse = await request(app)
                .post('/api/login') 
                .send({ email: user.email, password: "Password123" });
            const refreshToken = loginResponse.body.refreshToken; 
                
            const response = await request(app)
                .post('/api/renewAccessToken')
                .send({ refreshToken });
    
            expect(response.statusCode).toBe(200);
            expect(response.body).toHaveProperty('accessToken');
            expect(response.body).toHaveProperty('refreshToken');
        });
    
        it("should return 401 if no refresh token is provided", async () => {
            const response = await request(app)
                .post('/api/renewAccessToken')
                .send({});
    
            expect(response.statusCode).toBe(401);
            expect(response.body.msg).toBe("Refresh token is required");
        });
    
        it("should return 403 for an invalid refresh token", async () => {
            const invalidToken = "someInvalidToken";
    
            const response = await request(app)
                .post('/api/renewAccessToken')
                .send({ refreshToken: invalidToken });
    
            expect(response.statusCode).toBe(403);
            expect(response.body.msg).toBe("Invalid refresh token");
        });
    });
    describe("POST /api/logout", () => {
        let user;
        let accessToken;
        let refreshToken;
    
        beforeEach(async () => {
            user = new User({
                name: "Logout User",
                email: "logoutuser@e.com",
                password: "Password123",
            });
            await user.save();
    
            // Log in to get tokens
            const loginResponse = await request(app)
                .post('/api/login')
                .send({ email: user.email, password: "Password123" });
    
            accessToken = loginResponse.body.accessToken;
            refreshToken = loginResponse.body.refreshToken;
        });
    
        
        it("should logout the user by deleting the refresh token", async () => {
            const tokenCheckBeforeLogout = await RefreshToken.findOne({ token: refreshToken });
            expect(tokenCheckBeforeLogout).not.toBeNull(); 
    
            const response = await request(app)
                .post('/api/logout')
                .set('Authorization', `Bearer ${accessToken}`) 
                .send({ refreshToken });
    
            expect(response.statusCode).toBe(200);
            expect(response.body.msg).toBe("Logged out successfully");
    
            const tokenCheck = await RefreshToken.findOne({ token: refreshToken });
            expect(tokenCheck).toBeNull(); // Token should be removed from the database
        });
    
        it("should return 401 if no refresh token is provided", async () => {
            const response = await request(app)
                .post('/api/logout')
                .set('Authorization', `Bearer ${accessToken}`) 
                .send({});
    
            expect(response.statusCode).toBe(401);
            expect(response.body.msg).toBe("Refresh token is required");
        });
    
        it("should return 400 for an invalid refresh token", async () => {
            const invalidToken = "someInvalidToken";
    
            const response = await request(app)
                .post('/api/logout')
                .set('Authorization', `Bearer ${accessToken}`) 
                .send({ refreshToken: invalidToken });
    
            expect(response.statusCode).toBe(400);
            expect(response.body.msg).toBe("Invalid refresh token");
        });
    });
    describe("POST /api/admin/logout-user/:userId", () => {
        let user;
        let accessToken;
        let refreshToken;
    
        beforeEach(async () => {
            user = new User({
                name: "Logout User",
                email: "logoutuser@e.com",
                password: "Password123",

            });
            await user.save();
    
            // Log in to get tokens
            const loginResponse = await request(app)
                .post('/api/login')
                .send({ email: user.email, password: "Password123" });
    
            accessToken = loginResponse.body.accessToken;
            refreshToken = loginResponse.body.refreshToken;
        });
        it("should terminate the user's session and blacklist the token", async () => {
            // Fetch user from the database after login to get the updated 'agents' field
            const updatedUser = await User.findById(user._id); 
            
            // Check if agents field was automatically populated
            expect(updatedUser.agents).toBeDefined();
            expect(updatedUser.agents.length).toBeGreaterThan(0);
            console.log(updatedUser.agents)
    
            // Admin logs out the user and terminates the session
            const response = await request(app)
                .post(`/api/admin/logout-user/${user._id}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .send({ random: updatedUser.agents[0].random });
                console.log(updatedUser.agents[0].random)
    
            console.log(response.body);

            expect(response.statusCode).toBe(200);
            expect(response.body.agentsEmpty).toBe(true);
                
            const blacklistedToken = await BlacklistedToken.findOne({ token: accessToken });
            console.log("Blacklisted Token Found:", blacklistedToken); 

            expect(blacklistedToken).not.toBeNull(); // Token should be blacklisted
        });
    
        it("should return 404 if the user is not found", async () => {
            // creating a user that is not in a database
            const nonExistentUserId = new mongoose.Types.ObjectId();
    
            const response = await request(app)
                .post(`/api/admin/logout-user/${nonExistentUserId}`)
                .set('Authorization', `Bearer ${accessToken}`)
                .send({ random: "sessionRandomValue" });
    
            expect(response.statusCode).toBe(404);
            expect(response.body.message).toBe("User not found");
        });
    
        it("should return 401 if the authorization token is not provided", async () => {
            const user = new User({
                name: "Admin User",
                email: "adminuser@example.com",
                password: await bcrypt.hash("Password123", 10),
                agents: [{ random: "sessionRandomValue" }]
            });
            await user.save();
    
            const response = await request(app)
                .post(`/api/admin/logout-user/${user._id}`)
                .send({ random: "sessionRandomValue" });
    
            expect(response.statusCode).toBe(401);
            expect(response.body.message).toBe("Authorization token is required");
        });
    });  
});