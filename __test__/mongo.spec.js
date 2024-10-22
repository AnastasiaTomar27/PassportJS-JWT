const app = require('@server');
const request = require('supertest');
const mongoose = require('mongoose');
const User = require('@modelsUser');
const jwt = require('jsonwebtoken');
const { disconnectDB } = require('@mongooseConnection');

afterEach(async () => {
    await User.deleteMany();
});

afterAll(async () => {
    await disconnectDB();
    console.log("Disconnected from DB")
});

describe("User Routes", () => {
    describe("POST /api/signup", () => {
        it("should create a new user and return 201, ROLE: USER", async () => {
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
        it("should create a new user and return 201, ROLE: 1534 - means ADMIN", async () => {
            const response = await request(app)
                .post('/api/signup')
                .send({
                    name: "Admin",
                    email: "admin@example.com",
                    password: "Password123",
                    role: "1534"
                });
            
            expect(response.statusCode).toBe(201);
            expect(response.body.success).toBe(true);
            expect(response.body.data).toHaveProperty('email', 'admin@example.com');
        });

        it("should return 400 if the email already exists", async () => {
            const user = new User({
                name: "Existing User",
                email: "existing@example.com",
                password: "Password123"

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
            expect(response.body.errors[0].msg).toBe("User already registered!");
        });

        describe("Registering with invalid credentials", () => {
            it("NAME: should return validation error for name, if it is empty", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        email: "testuser@example.com",
                        password: "Password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
            it("NAME: should return validation error for name, if it's lenght is more than 20 characters'", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markusssssssssssssssssssssssssssssssssssssssssss",
                        email: "testuser@example.com",
                        password: "Password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Name must be maximum of 20 characters.");
            });
            it("NAME: should return validation error for name, if it is not a string", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: 123,
                        email: "testuser@example.com",
                        password: "Password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
            it("EMAIL: should return validation error for email, if it is empty", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        password: "Password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
            it("EMAIL: should return validation error for email, if it's lenght is more than 30 characters'", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        email: "testuser@example.commmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm",
                        password: "Password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Email must be maximum of 30 characters.");
            });
            it("EMAIL: should return validation error for email, if it is not a string", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        email: 123,
                        password: "Password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
            it("PASSWORD: should return validation error for password, if it is empty", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        email: "testuser@example.com",
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
            it("PASSWORD: should return validation error for password, if it's lenght is more than 20 characters'", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        email: "testuser@example.com",
                        password: "Password123kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Password must be maximum of 20 characters.");
            });
            it("PASSWORD: should return validation error for password, if it is not a string", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        email: "testuser@example.com",
                        password: 123
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
            it("PASSWORD: should return validation error for password, if there is no capital letter", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        email: "testuser@example.com",
                        password: "password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("User password configuration is invalid");
            });
        });
    });

    describe("POST /api/login", () => {
        let user;
        beforeEach(async () => {
            user = new User({
                name: "Login User",
                email: "login@example.com",
                password: "Password123",
            });
            await user.save();
        });
        describe("Logging with valid credentials", () => {
            it("should login a user and return a JWT token", async () => {
                // login user
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
        describe("Logging with invalid credentials", () => {
            it("EMAIL: should return validation error for email, if it is empty", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        password: "Password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
            
            it("EMAIL: should return validation error for email, if it is not a string", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        email: 123,
                        password: "Password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
            it("PASSWORD: should return validation error for password, if it is empty", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        email: "testuser@example.com",
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
        });
    });

    describe("GET /api/profile", () => {
        let user;
        let accessToken;
        let refreshToken;

        beforeEach(async () => {
            user = new User({
                name: "Profile User",
                email: "profile@example.com",
                password: "Password123"
            });
            await user.save();
    
            // Log in to get tokens
            const loginResponse = await request(app)
                .post('/api/login')
                .send({ email: user.email, password: "Password123" });
    
            accessToken = loginResponse.body.accessToken;
            refreshToken = loginResponse.body.refreshToken;
        });
        it("should return the user profile when authenticated with access token", async () => { 
            const response = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${accessToken}`);
            
            expect(response.statusCode).toBe(200);
            expect(response.body.data).toHaveProperty('email', 'profile@example.com');
            expect(response.body.data).not.toHaveProperty('password');  // Password should be excluded
        });
        it("should return status code 401 when authenticated with invalid access token", async () => {
            const token = jwt.sign({ _id: user._id, random: "hello"}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '24h' });

            const response = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${token}`);
            
            expect(response.statusCode).toBe(401);
            expect(response.body.errors[0].msg).toBe("Unauthorized access");

        });

        it("should return 401 if no access token is provided", async () => {
            const response = await request(app).get('/api/profile');
            expect(response.statusCode).toBe(401);
        });
    });
    describe("POST /api/renewAccessToken", () => {
        let user;
        let accessToken;
        let refreshToken;

        beforeEach(async () => {
            user = new User({
                name: "Token User",
                email: "tokenuser@ex.com",
                password: "Password123",
                role: "user"
            });
            await user.save();
    
            // Log in to get tokens
            const loginResponse = await request(app)
                .post('/api/login')
                .send({ email: user.email, password: "Password123" });
            
            accessToken = loginResponse.body.accessToken;
            refreshToken = loginResponse.body.refreshToken;
        });
        it("should renew access and refresh token with a valid refresh token", async () => {   
            const response = await request(app)
                .post('/api/renewAccessToken')
                .send({ refreshToken });
    
            expect(response.statusCode).toBe(200);
            expect(response.body).toHaveProperty('accessToken');
            expect(response.body).toHaveProperty('refreshToken');
        
            // check if new access token works correctly, should get access to the user profile
            const newAccessToken = response.body.accessToken;

            profileRouteResponse = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${newAccessToken}`);

                expect(profileRouteResponse.statusCode).toBe(200); 
                expect(profileRouteResponse.body.data).toHaveProperty('email', 'tokenuser@ex.com');
                expect(profileRouteResponse.body.data).toHaveProperty('name', "Token User");
        });
    
        it("should return 400 if no refresh token is provided", async () => {
            const response = await request(app)
                .post('/api/renewAccessToken')
                .send({});
    
            expect(response.statusCode).toBe(400);
            expect(response.body.errors[0].msg).toBe("Refresh token is required");
        });
    
        it("should return 403 for an invalid refresh token", async () => {
            const invalidToken = "someInvalidToken";
    
            const response = await request(app)
                .post('/api/renewAccessToken')
                .send({ refreshToken: invalidToken });
    
            expect(response.statusCode).toBe(401);
            expect(response.body.errors[0].msg).toBe("Invalid or expired refresh token");
        });
    });
    describe("POST /api/logout", () => {
        let user;
        let accessToken;
    
        beforeEach(async () => {
            user = new User({
                name: "Logout User",
                email: "logoutuser@e.com",
                password: "Password123"
            });
            await user.save();
    
            // Log in to get tokens
            const loginResponse = await request(app)
                .post('/api/login')
                .send({ email: user.email, password: "Password123" });
    
            accessToken = loginResponse.body.accessToken;
            refreshToken = loginResponse.body.refreshToken;
        });
    
        it("should logout the user by deleting random value from agents array", async () => {
            const response = await request(app)
                .post('/api/logout')
                .set('Authorization', `Bearer ${accessToken}`) 
    
            expect(response.statusCode).toBe(200);
            expect(response.body.msg).toBe("Logged out successfully");
        
            // Verify that the random value was removed from agents array
            const updatedUser = await User.findById(user._id);
            expect(updatedUser.agents).toHaveLength(0);  

            // Can't access profile route, because accessToken in invalid now
            const profileResponse = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${accessToken}`) 
            
            expect(profileResponse.statusCode).toBe(401);
            expect(profileResponse.body.errors[0].msg).toBe("Unauthorized access");
        });
    
        it("should return 401 if no access token is provided", async () => {
            const response = await request(app)
                .post('/api/logout')

                // 401 - user failed to provide valid authentication credentials 
                //(in this case, the missing or invalid JWT access token).
                expect(response.statusCode).toBe(401);
                expect(response.body.errors[0].msg).toBe("Unauthorized access");
        });
    
        it("should return 401 if an invalid access token is provided", async () => {
            const invalidToken = "someInvalidToken"; 
    
            const response = await request(app)
                .post('/api/logout')
                .set('Authorization', `Bearer ${invalidToken}`);
    
            expect(response.statusCode).toBe(401);
            expect(response.body.errors[0].msg).toBe("Unauthorized access"); 
        });
    });
    describe("POST /api/admin/logout-user", () => {
        describe("ADMIN - admin terminate the user session", () => {
            let admin;
            let user;
            let userId;

            beforeEach(async () => {
                // creating admin
                admin = new User({
                    name: "Anastasia",
                    email: "anastasia@gmail.com",
                    password: "Password123",
                    role: "1534"
                });
                await admin.save();

                const loginAdminResponse = await request(app)
                    .post('/api/login')
                    .send({ email: admin.email, password: "Password123" });

                // admin tokens
                adminAccessToken = loginAdminResponse.body.accessToken;
                adminRefreshToken = loginAdminResponse.body.refreshToken;

                // creating user
                user = new User({
                    name: "User",
                    email: "user@gmail.com",
                    password: "Password123",
                    role: "user"
                });
                await user.save();

                const loginUserResponse = await request(app)
                    .post('/api/login')
                    .send({ email: user.email, password: "Password123" });
                
                // user tokens
                userAccessToken = loginUserResponse.body.accessToken;
                userRefreshToken = loginUserResponse.body.refreshToken;
                userId = user._id; 

            });

            it("should terminate the user session successfully and remove the agent", async () => {
                const response = await request(app)
                    .post('/api/admin/logout-user')
                    .send({ userId: userId })
                    .set('Authorization', `Bearer ${adminAccessToken}`);

                expect(response.statusCode).toBe(200);
                expect(response.body.data.msg).toBe("User session terminated");
                expect(response.body.data).toHaveProperty('email', 'user@gmail.com');


                // Verify that the agent was removed
                const updatedUser = await User.findById(userId);
                expect(updatedUser.agents).toHaveLength(0); 

                // user can not access profile with the current refresh token
                const profileResponse = await request(app)
                    .get('/api/profile')
                    .set('Authorization', `Bearer ${userAccessToken}`);

                expect(profileResponse.statusCode).toBe(401);
                expect(profileResponse.body.errors[0].msg).toBe("Unauthorized access");
            });
            it("should return 401 if no access token is provided", async () => {
                const response = await request(app)
                    .post('/api/admin/logout-user')
                    .send({ userId: userId });
                    
                    expect(response.statusCode).toBe(401);
                    expect(response.body.errors[0].msg).toBe("Unauthorized access");
            });
            it("should return 401 if an invalid access token is provided", async () => {
                const invalidToken = "someInvalidToken"; 
        
                const response = await request(app)
                    .post('/api/admin/logout-user')
                    .set('Authorization', `Bearer ${invalidToken}`)
                    .send({ userId: userId });
        
                expect(response.statusCode).toBe(401);
                expect(response.body.errors[0].msg).toBe("Unauthorized access"); 
            });

            it("should return 400 if the user id format is invalid", async () => {
                const invalidUserId = "6713"; 

                const response = await request(app)
                    .post('/api/admin/logout-user')
                    .send({ userId: invalidUserId })
                    .set('Authorization', `Bearer ${adminAccessToken}`);

                expect(response.statusCode).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid user ID format");
            });

            it("should return 404 if the user is not found, but id format is valid", async () => {
                const notExistedUserId = "6713c78fd409cad0b5f607c9"; 

                const response = await request(app)
                    .post('/api/admin/logout-user')
                    .send({ userId: notExistedUserId })
                    .set('Authorization', `Bearer ${adminAccessToken}`);

                expect(response.statusCode).toBe(404);
                expect(response.body.errors[0].msg).toBe("User not found");
            });
        });

        describe("USER - user try to access /api/admin/logout-user route", () => {
            let user;
            let userId;

            beforeEach(async () => {
                user = new User({
                    name: "Terminate Session User",
                    email: "terminateuser@gmail.com",
                    password: "Password123",
                    role: "user"
                });
                await user.save();

                const loginResponse = await request(app)
                    .post('/api/login')
                    .send({ email: user.email, password: "Password123" });
        
                accessToken = loginResponse.body.accessToken;
                refreshToken = loginResponse.body.refreshToken;
            });

            it("should return", async () => {
                userId = "671764557747fde82c663589"
                const response = await request(app)
                    .post('/api/admin/logout-user')
                    .send({ userId: userId })
                    .set('Authorization', `Bearer ${accessToken}`);

                expect(response.statusCode).toBe(403);
                expect(response.body.errors[0].msg).toBe("Access denied. You do not have the required permissions to access this resource.");
            });
         });
    });
        
});