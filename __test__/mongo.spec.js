const app = require('@server');
const request = require('supertest');
const User = require('@modelUser');
const jwt = require('jsonwebtoken');
const { disconnectDB } = require('@mongooseConnection');
const Product = require('@modelProduct');
const Order = require('@modelOrder');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD
const { buildPDF } = require('@buildPDF'); 
const { sendInvoiceEmail } = require('@emailService'); 
const fs = require('fs');
const path = require('path');
const mock = require('mock-fs');


jest.mock('@buildPDF', () => ({
    buildPDF: jest.fn()
  }));
  
jest.mock('@emailService', () => ({
    sendInvoiceEmail: jest.fn(), 
}));

// Jest mocks the entire speakeasy. These mocked speakeasy functions don’t perform real 2FA operations; they just provide hardcoded responses, allowing us to verify how our route behaves based on expected input
jest.mock('speakeasy', () => ({
    // mocking the generateSecret function
    //jest.fn() creates a mock function which can record calls made to it and specify what it should return.
    // .mockReturnValue(...) return a value: here always {base32: 'mocked-secret'}
    generateSecret: jest.fn().mockReturnValue({
        base32: 'mocked-secret',
    }),
    // return 'mocked-url' every time it’s called, simulating the URL creation for the 2FA setup.
    otpauthURL: jest.fn().mockReturnValue('mocked-url'),
    //totp.verify is mocked to return true, which simulates successful verification of TOTP
    totp: {
        verify: jest.fn().mockReturnValue(true),
    },
}));

jest.mock('qrcode', () => ({
    toDataURL: jest.fn().mockResolvedValue('fakeQRCodeUrl'),
}));

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
        // it will not check if its really an admin, should I send role in response or just change the logic in register route? 
        it("should create a new user and return 201, ROLE: ADMIN", async () => {
            const response = await request(app)
                .post('/api/signup')
                .send({
                    name: "Admin",
                    email: "admin@example.com",
                    password: "Password123",
                    role: "admin",
                    adminPassword: ADMIN_PASSWORD
                });

            expect(response.statusCode).toBe(201);
            expect(response.body.success).toBe(true);
            expect(response.body.data).toHaveProperty('email', 'admin@example.com');
        
            const adminUser = await User.findOne({ email: "admin@example.com" });

            expect(adminUser.role).toBe("admin");
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
            it("EMAIL: should return validation error for email, if it doesn't contain @", async () => {
                const response = await request(app)
                    .post('/api/signup')
                    .send({
                        name: "Markus",
                        email: "markusgmail.com",
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
            it("should login a user and return access and refresh tokens", async () => {
                // login user
                const response = await request(app)
                    .post('/api/login')
                    .send({
                        email: "login@example.com",
                        password: "Password123"
                    });
                
                expect(response.statusCode).toBe(200);
                expect(response.body.msg).toBe("Please set up Two-Factor Authentication.");
                expect(response.body.temporaryToken).toBeDefined();
                expect(response.body.data.userId).toBeDefined();
                expect(response.body.data.needs2FASetup).toBe(true);
            });
        })
        describe("Logging with invalid credentials: user email doesn't exist", () => {
            it("should return status 401 and error Acecc Denied", async () => {
                const response = await request(app)
                    .post('/api/login')
                    .send({
                        email: "user@gmail.com",
                        password: "Password123"
                    });
            
                expect(response.status).toBe(401);
                expect(response.body.errors[0].msg).toBe("Access Denied");
            });
            it("EMAIL: should return validation error for email, if it is empty", async () => {
                const response = await request(app)
                    .post('/api/login')
                    .send({
                        password: "Password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
            
            it("EMAIL: should return validation error for email, if it is not a string", async () => {
                const response = await request(app)
                    .post('/api/login')
                    .send({
                        email: 123,
                        password: "Password123"
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
            it("PASSWORD: should return validation error for password, if it is empty", async () => {
                const response = await request(app)
                    .post('/api/login')
                    .send({
                        email: "testuser@example.com",
                    });
            
                expect(response.status).toBe(400);
                expect(response.body.errors[0].msg).toBe("Invalid value");
            });
        });
    });

    describe("POST /api/setup2FA", () => {
        let user;

        beforeEach(async () => {
            // Create a new user with no 2FA secret
            user = new User({
                name: "Test User",
                email: "testuser@example.com",
                password: "Password123",
            });
            await user.save();
            // Log in to get temporary token
            const loginResponse = await request(app)
                .post('/api/login')
                .send({ email: user.email, password: "Password123" });
                
            temporaryToken = loginResponse.body.temporaryToken;
        });

        it("should return an error if 2FA is already set up", async () => {
            // Simulate user having 2FA already set up
            user.twoFactorSecret = "fakeSecret";
            await user.save();

            const response = await request(app)
                .post('/api/setup2FA')
                .set('Authorization', `Bearer ${temporaryToken}`); // Assume user is authenticated

            expect(response.status).toBe(400);
            expect(response.body.errors[0].msg).toBe("2FA is already set up");
        });

        it("should return QRCode and secret when setting up 2FA", async () => {
            // Mock speakeasy to generate a secret
            speakeasy.generateSecret.mockReturnValue({
                base32: "secret123",
            });
            // Mock QRCode generation
            QRCode.toDataURL.mockResolvedValue("fakeQRCodeUrl");
            // const token = jwt.sign({ _id: user._id }, 'your-secret-key'); // Generate a JWT token

            const response = await request(app)
                .post('/api/setup2FA')
                .set('Authorization', `Bearer ${temporaryToken}`);

            expect(response.status).toBe(200);
            //expect(response.body.secret).toBe("secret123");
            expect(response.body.QRCode).toBe("fakeQRCodeUrl");
        });

        it("should return an error if there is an issue generating 2FA", async () => {
            speakeasy.generateSecret.mockImplementation(() => {
                throw new Error("Error generating 2FA secret");
            });

            const response = await request(app)
                .post('/api/setup2FA')
                .set('Authorization', `Bearer ${temporaryToken}`);

            expect(response.status).toBe(500);
            expect(response.body.errors[0].msg).toBe("Error setting up 2FA");
        });
    });



    describe("POST /api/reset2FA", () => {
        let user;
        let temporaryToken;

        beforeEach(async () => {
            // Create a new user and log them in to get a token
            user = new User({
                name: "Reset2FA User",
                email: "reset2fa@example.com",
                password: "Password123",
            });
            await user.save();

            // Log in to get a temporary token
            const loginResponse = await request(app)
                .post('/api/login')
                .send({ email: user.email, password: "Password123" });

            temporaryToken = loginResponse.body.temporaryToken;
        });

        afterEach(async () => {
            jest.restoreAllMocks();
            await User.deleteMany();
        });

        it("should successfully reset 2FA and return QR code URL", async () => {
            user.twoFactorSecret = "existingSecret";
            await user.save();

            // Mocking speakeasy and QRCode libraries
            const secretMock = { base32: "newSecret" };
            const qrCodeMockUrl = "fakeQRCodeUrl";
            
            jest.spyOn(speakeasy, 'generateSecret').mockReturnValue(secretMock);
            jest.spyOn(QRCode, 'toDataURL').mockResolvedValue(qrCodeMockUrl);

            const response = await request(app)
                .post('/api/reset2FA')
                .set('Authorization', `Bearer ${temporaryToken}`);
            
            expect(response.status).toBe(200);
            expect(response.body.msg).toBe("2FA has been reset successfully");
            expect(response.body.QRCode).toBe(qrCodeMockUrl);

            // Check that user's 2FA secret has been updated
            const updatedUser = await User.findById(user._id);
            expect(updatedUser.twoFactorSecret).toBe(secretMock.base32);
            expect(updatedUser.twoFactorSecret).not.toBe("existingSecret");
        });

        it("should return a 500 error if QR code generation fails", async () => {
            jest.spyOn(speakeasy, 'generateSecret').mockReturnValue({ base32: "newSecret" });
            jest.spyOn(QRCode, 'toDataURL').mockRejectedValue(new Error("QR code generation error"));

            const response = await request(app)
                .post('/api/reset2FA')
                .set('Authorization', `Bearer ${temporaryToken}`);
            
            expect(response.status).toBe(500);
            expect(response.body.errors[0].msg).toBe("Error resetting 2FA");
        });

        it("should return a 500 error if user save fails", async () => {
            jest.spyOn(speakeasy, 'generateSecret').mockReturnValue({ base32: "newSecret" });
            jest.spyOn(QRCode, 'toDataURL').mockResolvedValue("fakeQRCodeUrl");

            // Mock the save method to throw an error on the second save attempt
            jest.spyOn(User.prototype, 'save').mockImplementationOnce(() => Promise.resolve())
                .mockImplementationOnce(() => Promise.reject(new Error("Save failed")));

            const response = await request(app)
                .post('/api/reset2FA')
                .set('Authorization', `Bearer ${temporaryToken}`);
            
            expect(response.status).toBe(500);
            expect(response.body.errors[0].msg).toBe("Error resetting 2FA");
        });

        it("should return a 401 error if no user is found in request", async () => {
            // Simulate no user in the request by not setting the `req.user`
            const response = await request(app)
                .post('/api/reset2FA')
                .set('Authorization', `Bearer invalidToken`); // Invalid token simulates missing user

            expect(response.status).toBe(401);
            expect(response.body.errors[0].msg).toBe("Unauthorized access");
        });
    });


    describe("POST /api/verify2FA", () => {
        let user;

        beforeEach(async () => {
            user = new User({
                name: "Test User",
                email: "testuser@example.com",
                password: "Password123",
            });
            user.twoFactorSecret = "secret123"; // Set up 2FA for testing
            await user.save();
            // Log in to get temporary token
            const loginResponse = await request(app)
                .post('/api/login')
                .send({ email: user.email, password: "Password123" });
                
            temporaryToken = loginResponse.body.temporaryToken;
        });

        it("should return an error if TOTP is missing", async () => {
            const response = await request(app)
                .post('/api/verify2FA')
                .set('Authorization', `Bearer ${temporaryToken}`)
                .send({}); // No TOTP

            expect(response.status).toBe(422);
            expect(response.body.errors[0].msg).toBe("TOTP is required");
        });

        it("should return an error if the TOTP is incorrect", async () => {            
            speakeasy.totp.verify = jest.fn().mockReturnValue(false);

            const response = await request(app)
                .post('/api/verify2FA')
                .set('Authorization', `Bearer ${temporaryToken}`)
                .send({ totp: "invalidTotp" });
        

            expect(response.status).toBe(400);
            expect(response.body.message).toBe("TOTP is not correct or expired");
        });
        

        it("should generate new tokens and return success if TOTP is correct", async () => {
            // Mock speakeasy to verify the TOTP
            speakeasy.totp.verify.mockReturnValue(true);
            
            const response = await request(app)
                .post('/api/verify2FA')
                .set('Authorization', `Bearer ${temporaryToken}`)
                .send({ totp: "correctTotp" });

            expect(response.status).toBe(200);
            expect(response.body.status).toBe(true);
            expect(response.body.msg).toBe("TOTP validated successfully: user logged in successfully");
            expect(response.body.accessToken).toBeDefined();
            expect(response.body.refreshToken).toBeDefined();
            expect(response.body.data.user).toBe(user.name);
            expect(response.body.data.email).toBe(user.email);
        });

        it("should return an error if there is a server error during user save", async () => {
            // Register a new test user for this specific test case
            const errorUser = new User({
                name: "Error Test User",
                email: "errortestuser@example.com",
                password: "Password123",
            });
            errorUser.twoFactorSecret = "secretForErrorTest";
            await errorUser.save();
        
            // Log in to get a temporary token for this user
            const loginResponse = await request(app)
                .post('/api/login')
                .send({ email: errorUser.email, password: "Password123" });
        
            const errorUserToken = loginResponse.body.temporaryToken;
        
            // Mock TOTP verification to return true
            jest.spyOn(speakeasy.totp, 'verify').mockReturnValue(true);
        
            // Mock save to throw an error for this specific user instance
            // jest.spyOn(User.prototype, 'save') ensures that any save call on User instances during this test will throw an error.
            jest.spyOn(User.prototype, 'save').mockImplementationOnce(() => {
                throw new Error("Save failed");
            });        
            // Call verify2FA endpoint
            const response = await request(app)
                .post('/api/verify2FA')
                .set('Authorization', `Bearer ${errorUserToken}`)
                .send({ totp: "correctTotp" });
        
            // Assertions
            expect(response.status).toBe(500);
            expect(response.body.errors[0].msg).toBe("Error saving user agents");
        });
        
    });


    describe("GET /api/profile", () => {
        const keys = process.env.ACCESS_TOKEN_SECRET;
        const accessTokenExpiry = process.env.JWT_ACCESS_TOKEN_EXPIRY; // e.g., "10m"
        let accessToken;
        let user;
        const random = "some_random_value";

        beforeEach(async () => {
            // Step 1: Create and save a new user with `isTwoFactorVerified` set to true
            user = new User({
                name: "Profile User",
                email: "profile@example.com",
                password: "Password123",
                isTwoFactorVerified: true,
                twoFactorSecret: "secret", // Add if required by your schema
                agents: [{random}]
            });
            await user.save();
        
            const payload = { _id: user._id, random }; // include necessary payload data
        
            accessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
        
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
            const incorrectAccessToken = jwt.sign({ _id: user._id, random: "hello"}, keys, { expiresIn: accessTokenExpiry });

            const response = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${incorrectAccessToken}`);
            
            expect(response.statusCode).toBe(401);
            expect(response.body.errors[0].msg).toBe("Unauthorized access");

        });

        it("should return 401 if no access token is provided", async () => {
            const response = await request(app).get('/api/profile');

            expect(response.statusCode).toBe(401);
            expect(response.body.errors[0].msg).toBe("Unauthorized access");
        });
    });
    describe("POST /api/renewAccessToken", () => {
        const keys = process.env.ACCESS_TOKEN_SECRET;
        const keys2 = process.env.REFRESH_TOKEN_SECRET;
        const accessTokenExpiry = process.env.JWT_ACCESS_TOKEN_EXPIRY; 
        let accessToken;
        let refreshToken;
        let user;
        const random = "some_random_value";

        beforeEach(async () => {
            user = new User({
                name: "Token User",
                email: "tokenuser@example.com",
                password: "Password123",
                isTwoFactorVerified: true,
                twoFactorSecret: "secret", 
                agents: [{random}]
            });
            await user.save();
        
            const payload = { _id: user._id, random }; 
        
            accessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
            refreshToken = jwt.sign(payload, keys2 );
        });
        it("should renew access and refresh token with a valid refresh token", async () => {   
            const response = await request(app)
                .post('/api/renewAccessToken')
                .send({ refreshToken });
    
            expect(response.statusCode).toBe(200);
            expect(response.body).toHaveProperty('accessToken');
            expect(response.body).toHaveProperty('refreshToken');

            // now old access token is invalid, user can't aceess profile
            oldAccessTokenProfileResponse = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${accessToken}`);

                expect(oldAccessTokenProfileResponse.statusCode).toBe(401);
                expect(oldAccessTokenProfileResponse.body.errors[0].msg).toBe("Unauthorized access");

            // check if new access token works correctly, should get access to the user profile
            const newAccessToken = response.body.accessToken;

            profileRouteResponse = await request(app)
                .get('/api/profile')
                .set('Authorization', `Bearer ${newAccessToken}`);

                expect(profileRouteResponse.statusCode).toBe(200); 
                expect(profileRouteResponse.body.data).toHaveProperty('email', 'tokenuser@example.com');
                expect(profileRouteResponse.body.data).toHaveProperty('name', "Token User");
        });
    
        it("should return 400 if no refresh token is provided", async () => {
            const response = await request(app)
                .post('/api/renewAccessToken')
                .send({});
    
            expect(response.statusCode).toBe(400);
            expect(response.body.errors[0].msg).toBe("Refresh token is required");
        });
    
        it("should return 401 for an invalid refresh token", async () => {
            const invalidToken = "someInvalidToken";
    
            const response = await request(app)
                .post('/api/renewAccessToken')
                .send({ refreshToken: invalidToken });
    
            expect(response.statusCode).toBe(401);
            expect(response.body.errors[0].msg).toBe("Invalid or expired refresh token");
        });
    });
    describe("POST /api/logout", () => {
        const keys = process.env.ACCESS_TOKEN_SECRET;
        const keys2 = process.env.REFRESH_TOKEN_SECRET;
        const accessTokenExpiry = process.env.JWT_ACCESS_TOKEN_EXPIRY; 
        let accessToken;
        let user;
        const random = "some_random_value";

        beforeEach(async () => {
            user = new User({
                name: "Token User",
                email: "tokenuser@example.com",
                password: "Password123",
                isTwoFactorVerified: true,
                twoFactorSecret: "secret", 
                agents: [{random}]
            });
            await user.save();
        
            const payload = { _id: user._id, random }; 
        
            accessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
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
                //(in this case, the missing access token).
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
            const keys = process.env.ACCESS_TOKEN_SECRET;
            const accessTokenExpiry = process.env.JWT_ACCESS_TOKEN_EXPIRY; 
            let adminAccessToken;
            let userAccessToken;
            let user;
            let admin;
            const random = "some_random_value";

            beforeEach(async () => {
                // Creating admin
                admin = new User({
                    name: "Admin",
                    email: "admin@example.com",
                    password: "Password123",
                    isTwoFactorVerified: true,
                    twoFactorSecret: "secret", 
                    agents: [{random}],
                    role: "admin"
                });
                await admin.save();
            
                const payloadAdmin = { _id: admin._id, random }; 
            
                adminAccessToken = jwt.sign(payloadAdmin, keys, { expiresIn: accessTokenExpiry });

                // Step 2: Creating user
                user = new User({
                    name: "User",
                    email: "user@example.com",
                    password: "Password123",
                    isTwoFactorVerified: true,
                    twoFactorSecret: "secret", 
                    agents: [{random}]
                });
                await user.save();
            
                const payload = { _id: user._id, random }; 
            
                userAccessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
            });

            it("should terminate the user session successfully and remove the agent", async () => {
                const response = await request(app)
                    .post('/api/admin/logout-user')
                    .send({ userId: user._id })
                    .set('Authorization', `Bearer ${adminAccessToken}`);

                expect(response.statusCode).toBe(200);
                expect(response.body.data.msg).toBe("User session terminated");
                expect(response.body.data).toHaveProperty('email', 'user@example.com');

                // Verify that the agent was removed
                const updatedUser = await User.findById(user._id);
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
                    .send({ userId: user._id });
                    
                    expect(response.statusCode).toBe(401);
                    expect(response.body.errors[0].msg).toBe("Unauthorized access");
            });
            it("should return 401 if an invalid access token is provided", async () => {
                const invalidAdminAccessToken = "someInvalidToken"; 
        
                const response = await request(app)
                    .post('/api/admin/logout-user')
                    .set('Authorization', `Bearer ${invalidAdminAccessToken}`)
                    .send({ userId: user._id });
        
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
            const keys = process.env.ACCESS_TOKEN_SECRET;
            const accessTokenExpiry = process.env.JWT_ACCESS_TOKEN_EXPIRY; // e.g., "10m"
            let userAccessToken;
            let user;
            let adminId;
            const random = "some_random_value";

            beforeEach(async () => {
                user = new User({
                    name: "UserTerminate",
                    email: "userTerminate@example.com",
                    password: "Password123",
                    isTwoFactorVerified: true,
                    twoFactorSecret: "secret", 
                    agents: [{random}]
                });
                await user.save();
            
                const payload = { _id: user._id, random }; 
            
                userAccessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
            });

            it("should return", async () => {
                adminId = "671764557747fde82c663589"
                const response = await request(app)
                    .post('/api/admin/logout-user')
                    .send({ userId: adminId })
                    .set('Authorization', `Bearer ${userAccessToken}`);

                expect(response.statusCode).toBe(403);
                expect(response.body.errors[0].msg).toBe("Access denied. You do not have the required permissions to access this resource.");
            });
         });
    });
        
});

describe("Product and Order Routes with Authentication", () => {
    const keys = process.env.ACCESS_TOKEN_SECRET;
            const accessTokenExpiry = process.env.JWT_ACCESS_TOKEN_EXPIRY; 
            let adminAccessToken;
            let userAccessToken;
            let user;
            let admin;
            const random = "some_random_value";

            beforeEach(async () => {
                // Step 2: Creating admin
                admin = new User({
                    name: "Admin",
                    email: "admin@example.com",
                    password: "Password123",
                    isTwoFactorVerified: true,
                    twoFactorSecret: "secret", 
                    agents: [{random}],
                    role: "admin"
                });
                await admin.save();
            
                const payloadAdmin = { _id: admin._id, random }; 
            
                adminAccessToken = jwt.sign(payloadAdmin, keys, { expiresIn: accessTokenExpiry });

                // Step 2: Creating user
                user = new User({
                    name: "User",
                    email: "user@example.com",
                    password: "Password123",
                    isTwoFactorVerified: true,
                    twoFactorSecret: "secret", 
                    agents: [{random}]
                });
                await user.save();
            
                const payload = { _id: user._id, random }; 
            
                userAccessToken = jwt.sign(payload, keys, { expiresIn: accessTokenExpiry });
            });

        // SEED ROUTE
    describe("POST /api/seed", () => {
        // Test case: Successful seeding by an admin
        it("should allow an admin to seed products", async () => {
            const response = await request(app)
                .post('/api/seed')
                .set('Authorization', `Bearer ${adminAccessToken}`);

            expect(response.statusCode).toBe(201);
            expect(response.body.message).toBe("Products seeded successfully");
            expect(response.body.data).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({ name: "Bananas", price: 1.5 }),
                    expect.objectContaining({ name: "Strawberry", price: 2.5 }),
                    expect.objectContaining({ name: "Apples", price: 1.5 })
                ])
            );
        });

        // Test case: Unauthorized access attempt by a regular user
        it("should prevent a regular user from seeding products", async () => {
            const response = await request(app)
                .post('/api/seed')
                .set('Authorization', `Bearer ${userAccessToken}`);

            expect(response.statusCode).toBe(403);
            expect(response.body.errors[0].msg).toBe("Access denied. You do not have the required permissions to access this resource.");
        });

        // Test case: Partial seeding when some products already exist
        it("should respond with an error if some products already exist in the store", async () => {
            await request(app)
                .post('/api/seed')
                .set('Authorization', `Bearer ${adminAccessToken}`);

            // adding the same products
            const response = await request(app)
                .post('/api/seed')
                .set('Authorization', `Bearer ${adminAccessToken}`);

            expect(response.statusCode).toBe(400);
            expect(response.body.errors[0].msg).toBe("Some products already exist in the store.");
        });
    });

    // ADD PRODUCT TO ORDER ROUTE
    describe("POST /api/addProductToOrder", () => {
        let product;

        beforeEach(async () => {
            product = new Product({ name: "Apples", price: 30 });
            await product.save();
        });

        it("should allow a user to add a product to their order", async () => {
            const response = await request(app)
                .post('/api/addProductToOrder')
                .send({ name: "Apples" })
                .set('Authorization', `Bearer ${userAccessToken}`);

            expect(response.statusCode).toBe(201);
            expect(response.body.message).toBe("Product added to order successfully");
            expect(response.body.order.products[0]).toHaveProperty("name", "Apples");
        });

        it("should prevent access without authentication", async () => {
            const response = await request(app)
                .post('/api/addProductToOrder')
                .send({ name: "Apples" });

            expect(response.statusCode).toBe(401);
            expect(response.body.errors[0].msg).toBe("Unauthorized access");
        });
        it("should respond this message that the name of the product is required, if user didn't put it", async () => {
            const response = await request(app)
                .post('/api/addProductToOrder')
                .set('Authorization', `Bearer ${userAccessToken}`);

            expect(response.statusCode).toBe(400);
            expect(response.body.errors[0].msg).toBe("Product name is required");
        });
        it("should respond this message that the product is not in the store, if there is no one", async () => {
            const response = await request(app)
                .post('/api/addProductToOrder')
                .send({ name: "Bread" })
                .set('Authorization', `Bearer ${userAccessToken}`);

            expect(response.statusCode).toBe(404);
            expect(response.body.errors[0].msg).toBe("Product not found");
        });
    });

    // CHECK MY ORDER ROUTE
    describe("GET /api/checkMyOrder", () => {
        it("should allow a user to check their order", async () => {
            await request(app)
                .post('/api/addProductToOrder')
                .send({ name: "Apples" })
                .set('Authorization', `Bearer ${userAccessToken}`);

            const response = await request(app)
                .get('/api/checkMyOrder')
                .set('Authorization', `Bearer ${userAccessToken}`);

            expect(response.statusCode).toBe(200);
            expect(response.body.message).toBe("My order:");
            expect(Array.isArray(response.body.data.order)).toBe(true);

            const order = response.body.data.order[0];
            expect(order.products.length).toBeGreaterThan(0);

            const applesProduct = order.products.find(product => product.name === "Apples");
            expect(applesProduct).toBeDefined(); 
            expect(applesProduct).toHaveProperty("name", "Apples");
            expect(applesProduct).toHaveProperty("price", 1.5); 
        });

        it("should prevent access without authentication", async () => {
            const response = await request(app).get('/api/checkMyOrder');

            expect(response.statusCode).toBe(401);
            expect(response.body.errors[0].msg).toBe("Unauthorized access");
        });
    });

    // FETCH USER BY ADMIN ROUTE
    describe("GET /api/admin/fetchUser", () => {
        it("should allow an admin to fetch a user's details and orders", async () => {
            const response = await request(app)
                .get('/api/admin/fetchUser')
                .send({ userId: user._id })
                .set('Authorization', `Bearer ${adminAccessToken}`);

            expect(response.statusCode).toBe(200);
            expect(response.body.data).toHaveProperty("name", user.name);
            expect(response.body.data).toHaveProperty("email", user.email);
        });

        it("should prevent a regular user from accessing admin endpoint", async () => {
            const response = await request(app)
                .get('/api/admin/fetchUser')
                .send({ userId: user._id })
                .set('Authorization', `Bearer ${userAccessToken}`);

            expect(response.statusCode).toBe(403);
            expect(response.body.errors[0].msg).toBe("Access denied. You do not have the required permissions to access this resource.");
        });
        it("should respond with a message that user Id is not valid", async () => {
            const userId = "558"
            const response = await request(app)
                .get('/api/admin/fetchUser')
                .send({ userId: userId })
                .set('Authorization', `Bearer ${adminAccessToken}`);

            expect(response.statusCode).toBe(400);
            expect(response.body.errors[0].msg).toBe("Invalid user ID format");
        });
        it("should respond with a message - user not found", async () => {
            const userId = "67285c95cb334ac35d7cd968"
            const response = await request(app)
                .get('/api/admin/fetchUser')
                .send({ userId: userId })
                .set('Authorization', `Bearer ${adminAccessToken}`);

            expect(response.statusCode).toBe(404);
            expect(response.body.errors[0].msg).toBe('User not found');
        });
    });
});

describe("POST /api/generate-invoice", () => {
    let accessToken, userId, random;
    const mockOrder = {
        _id: 'order-id',
        userId: { _id: '672fb02d3dfcaeb9b979acee', name: 'John Doe', email: 'john.doe@example.com' },
        products: [{ name: 'Product A', price: 100 }],

    };

    beforeAll(() => {
        // Generate a random value to be used in the agents field
        random = 'randomValue';
        userId = '672fb02d3dfcaeb9b979acee';
        
        // Create a JWT with the random field in the payload
        accessToken = jwt.sign({ _id: userId, random }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1h" });
        
        // Mock the User model (assuming it's the User model that handles agents and tempAgents)
        const mockUser = {
            _id: userId,
            agents: [{ random: 'randomValue' }],  // Mock the user having an agent with a matching random
            tempAgents: [{ random: 'tempRandomValue' }]  // You can adjust this if necessary
        };

        
        // Mock User.findById to return the mock user
        User.findById = jest.fn().mockResolvedValue(mockUser);
    });

    beforeEach(() => {
        // Clear all mocks before each test
        jest.clearAllMocks();
    });

    it("should generate an invoice successfully", async () => {
        Order.findOne = jest.fn().mockReturnValue({
            populate: jest.fn().mockReturnValue({
              populate: jest.fn().mockResolvedValueOnce(mockOrder),
            }),
        });
          
        buildPDF.mockResolvedValueOnce('/path/to/invoice.pdf');
        sendInvoiceEmail.mockResolvedValueOnce(true);

        const response = await request(app)
            .post('/api/generate-invoice')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({ orderId: 'order-id' });

        expect(Order.findOne).toHaveBeenCalledWith({ _id: 'order-id', userId: userId });

        expect(response.statusCode).toBe(200);
        expect(response.body.message).toBe('Invoice generated and sent successfully');
        expect(response.body).toHaveProperty('fileUrl');
    });

    it("should return 404 if order is not found", async () => {
        Order.findOne = jest.fn().mockReturnValue({
            populate: jest.fn().mockReturnValue({
              populate: jest.fn().mockResolvedValueOnce(null),
            }),
        });
        const response = await request(app)
            .post('/api/generate-invoice')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({ orderId: 'non-existent-order-id' });

        expect(response.statusCode).toBe(404);
        expect(response.body.errors[0].msg).toBe("Order not found or access denied");
    });

    it("should return 400 if orderId is missing", async () => {
        const response = await request(app)
            .post('/api/generate-invoice')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({});

        expect(response.statusCode).toBe(400);
        expect(response.body.errors[0].msg).toBe("Order ID is required");
    });

    it("should return 500 if there's an error generating the invoice", async () => {
        
        Order.findOne = jest.fn().mockReturnValue({
            populate: jest.fn().mockReturnValue({
                populate: jest.fn().mockResolvedValueOnce(mockOrder),
            }),
        });

        buildPDF.mockRejectedValueOnce(new Error("Error writing PDF file"));
        
        const response = await request(app)
            .post('/api/generate-invoice')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({ orderId: 'order-id' });
        
        expect(Order.findOne).toHaveBeenCalledWith({ _id: 'order-id', userId: userId });  // Check if the method is called with the correct arguments
        expect(buildPDF).toHaveBeenCalled();

        expect(response.statusCode).toBe(500);
        expect(response.body.errors[0].message).toBe("Error generating PDF");
        expect(response.body.errors[0].details).toBe("Error writing PDF file");
    });


    it("should generate a PDF in a temporary directory", async () => {
        
        
        // Setup the absolute path for file system checks
        const tempDir = path.join(__dirname, '..', 'temp');
        const pdfFileName = 'invoice-672fb86119bba8fc4780c8ec.pdf';
        const absolutePDFPath = path.join(tempDir, pdfFileName);
    
        // Configure the mock filesystem for this test only
        mock({
            [tempDir]: {
                // Simulate the creation of a PDF file in the mock directory
                [pdfFileName]: '', // Mock file creation
            }
        });
    
        try {
            // Mock Order.findOne and buildPDF function as usual
            Order.findOne = jest.fn().mockReturnValue({
                populate: jest.fn().mockReturnValue({
                    populate: jest.fn().mockResolvedValueOnce(mockOrder),
                }),
            });
            buildPDF.mockResolvedValueOnce(absolutePDFPath);
    
            // Perform the API call to generate the invoice
            const response = await request(app)
                .post('/api/generate-invoice')
                .set('Authorization', `Bearer ${accessToken}`)
                .send({ orderId: 'order-id' });
    
            // Validate the response
            expect(response.statusCode).toBe(200);
            expect(response.body.message).toBe('Invoice generated and sent successfully');
            expect(response.body.fileUrl).toBe(`/api/invoices/${pdfFileName}`);
    
            // Check if the file was created in the mock filesystem
            expect(fs.existsSync(absolutePDFPath)).toBe(true);
    
        } finally {
            // Restore the real filesystem after the test
            mock.restore();
        }
    });
});

describe('Invoices Route', () => {
    let accessToken, userId, random;

    beforeEach(() => {
        // Generate a random value to be used in the agents field
        random = 'randomValue';
        userId = '672fb02d3dfcaeb9b979acee';
        
        // Create a JWT with the random field in the payload
        accessToken = jwt.sign({ _id: userId, random }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1h" });

        // Mock the User model (assuming it's the User model that handles agents and tempAgents)
        const mockUser = {
            _id: userId,
            agents: [{ random: 'randomValue' }],  // Mock the user having an agent with a matching random
            tempAgents: [{ random: 'tempRandomValue' }]  // Adjust this if necessary
        };

        // Mock User.findById to return the mock user
        User.findById = jest.fn().mockResolvedValue(mockUser);

        // Mock fs.existsSync to simulate file existence for the test
        const invoicesDir = path.join(__dirname, '..', 'service', 'invoices');
        
        // Simulate that the file exists in the invoices directory
        mock({
            [invoicesDir]: {
                'invoice-672fb86119bba8fc4780c8ec.pdf': '', // Simulate an existing file (empty file)
            },
        });
        jest.spyOn(fs, 'existsSync').mockReturnValue(true);

    });

    afterEach(() => {
        mock.restore(); // Restore the real filesystem after each test
    });

    it('should return the file for viewing if it exists', async () => {
        const filename = 'invoice-672fb86119bba8fc4780c8ec.pdf';

        // Send a GET request to fetch the invoice file
        const response = await request(app)
            .get(`/api/invoices/${filename}`)
            .set('Authorization', `Bearer ${accessToken}`); // Include the JWT token in the Authorization header

        // Assert that the file is returned correctly for viewing
        expect(response.status).toBe(200);  // Expect HTTP 200 (OK) status
        expect(response.headers['content-type']).toBe('application/pdf');  // Expect the content type to be PDF
    });

    it('should return 404 if invoice file does not exist', async () => {
        // Simulate the invoice file not existing
        jest.spyOn(fs, 'existsSync').mockReturnValue(false);

        const filename = 'nonexistent-invoice.pdf';
        const response = await request(app)
            .get(`/api/invoices/${filename}`)
            .set('Authorization', `Bearer ${accessToken}`) // Include the JWT token in the Authorization header

        // Assert that it returns a 404 error if the file doesn't exist
        expect(response.status).toBe(404);
        expect(response.body.errors[0].msg).toBe('Invoice not found');
    });

    it('should return a 500 error if there is a file system error', async () => {
        jest.spyOn(fs, 'existsSync').mockImplementationOnce(() => { throw new Error('File system error'); });

        const filename = 'invoice-672fb86119bba8fc4780c8ec.pdf';
        const response = await request(app)
            .get(`/api/invoices/${filename}`)
            .set('Authorization', `Bearer ${accessToken}`)

        // Assert that a 500 error is returned if there is a file system error
        expect(response.status).toBe(500);
        expect(response.body.errors[0].msg).toBe('Internal server error.');
    });
    it('should prompt download when download=true is set in the query', async () => {
        const filename = 'invoice-672fb86119bba8fc4780c8ec.pdf';
        
        // Send a GET request with the download=true query parameter
        const response = await request(app)
            .get(`/api/invoices/${filename}?download=true`)
            .set('Authorization', `Bearer ${accessToken}`);
    
        // Assert the status and headers for a download response
        expect(response.status).toBe(200);
        expect(response.headers['content-disposition']).toContain('attachment');  // Download should trigger attachment
        expect(response.headers['content-disposition']).toContain(filename);  // Should contain the filename for the download
    });
    
});