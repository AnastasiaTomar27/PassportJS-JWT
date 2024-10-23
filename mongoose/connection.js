// const mongoose = require('mongoose');
// mongoose.connect(process.env.MONGODB_URL)
// console.log("Connected to MongoDB")
const mongoose = require('mongoose');
const { MongoMemoryServer }  = require('mongodb-memory-server');

let mongod = null; // For in-memory MongoDB instance
let isConnected = false;


const connectDB = async () => {
    if (isConnected) {
        console.log('Already connected');
        return;
    }

    try {
        if (process.env.NODE_ENV === 'test') {
            console.log('Connecting to in-memory MongoDB');
            // Use in-memory MongoDB for testing
            mongod = await MongoMemoryServer.create();
            const uri = mongod.getUri();
            await mongoose.connect(uri);
            console.log('Connected to in-memory MongoDB');
        } else {
            // Use production MongoDB connection string
            console.log('Connecting to production MongoDB');
            const uri = process.env.MONGODB_URL;
            await mongoose.connect(uri);
            console.log('Connected to production MongoDB');
        }
        isConnected = true;
    } catch (err) {
        console.log('Error connecting to MongoDB:', err);
    }
};

const disconnectDB = async () => {
    if (!isConnected) {
        console.log('Not connected');
        return;
    }

    try {
        await mongoose.disconnect();
        if (mongod) {
            await mongod.stop(); // Stop in-memory MongoDB
        }
        isConnected = false;
        console.log('Disconnected from MongoDB');
    } catch (err) {
        console.error('Error disconnecting from MongoDB:', err);
    }
};


module.exports = { connectDB, disconnectDB };
