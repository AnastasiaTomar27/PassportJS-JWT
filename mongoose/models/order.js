const { mongoose } = require("mongoose");

const OrderSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
	products: [{ 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Product' // Product should match this: const Product = mongoose.model("Product", ProductSchema);
    }],
    createdAt: {
        type: Date,
        default: Date.now
    }
   
});

const Order = mongoose.model("Order", OrderSchema);

module.exports = Order;