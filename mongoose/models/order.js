const { mongoose } = require("mongoose");

const OrderSchema = new mongoose.Schema({
    createdAt: {
        type: Date,
        default: Date.now
    },
	products: [{ 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Product' // Product should match this: const Product = mongoose.model("Product", ProductSchema);
    }]
});

const Order = mongoose.model("Order", OrderSchema);

module.exports = Order;