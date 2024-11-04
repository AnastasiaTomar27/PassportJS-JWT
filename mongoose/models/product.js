const { mongoose } = require("mongoose");

const ProductSchema = new mongoose.Schema({
	name: { 
        type: mongoose.Schema.Types.String, 
        required: true
    },
    price: {
        type: mongoose.Schema.Types.Number,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const Product = mongoose.model("Product", ProductSchema);

module.exports = Product;