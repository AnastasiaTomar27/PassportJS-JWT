const { mongoose } = require("mongoose");

const ProductSchema = new mongoose.Schema({
	name: { 
        type: mongoose.Schema.Types.String, 
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    price: {
        type: mongoose.Schema.Types.Number,
        required: true
    }
});

const Product = mongoose.model("Product", ProductSchema);

module.exports = Product;