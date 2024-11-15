const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const invoicesDir = path.join(__dirname, 'invoices'); // __dirname means the path to service folder

function buildPDF(order) {

    // Promise gives the function an asynchronous structure
    return new Promise((resolve, reject) => {

        const filePath = path.join(invoicesDir, `invoice-${order._id}.pdf`);

        const doc = new PDFDocument();
        // creates a writable stream, that will be saved in filePath
        const stream = fs.createWriteStream(filePath);
        //  By piping doc into stream, everything you write to doc (like text, lines, images, etc.) is sent directly to stream, which writes the content to the file on disk.
        doc.pipe(stream);

        // Invoice Header
        doc.fontSize(18).text('Invoice', { align: 'center' });
        doc.moveDown();

        // Customer Information
        doc.fontSize(12)
            .text(`Customer Name: ${order.userId.name}`)
            .text(`Customer Email: ${order.userId.email}`)
            .moveDown();

        // Order Details
        doc.text(`Date: ${new Date().toLocaleDateString()}`);
        doc.text('Items:');
        
        let total = 0;
        order.products.forEach(product => {
            doc.text(`- ${product.name}: $${product.price}`);
            total += product.price;
        });
        
        const vat = total * 0.2;
        const grandTotal = total + vat;

        doc.moveDown();
        doc.text(`Total Price (Excl. VAT): $${total.toFixed(2)}`);
        doc.text(`VAT (20%): $${vat.toFixed(2)}`);
        doc.text(`Grand Total: $${grandTotal.toFixed(2)}`);
        
        doc.end(); // doc stops sending data

        // listens for the finish event on the stream
        stream.on('finish', () => {
            resolve(filePath);
        });        
        stream.on('error', (error) => {
            reject({ errors: [{ msg: "Error writing PDF file" }] });
        });    }); 
}

module.exports = {buildPDF};