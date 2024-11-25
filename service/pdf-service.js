const puppeteer = require('puppeteer');
// const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const invoicesDir = path.join(__dirname, 'invoices'); // Directory for storing PDFs

// Generate PDF from HTML content
async function buildPDFfromHTML(order) {
    const filePath = path.join(invoicesDir, `invoice-${crypto.randomUUID()}.pdf`);

    // HTML content for the invoice
    const htmlContent = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Invoice</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { text-align: center; margin-bottom: 20px; }
                .customer-info, .order-details { margin-bottom: 20px; }
                .order-details table { width: 100%; border-collapse: collapse; }
                .order-details th, .order-details td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                .totals { margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Invoice</h1>
            </div>
            <div class="customer-info">
                <p><strong>Customer Name:</strong> ${order.userId.name}</p>
                <p><strong>Customer Email:</strong> ${order.userId.email}</p>
                <p><strong>Date:</strong> ${new Date().toLocaleDateString()}</p>
            </div>
            <div class="order-details">
                <h2>Order Details</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Product</th>
                            <th>Price</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${order.products.map(product => `
                            <tr>
                                <td>${product.name}</td>
                                <td>$${product.price.toFixed(2)}</td>
                            </tr>`).join('')}
                    </tbody>
                </table>
            </div>
            <div class="totals">
                <p><strong>Total Price (Excl. VAT):</strong> $${order.products.reduce((sum, p) => sum + p.price, 0).toFixed(2)}</p>
                <p><strong>VAT (20%):</strong> $${(order.products.reduce((sum, p) => sum + p.price, 0) * 0.2).toFixed(2)}</p>
                <p><strong>Grand Total:</strong> $${(order.products.reduce((sum, p) => sum + p.price, 0) * 1.2).toFixed(2)}</p>
            </div>
        </body>
        </html>
    `;

    try {
        const browser = await puppeteer.launch(); // Launch a headless browser
        const page = await browser.newPage(); // Open a new page
        await page.setContent(htmlContent); // Set the HTML content
        await page.pdf({
            path: filePath, // Save the PDF to this path
            format: 'A4', // Standard paper size
            printBackground: true, // Include CSS background colors
        });
        await browser.close(); // Close the browser
        return filePath;
    } catch (error) {
        throw new Error(`Error generating PDF: ${error.message}`);
    }
}

module.exports = { buildPDFfromHTML };
