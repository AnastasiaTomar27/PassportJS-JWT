const nodemailer = require('nodemailer');
const fs = require('fs').promises;

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail', // Use Gmail's SMTP service
    auth: {
        user: 'test404@gmail.com', // Gmail email address
        pass: "ytlu xdrh wqxb ccie" // I turned on 2FA and set App passwords, here should be that password
    }
});

async function sendInvoiceEmail(order, recipientEmail, filePath) {
    try {
        // Asynchronously check if the file exists
        await fs.access(filePath);  // This will throw an error if the file doesn't exist

        const mailOptions = {
            from: 'test404app@gmail.com',
            to: recipientEmail,
            subject: 'Your Invoice',
            text: `Dear ${order.userId.name},\n\nPlease find attached your invoice.\n\nBest regards,\nYour Dream Company`,
            attachments: [
                {
                    filename: `invoice-${order._id.toString()}.pdf`,
                    path: filePath
                }
            ]
        };
        // Test SMTP connection (Simple Mail Transfer Protocol -  it’s the standard protocol used to send emails across the internet.)
        // checks if Nodemailer can connect to the SMTP server (like Gmail’s SMTP server) with the provided credentials and settings
        try {
            await transporter.verify();
            console.log('SMTP server is ready to send emails');
        } catch (verifyError) {
            console.error('SMTP connection error:', verifyError);
            throw new Error("SMTP connection error");
        }

        await transporter.sendMail(mailOptions);
        console.log('Invoice email sent successfully to:', recipientEmail);
    
    } catch (error) {
        console.error('Error in sendInvoiceEmail:', error);
        throw error;
    }
}

module.exports = { sendInvoiceEmail };



