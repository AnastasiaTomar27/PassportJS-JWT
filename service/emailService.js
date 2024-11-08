const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail', // Use Gmail's SMTP service
    auth: {
        user: 'test404app@gmail.com', // Gmail email address
        //pass: 'EtoNoviyPassword111!!!' // Replace with App Password if you have 2FA enabled
        pass: "ytlu xdrh wqxb ccie" // I turned on 2FA and set App passwords, here shoul that password
    }
});

async function sendInvoiceEmail(order, recipientEmail, filePath) {
    try {
        console.log("Attempting to send email with filePath:", filePath);

        if (!fs.existsSync(filePath)) {
            throw new Error("Invoice file not found");
        }

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

        // Test SMTP connection
        transporter.verify((error, success) => {
            if (error) {
                console.log('Error:', error); 
            } else {
                console.log('SMTP server is ready to send emails'); 
            }
        });

        await transporter.sendMail(mailOptions);
        console.log('Invoice email sent successfully to:', recipientEmail);
    } catch (error) {
        console.error('Error sending invoice email:', error);
    }
}

module.exports = { sendInvoiceEmail };



