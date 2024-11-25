const nodemailer = require('nodemailer');
const fs = require('fs').promises; // Used to work with the file system (like checking if an invoice file exists) but with promises instead of callbacks.
const admin_email = process.env.ADMIN_EMAIL;
const admin_email_password = process.env.ADMIN_EMAIL_PASSWORD;

// Configure Nodemailer
const transporter = nodemailer.createTransport({ // Sets up the connection to the Gmail service with the provided credentials.
    service: 'gmail', // Use Gmail's SMTP service
    auth: {
        user: admin_email, // Gmail admin email address
        pass: admin_email_password // I turned on 2FA and set App passwords, here should be that password
    }
});

// Wrapper for admin notifications
async function sendEmailToAdmin({ subject, text }) {
    const mailOptions = {
        from: admin_email, // sender address (must be the same as the 'user' in the transporter)
        to: admin_email, // recipient address (your Gmail address in this case)
        subject: subject, // subject line
        text: text // plain text body
    };

    try {
        // Send email
        const info = await transporter.sendMail(mailOptions); // sendMail function is where the email is actually sent.
        console.log('Email sent: ' + info.response);
    } catch (error) {
        //console.error('Error sending email: ', error);
        throw error
    }
}

async function sendInvoiceEmail(order, recipientEmail, filePath) {
    try {
        // Asynchronously check if the file exists
        await fs.access(filePath);  // This will throw an error if the file doesn't exist

        const mailOptions = {
            from: admin_email,
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
            //console.log('SMTP server is ready to send emails');
        } catch (verifyError) {
            //console.error('SMTP connection error:', verifyError);
            throw new Error("SMTP connection error");
        }

        await transporter.sendMail(mailOptions);
        console.log('Invoice email sent successfully to:', recipientEmail);
    
    } catch (error) {
        //console.error('Error in sendInvoiceEmail:', error);
        throw error;
    }
}

module.exports = { sendEmailToAdmin, sendInvoiceEmail };



