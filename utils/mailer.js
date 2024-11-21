const nodeMailer = require('nodemailer');

const transporter = nodeMailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
    },
});

const sendMail = (to, subject, html) => {
    return transporter.sendMail({
        from: process.env.EMAIL, to, subject, html
    });
}

module.exports = sendMail;
