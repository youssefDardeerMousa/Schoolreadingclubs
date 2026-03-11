import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();
const sendEmail = async (to, subject, html) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PASS,
    },
  });

  await transporter.sendMail({
    from: process.env.EMAIL,
    to,
    subject,
    html,
  });
};

export default sendEmail;
