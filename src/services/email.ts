import nodemailer from 'nodemailer';
import { IMailOptions } from '../types/email';
import dotenv from 'dotenv';
dotenv.config();

const emailUser = process.env.EMAIL_USER;
const emailPass = process.env.EMAIL_PASS;

if (!emailUser || !emailPass) {
  console.error('❌ EMAIL_USER or EMAIL_PASS not set in environment variables');
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: emailUser,
    pass: emailPass,
  },
});

// Verify connection on startup
transporter.verify((error) => {
  if (error) {
    console.error('❌ Email transporter verification failed:', error.message);
  } else {
    console.log('✅ Email transporter ready');
  }
});

export const sendEmail = (mailOptions: IMailOptions): Promise<boolean> => {
  return new Promise(resolve => {
    if (!emailUser || !emailPass) {
      console.error('❌ Cannot send email: Credentials missing');
      resolve(false);
      return;
    }

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('❌ Email send failed:', error.message);
        console.error('Error details:', JSON.stringify(error, null, 2));
        resolve(false);
      } else if (info && info.accepted && info.accepted.length > 0) {
        console.log('✅ Email sent to:', mailOptions.to);
        resolve(true);
      } else {
        console.error('❌ Email send failed: No accepted recipients');
        resolve(false);
      }
    });
  });
};
