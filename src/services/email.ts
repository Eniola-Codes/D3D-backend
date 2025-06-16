import nodemailer from 'nodemailer';
import { IMailOptions } from '../types/email';
import dotenv from 'dotenv';
dotenv.config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export const sendEmail = (mailOptions: IMailOptions): Promise<boolean> => {
  return new Promise(resolve => {
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        resolve(false);
      } else if (info.accepted.length > 0) {
        resolve(true);
      } else {
        resolve(false);
      }
    });
  });
};
