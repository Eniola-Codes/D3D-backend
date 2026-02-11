import { Resend } from 'resend';
import { IMailOptions } from '../types/email';
import dotenv from 'dotenv';
dotenv.config();

export const sendEmail = async (mailOptions: IMailOptions): Promise<boolean> => {
  try {
    const resend = new Resend(process.env.RESEND_API_KEY);
    const { data, error } = await resend.emails.send({
      from: mailOptions.from,
      to: mailOptions.to,
      subject: mailOptions.subject,
      html: mailOptions.html,
    });
    if (error) {
      console.log(error);
      return false;
    }
    console.log(data);
    return true;
  } catch (error) {
    console.log(error);
    return false;
  }
};
