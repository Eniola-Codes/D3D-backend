"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetPasswordView = void 0;
const resetPasswordView = (email) => `<html>
           <head>
             <style>
               body {
                 font-family: 'Arial', sans-serif;
                 background-color: #ffffff;
                 color: #333;
                 padding: 20px;
                 margin: 0;
               }
               .container {
                 max-width: 600px;
                 margin: 0 auto;
                 background-color: #ffffff;
                 padding: 20px;
                 border-radius: 10px;
                 box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
                 border: 1px solid #e0e0e0;
               }
               .header {
                 text-align: center;
                 padding: 20px 0;
                 border-bottom: 2px solid #f0f0f0;
                 margin-bottom: 20px;
               }
               .content {
                 margin: 20px 0;
                 line-height: 1.6;
                 font-size: 13px;
               }
               .code {
                 font-size: 28px;
                 font-weight: bold;
                 color: #000;
                 padding: 15px;
                 border: 1px solid #d1d1d1;
                 background-color: #f9f9f9;
                 border-radius: 5px;
                 display: inline-block;
                 letter-spacing: 1px;
               }
               .footer {
                 text-align: center;
                 font-size: 13px;
                 color: #aaa;
                 margin-top: 20px;
                 border-top: 1px solid #f0f0f0;
                 padding-top: 10px;
               }
               .note {
                 font-size: 13px;
                 color: #666;
                 margin-top: 10px;
               }
             </style>
           </head>
           <body>
             <div class="container">
               <div class="header">
                 <h2>Password Reset Successful</h2>
               </div>
               <div class="content">
                 <p>Hello friend!</p>
                 <p>You have successfully reset the password of your account associated with the email ${email}.</p>
                 <p>If you did not reset your password, contact us at <a href="mailto:d3d.data@gmail.com">d3d.data@gmail.com</a> to issue a security complain.</p>
                 <p class="note">Now that you have changed your password, you can access your account with your newly set password.</p>
               </div>
               <div class="footer">
                 <p>&copy; ${new Date().getFullYear()} Data3D</p>
               </div>
             </div>
           </body>
         </html>`;
exports.resetPasswordView = resetPasswordView;
