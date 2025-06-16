export const getOtpView = (token: string) =>
  `<html>
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
              <h2>Your Password Reset Code</h2>
            </div>
            <div class="content">
              <p>Please use the code below to reset your password. This code is valid for the next 10 minutes.</p>
              <p class="code">${token}</p>
              <p>If you did not request a password reset, you can safely ignore this email. No changes will be made to your account.</p>
              <p class="note">'Once you have entered the code, you will be prompted to set a new password for your account. Make sure to choose a strong, memorable password</p>
            </div>
            <div class="footer">
              <p>&copy; ${new Date().getFullYear()} Data3D</p>
            </div>
          </div>
        </body>
      </html>`;
