require('dotenv').config();
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const msg = {
  to: 'hearthandhealorg@gmail.com',
  from: 'hearthandhealorg@gmail.com',
  subject: 'Test Email',
  text: 'Testing SendGrid API Key',
};

sgMail.send(msg).then(() => {
  console.log('Email sent successfully');
}).catch((error) => {
  console.error('SendGrid Error:', error.response ? error.response.body : error.message);
});
