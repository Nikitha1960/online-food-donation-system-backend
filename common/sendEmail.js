const nodemailer = require("nodemailer");
const hbs = require("nodemailer-express-handlebars");

const username = "foodforallplatform@gmail.com"
const senderEmail = "foodforallplatform@gmail.com"
const password = "loqwplnxvfonmfyi"

var transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "foodforallplatform@gmail.com",
    pass: "loqwplnxvfonmfyi",
  },
});
var transporter2 = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "foodforallplatform@gmail.com",
    pass: "loqwplnxvfonmfyi",
  },
});

var transporter3 = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "foodforallplatform@gmail.com",
    pass: "loqwplnxvfonmfyi",
  },
});

var transporter4 = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "foodforallplatform@gmail.com",
    pass: "loqwplnxvfonmfyi",
  },
});

transporter.use(
  "compile",
  hbs({
    viewEngine: "express-handlebars",
    viewPath: "./common/views/",
  })
);
transporter2.use(
  "compile",
  hbs({
    viewEngine: "express-handlebars",
    viewPath: "./common/views/accepted",
  })
);
transporter3.use(
  "compile",
  hbs({
    viewEngine: "express-handlebars",
    viewPath: "./common/views/rejected",
  })
);
transporter4.use(
  "compile",
  hbs({
    viewEngine: "express-handlebars",
    viewPath: "./common/views/deleted",
  })
);
function sendEmail(email, text) {
  var mailOptions = {
    from: "foodforallplatform@gmail.com",
    to: email,
    subject: "Food for all ",
    text: `${text}`,
    template: "index",
    context: {
      name: text,
    },
  };
  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
}
function sendAcceptedEmail(email, text) {
  var mailOptions = {
    from: "foodforallplatform@gmail.com",
    to: email,
    subject: "Your request has been accepted",
    text: `${text}`,
    template: "index",
    context: {
      name: text,
    },
  };
  transporter2.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
}

function sendRejectedEmail(email, text) {
  var mailOptions = {
    from: "foodforallplatform@gmail.com",
    to: email,
    subject: "Your request has been rejected",
    text: `${text}`,
    template: "index",
    context: {
      name: text,
    },
  };
  transporter3.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
}

function sendDonationDeletedEmail(email, text) {
  var mailOptions = {
    from: "foodforallplatform@gmail.com",
    to: email,
    subject: "The donation you have sent a request has been deleted",
    text: `${text}`,
    template: "index",
    context: {
      name: text,
    },
  };
  transporter4.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
}


// For organization emails
var transporterOrganizationEmails = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: username,
    pass: password,
  },
});

transporterOrganizationEmails.use(
  "compile",
  hbs({
    viewEngine: "express-handlebars",
    viewPath: "./common/views/organizationEmails",
  })
)

function sendOrganizationEmail(email, emailSubject, text) {
  var mailOptions = {
    from: senderEmail,
    to: email,
    subject: emailSubject,
    text: `${text}`,
    template: "index",
    context: {
      emailText: text,
    },
  };
  transporterOrganizationEmails.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
}

module.exports = {
  sendEmail,
  sendAcceptedEmail,
  sendRejectedEmail,
  sendDonationDeletedEmail,
  sendOrganizationEmail,
};
