const AWS = require("aws-sdk");
const crypto = require("crypto");

var cognito = new AWS.CognitoIdentityServiceProvider({apiVersion: '2016-04-18'});

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const USER_POOL_ID = process.env.USER_POOL_ID;

const hashSecret = (clientSecret, username, clientId) =>
  crypto.createHmac('SHA256', clientSecret)
    .update(username + clientId)
    .digest('base64');

const changePassword = async (accessToken, oldPassword, newPassword) => {
  return new Promise((resolve,reject) => {
    var params = {
      AccessToken: accessToken,
      PreviousPassword: oldPassword,
      ProposedPassword: newPassword
    };
    cognito.changePassword(params, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });
};

const forgotPassword = async username => {
  return new Promise((resolve,reject) => {
    var params = {
      ClientId: CLIENT_ID,
      Username: username,
      SecretHash: hashSecret(CLIENT_SECRET, username, CLIENT_ID),
    };
    cognito.forgotPassword(params, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });
};

const getUser = async username => {
  return new Promise((resolve, reject) => {
    var params = {
      UserPoolId: USER_POOL_ID,
      Username: username
    };
    cognito.adminGetUser(params, (err, user) => {
      if (err) return reject(err);
      resolve(user);
    });
  });
};

const login = async (username, password) => {
  return new Promise((resolve,reject) => {
    var params = {
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: CLIENT_ID,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
        SECRET_HASH: hashSecret(CLIENT_SECRET, username, CLIENT_ID),
      },
    };
    cognito.initiateAuth(params, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });
};

const refreshToken = async (username, password) => {
  return new Promise((resolve,reject) => {
    var params = {
      AuthFlow: "REFRESH_TOKEN_AUTH",
      ClientId: CLIENT_ID,
      AuthParameters: {
        REFRESH_TOKEN: token,
        SECRET_HASH: hashSecret(CLIENT_SECRET, username, CLIENT_ID),
      },
      ClientMetadata: {},
    };
    cognito.initiateAuth(params, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });
};

const resendCode = async username => {
  return new Promise((resolve, reject) => {
    var params = {
      ClientId: CLIENT_ID,
      Username: username,
      SecretHash: hashSecret(CLIENT_SECRET, username, CLIENT_ID),
    };
    cognito.resendConfirmationCode(params, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });
};

const resetPassword = async (username, newPassword, code) => {
  return new Promise((resolve,reject) => {
    var params = {
      ClientId: CLIENT_ID,
      ConfirmationCode: code,
      Password: newPassword,
      Username: username,
      SecretHash: hashSecret(CLIENT_SECRET, username, CLIENT_ID),
    };
    cognito.confirmForgotPassword(params, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });
};

const userSignUp = async (username, email, password) => {
  return new Promise((resolve, reject) => {
    var params = {
      ClientId: CLIENT_ID,
      Password: password,
      Username: email,
      SecretHash: hashSecret(CLIENT_SECRET, email, CLIENT_ID),
      UserAttributes: [
        {
          Name: "preferred_username",
          Value: username
        }
      ],
      ValidationData: [
        {
          Name: "email",
          Value: email
        }
      ]
    };
    cognito.signUp(params, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });
};


module.exports = {
  changePassword,
  getUser,
  forgotPassword,
  login,
  refreshToken,
  resendCode,
  resetPassword,
  userSignUp,
};
