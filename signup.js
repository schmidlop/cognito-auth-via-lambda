const AWS = require("aws-sdk");
const crypto = require("crypto");

var cognito = new AWS.CognitoIdentityServiceProvider({apiVersion: '2016-04-18'});

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const USER_POOL_ID = process.env.USER_POOL_ID;

const errorResponse = (error, awsRequestId, callback) => {
  console.error(error.message);
  console.error(error.stack);
  callback(null, {
      statusCode: error.status || 500,
      body: JSON.stringify({
          Error: error.message || "Unknown Exception",
          Reference: awsRequestId,
      }),
      headers: {
          'Access-Control-Allow-Origin': '*',
      },
  });
};

const successResponse = (response, callback) => {
  callback(null, {
    statusCode: response.status || 200,
    body: JSON.stringify(response),
    headers: {
      "Access-Control-Allow-Origin": "*",
    },
  });
};

const responses = {
  BAD_REQUEST: msg => ({status: 400, message: `Bad Request.${msg ? " " + msg : ""}`}),
  NOT_FOUND: msg => ({status: 404, message: `Not Found.${msg ? " " + msg : ""}`})
};

const hashSecret = (clientSecret, username, clientId) => crypto.createHmac('SHA256', clientSecret)
  .update(username + clientId)
  .digest('base64')


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

exports.handler = async (event, context, callback) => {
  const { awsRequestId } = context;
  const {username, password, email} = event.queryStringParameters;
  try {

    if (!username) throw responses.BAD_REQUEST("Missing required parameter: username");
    if (!password) throw responses.BAD_REQUEST("Missing required parameter: password");
    if (!email) throw responses.BAD_REQUEST("Missing required parameter: email");

    const user = await userSignUp(username, email, password);
    successResponse(user, callback);
  } catch (ex) {
    if (ex.message === "An account with the given email already exists.") {
      try {
        console.error(JSON.stringify(ex));
        const user = await getUser(email);
        successResponse(user, callback);
      } catch (err) {
        errorResponse(err, awsRequestId, callback);
      }
    } else {
      errorResponse(ex, awsRequestId, callback);
    }
  }
};


// const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
// const crypto = require("crypto");

// const fetchIntercept = require("./fetch-intercept");

// const COGNITO_SECRET_HASH_API = [
//   'AWSCognitoIdentityProviderService.ConfirmForgotPassword',
//   'AWSCognitoIdentityProviderService.ConfirmSignUp',
//   'AWSCognitoIdentityProviderService.ForgotPassword',
//   'AWSCognitoIdentityProviderService.ResendConfirmationCode',
//   'AWSCognitoIdentityProviderService.SignUp',
// ]

// const CLIENT_ID = process.env.CLIENT_ID;
// const CLIENT_SECRET = process.env.CLIENT_SECRET;
// const USER_POOL_ID = process.env.USER_POOL_ID;


// fetchIntercept.register({
//   request(url, config) {
//     const { headers } = config
//     if (headers && COGNITO_SECRET_HASH_API.includes(headers['X-Amz-Target'])) {
//       const body = JSON.parse(config.body)
//       const { ClientId: clientId, Username: username } = body
//       // eslint-disable-next-line no-param-reassign
//       config.body = JSON.stringify({
//         ...body,
//         SecretHash: hashSecret(CLIENT_SECRET, username, clientId),
//       })
//     }
//     return [url, config]
//   },
// })

// const errorResponse = (error, awsRequestId, callback) => {
//   console.error(error.message);
//   console.error(error.stack);
//   callback(null, {
//       statusCode: error.status || 500,
//       body: JSON.stringify({
//           Error: error.message || "Unknown Exception",
//           Reference: awsRequestId,
//       }),
//       headers: {
//           'Access-Control-Allow-Origin': '*',
//       },
//   });
// };

// const successResponse = (response, callback) => {
//   callback(null, {
//     statusCode: response.status || 200,
//     body: JSON.stringify(response.data),
//     headers: {
//       "Access-Control-Allow-Origin": "*",
//     },
//   });
// };

// const addAttribute = (attributeList, name, value) => {
//   const attributeToAdd = new AmazonCognitoIdentity.CognitoUserAttribute({
//     Name: name,
//     Value: value
//   });
//   attributeList.push(attributeToAdd);
//   return attributeList;
// };

// const signUp = async (userPool, username, password, attributeList) => {
//   return new Promise((resolve, reject) => {
//     userPool.signUp(username, password, attributeList, null, (err, result) => {
//       if (err) return reject(err);
//       resolve(result.user);
//     });
//   });
// };

// const responses = {
//   BAD_REQUEST: msg => ({status: 400, message: `Bad Request.${msg ? " " + msg : ""}`}),
//   NOT_FOUND: msg => ({status: 404, message: `Not Found.${msg ? " " + msg : ""}`})
// };


// exports.handler = async (event, context, callback) => {
//   const { awsRequestId } = context;
//   try {
//     const userPool = new AmazonCognitoIdentity.CognitoUserPool({
//       UserPoolId: USER_POOL_ID,
//       ClientId: CLIENT_ID
//     });

//     const {username, password, email} = event.queryStringParameters;
//     if (!username) throw responses.BAD_REQUEST("Missing required parameter: username");
//     if (!password) throw responses.BAD_REQUEST("Missing required parameter: password");
//     if (!email) throw responses.BAD_REQUEST("Missing required parameter: email");

//     const attributeList = addAttribute([], "preferred_username", username);
//     const user = await signUp(userPool, email, password, attributeList);
//     successResponse(user, callback);
//   } catch (ex) {
//     errorResponse(ex, awsRequestId, callback);
//   }
// };
