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

const refreshToken = async (username, password) => {
  return new Promise((resolve,reject) => {
    var params = {
      AuthFlow: "REFRESH_TOKEN_AUTH",
      ClientId: CLIENT_ID,
      AuthParameters: {
        REFRESH_TOKEN: token,
        SECRET_HASH: hashSecret(CLIENT_SECRET, username, CLIENT_ID),
      },
      ClientMetadata: {}.
    };
    cognito.initiateAuth(params, (err, data) => {
      if (err) return reject(err);
      resolve(data);
    });
  });
};


exports.handler = async (event, context, callback) => {
  const { awsRequestId } = context;
  try {
    const { token } = JSON.parse(event.body);
    if (!token) throw responses.BAD_REQUEST("Missing required parameter: token");

    const result = await refreshToken(token);
    successResponse(result, callback);
  } catch (ex) {
    errorResponse(ex, awsRequestId, callback);
  }
};


cognitoidentityserviceprovider.initiateAuth(params, function(err, data) {
  if (err) console.log(err, err.stack); // an error occurred
  else     console.log(data);           // successful response
});
