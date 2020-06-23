const auth = require("./auth-utilities");
const http = require("./http-utilities");

exports.handler = async (event, context, callback) => {
  const { awsRequestId } = context;
  const {username, password, email} = event.queryStringParameters;
  try {
    if (!username) throw http.responses.BAD_REQUEST("Missing required parameter: username");
    if (!password) throw http.responses.BAD_REQUEST("Missing required parameter: password");
    if (!email) throw http.responses.BAD_REQUEST("Missing required parameter: email");

    const user = await auth.userSignUp(username, email, password);
    http.successResponse(user, callback);
  } catch (ex) {
    if (ex.message === "An account with the given email already exists.") {
      try {
        console.error(JSON.stringify(ex));
        const user = await auth.getUser(email);
        http.successResponse(user, callback);
      } catch (err) {
        http.errorResponse(err, awsRequestId, callback);
      }
    } else {
      http.errorResponse(ex, awsRequestId, callback);
    }
  }
};
