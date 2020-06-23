const responses = {
  BAD_REQUEST: msg => ({status: 400, message: `Bad Request.${msg ? " " + msg : ""}`}),
  NOT_FOUND: msg => ({status: 404, message: `Not Found.${msg ? " " + msg : ""}`})
};

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

module.exports = {
  errorResponse,
  responses,
  successResponse,
};
