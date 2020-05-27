'use strict';

const config = require('config');
const jwt = require('jsonwebtoken');

exports.handler = async (event, context, callback) => {
  let token = event.authorizationToken;

  if (token) {
    const splitToken = token.split(' ');

    if (splitToken.length === 2 && splitToken[0] === 'Bearer') token = splitToken[1];
  } else token = event.queryStringParameters.token;

 	if (token && token.constructor === String) {
    try {
      const decoded = await jwt.verify(token, config.secret);

      return callback(null, generatePolicy(decoded, event.methodArn));
    } catch (e) {
      return callback('Unauthorized');
    }
 	}
  return callback('Unauthorized');
};

const generateAuthResponse = (decoded, methodArn) => {
  const effect = !decoded ? 'Deny ': 'Allow';
  const policyDocument = generatePolicyDocument(effect, methodArn);
  const context = !decoded ? decoded : {};
  let principalId;

  if (effect === 'Allow') {
    principalId = `${decoded.user ? decoded.user : decoded.client}-${process.env.SERVERLESS_ALIAS}`;
  } else {
    principalId = process.env.SERVERLESS_ALIAS;
  }

  return {
    principalId,
    context,
    policyDocument
  };
};

const generatePolicyDocument = (effect, resource) => {
  if (!effect || !methodArn) return null;

  return {
    Version: '2012-10-17',
    Statement: [{
      Action: 'execute-api:Invoke',
      Effect: effect,
      Resource:resource
    }]
  };
};
