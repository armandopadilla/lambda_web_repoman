var express = require('express');
var router = express.Router();

const utils = require('../utils')
const validator = require('validator');
const AWS = require('aws-sdk');

const SECRET = 'K8txD8jjhkFx3tG4BGFFMUCRvMgDdGDL'

const DynamoDB = new AWS.DynamoDB({
  accessKeyId: '',
  secretAccessKey: '',
  region: ''
})

const TABLE_NAME = 'Repoman_Users'

/**
 * Link Account landing page.  Form.
 */
router.get('/link-account', function(req, res, next) {
  const clientId = req.query.client_id || ''
  const state = req.query.state || ''
  const responseType = req.query.response_type || ''
  const redirectUri = req.query.redirect_uri || ''

  DynamoDB.scan({
    TableName: 'Repoman_Users',
    FilterExpression: "accessToken = :accessToken and awsUserId = :userId AND device = :deviceId",
    ExpressionAttributeValues: {
      ':accessToken': { S: 'asdf' },
      ':userId': { S: 'userId' },
      ':deviceId': { S: 'deviceId' }
    }
  }).promise().then(results => {
    console.log(results)
  })

  res.render('link-account', { clientId, state, responseType, redirectUri, error: false });
});


router.post('/link-account', (req, res, next) => {
  // Init vars
  const email = req.body.email || ''
  const password = req.body.password || ''
  const clientId = req.body.clientId || ''
  const state = req.body.state || ''
  const responseType = req.body.responseType || ''
  const redirectUri = req.body.redirectUri || ''

  // Check the email+password
  if (validator.isEmpty(email) || validator.isEmpty(password)) {
    return res.render('link-account', { clientId, state, responseType, redirectUri , error: 'Username and/or password invalid.' })
  }

  if (validator.isEmpty(clientId) ||
    validator.isEmpty(state) ||
    validator.isEmpty(responseType) ||
    validator.isEmpty(redirectUri)) {
    return res.render('link-account', { clientId, state, responseType, redirectUri , error: 'Required Alexa parameters missing.' })
  }

  let params = {
    Key: {
      "email": { S: email },
    },
    TableName: TABLE_NAME
  }
  return DynamoDB.getItem(params)
    .promise()
    .then(user => {
      if (!user.Item) return res.render('link-account', { clientId, state, responseType, redirectUri , error: 'Username and/or password invalid.' })

      // Check if the password is valid
      const passwordSalt = user.Item.passwordSalt.S
      const passwordHashed = user.Item.password.S

      if (!utils.checkHash(password, passwordHashed, passwordSalt)) {
        return res.render('link-account', { clientId, state, responseType, redirectUri , error: 'Username and/or password invalid.' })
      }
    })

    .then(() => utils.hashString(`${email}:${SECRET}:${Date.now()}`))

    // Save the access token for the user.
    .then((accessTokenObj) => {
      const updateUserParams = {
        ExpressionAttributeValues: {
          ":accessToken": {
            S: accessTokenObj.stringHash,
          },
          ":accessTokenSalt": {
            S: accessTokenObj.salt
          },
          ":clientId": {
            S: clientId
          }
        },
        Key: {
          "email": {S: email}
        },
        UpdateExpression: "SET accessToken = :accessToken, accessTokenSalt = :accessTokenSalt, clientId = :clientId",
        TableName: TABLE_NAME
      }

      return DynamoDB.updateItem(updateUserParams).promise().then(() => accessTokenObj)
    })

    // Redirect the user to aws.
    .then((accessTokenObj => {
      const redirectURL = `${redirectUri}#state=${state}&access_token=${encodeURIComponent(accessTokenObj.stringHash)}&token_type=Bearer`
      return res.redirect(301, redirectURL);
    }))
    .catch(error => {
      console.log(error)
    })
})


/**
 * Sign up landing page. Form
 *
 */
router.get('/signup', (req, res, next) => res.render('signup', {
  error: false,
  email: null,
  password: null,
  repassword: null,
  githubToken: null,
  githubUsername: null
}));

/**
 * Sign up submission
 *
 */
router.post('/signup', (req, res, next) => {
  // Initial vars
  const email = req.body.email || ''
  const password = req.body.password || ''
  const repassword = req.body.repassword || ''
  const githubToken = req.body.githubToken || ''
  const githubUsername = req.body.githubUsername || ''

  const resVals = {
    email,
    password,
    repassword,
    githubToken,
    githubUsername
  }

  if (!validator.isEmail(email)) {
    resVals.error = 'Email provided is invalid.'
    return res.render('signup', resVals);
  }
  if (validator.isEmpty(password)) {
    resVals.error = 'Password can not be empty.'
    return res.render('signup', resVals);
  }
  if (validator.isEmpty(githubToken)) {
    resVals.error = 'Github Token can not be empty.'
    return res.render('signup', resVals);
  }
  if (password !== repassword) {
    resVals.error = 'Passwords do not match.'
    return res.render('signup', resVals);
  }

  if (validator.isEmpty(githubUsername)) {
    resVals.error = 'Github username is required.'
    return res.render('signup', resVals)
  }

  let lclHashPass

  // Check if email is valid
  const params = {
    Key: { "email": { S: email } },
    TableName: TABLE_NAME
  }
  DynamoDB.getItem(params)
    .promise()
    .then(user => {
      if (user.Item) throw Error('User is already part of Repoman')
    })

    // Hash the password
    .then(() => utils.hashString(password))

    // Add to database.
    .then((hashPass) => {
      const newUserParams = {
        Item: {
          "email": { S: email },
          "password": { S: hashPass.stringHash },
          "passwordSalt": { S: hashPass.salt },
          "githubToken": { S: githubToken },
          "githubUsername": { S: githubUsername }
        },
        TableName: TABLE_NAME
      }

      return DynamoDB.putItem(newUserParams).promise()
    })

    // Respond
    .then(() => res.render('signup-thankyou'))
    .catch(error => {
      resVals.error = error.message
      res.render('signup', resVals);
    })

});

module.exports = router;