_ = require 'lodash'
cors = require 'cors'
async = require 'async'
morgan = require 'morgan'
express = require 'express'
request = require 'request'
passport = require 'passport'
session = require 'cookie-session'
bodyParser = require 'body-parser'
errorHandler = require 'errorhandler'
MeshbluConfig = require 'meshblu-config'
OctobluStrategy = require 'passport-octoblu'
debug = require('debug')('octoblu-oauth-server-example')
CredentialManager = require './src/models/credential-manager'

PORT  = process.env.PORT || 80

passport.serializeUser (user, done) ->
  done null, JSON.stringify user

passport.deserializeUser (id, done) ->
  done null, JSON.parse id

app = express()
app.use cors()
app.use morgan('combined')
app.use errorHandler()
app.use session cookie: {secure: true}, secret: 'totally secret', name: 'oauth-crossy-io'
app.use passport.initialize()
app.use passport.session()
app.use bodyParser.urlencoded limit: '50mb', extended : true
app.use bodyParser.json limit : '50mb'

app.options '*', cors()

meshbluConfig = new MeshbluConfig

options =
  name: 'Octoblu'

credentialManager = new CredentialManager options, meshbluConfig

octobluStrategyConfig =
  clientID: process.env.CLIENT_ID
  clientSecret: process.env.CLIENT_SECRET
  callbackURL: 'https://oauth.crossy.io/callback'
  passReqToCallback: true

passport.use new OctobluStrategy octobluStrategyConfig, (req, token, secret, profile, next) ->
  debug 'got token', token, secret
  req.session.token = token
  req.session.userUuid = profile.uuid
  next null, uuid: profile.uuid

app.get '/', (req, res) ->
  req.session.callbackUrl = req.query.callbackUrl
  debug 'callbackUrl', req.session.callbackUrl
  passport.authenticate('octoblu') req, res

app.get '/healthcheck', (req, res) ->
  res.send('{"online":true}').status(200)

app.get '/callback', passport.authenticate('octoblu'), (req, res) ->
  credentialManager.findOrCreate req.session.userUuid, req.session.userUuid, req.session.token, (error, result) =>
    return res.status(422).send(error.message) if error?

    if req.session.callbackUrl?
      callbackUrl = url.parse req.session.callbackUrl, true
      delete callbackUrl.search
      callbackUrl.query.uuid = result.uuid
      callbackUrl.query.creds_uuid = result.creds.uuid
      callbackUrl.query.creds_token = result.creds.token
      return res.redirect url.format(callbackUrl)

  res.status(200).end()

server = app.listen PORT, ->
  host = server.address().address
  port = server.address().port

  console.log "Server running on #{host}:#{port}"
