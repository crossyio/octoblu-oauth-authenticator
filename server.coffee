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
OctobluStrategy = require 'passport-octoblu'
debug = require('debug')('octoblu-oauth-server-example')

PORT  = process.env.PORT || 5988

passport.serializeUser (user, done) ->
  done null, JSON.stringify user

passport.deserializeUser (id, done) ->
  done null, JSON.parse id

app = express()
app.use cors()
app.use morgan('combined')
app.use errorHandler()
app.use session cookie: {secure: true}, secret: 'totally secret', name: 'octoblu-oauth-server-example'
app.use passport.initialize()
app.use passport.session()
app.use bodyParser.urlencoded limit: '50mb', extended : true
app.use bodyParser.json limit : '50mb'

app.options '*', cors()

octobluStrategyConfig =
  clientID: process.env.CLIENT_ID
  clientSecret: process.env.CLIENT_SECRET
  callbackURL: 'https://oauth.crossy.io/callback'
  passReqToCallback: true

passport.use new OctobluStrategy octobluStrategyConfig, (req, token, secret, profile, next) ->
  debug 'got token', token, secret
  req.session.token = token
  next null, uuid: profile.uuid

app.get '/', passport.authenticate('octoblu')
app.get '/callback', passport.authenticate('octoblu'), (req, res) ->
  res.send(req.session.token)

server = app.listen PORT, ->
  host = server.address().address
  port = server.address().port

  console.log "Server running on #{host}:#{port}"
