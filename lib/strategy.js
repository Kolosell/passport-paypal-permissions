/**
 * Module dependencies.
 */
var passport = require('passport'),
    // AuthorizationError = require('passport-oauth2').AuthorizationError,
    util = require('util'),
    PermissionsApi = require('paypal-permissions-sdk');


/**
 * `Strategy` constructor.
 *
 * @param {Object} options
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  // options.permissionsURL = options.permissionsURL || 'https://www.paypal.com/cgi-bin/webscr?cmd=_grant-permission&request_token=';
  options.permissionsURL = options.permissionsURL || 'https://www.paypal.com/cgi-bin/webscr';
  options.mode = options.mode || 'live';

  if (!verify) throw new Error('Paypal authentication strategy requires a verify function');
  if (!options.username) throw new Error('Paypal authentication strategy requires a username');
  if (!options.password) throw new Error('Paypal authentication strategy requires a password');
  if (!options.signature) throw new Error('Paypal authentication strategy requires a signature');
  if (!options.appId) throw new Error('Paypal authentication strategy requires an appId');
  if (!options.returnURL) throw new Error('Paypal authentication strategy requires a returnURL');
  
  passport.Strategy.call(this);
  this.name = 'paypal_permissions';
  this._verify = verify;
  this._returnURL = options.returnURL;
  this._permissionsURL = options.permissionsURL;
  this._passReqToCallback = options.passReqToCallback;

  this._permissions = new PermissionsApi({
    userId: options.username,
    password: options.password,
    signature: options.signature,
    appId: options.appId,
    mode: options.mode
  });
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if(req.query && req.query.request_token && req.query.verification_code) {
    this._permissions.getAccessToken(req.query.request_token, req.query.verification_code, (error, response) => {
      if(error) {
        return this.fail({ message: 'Something went wrong!' });
      }

      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        
        info = info || {};
        self.success(user, info);
      }

      try {
        if (self._passReqToCallback) {
          var arity = self._verify.length;
          if (arity == 6) {
            self._verify(req, response.token, response.tokenSecret, verified);
          } else { // arity == 5
            self._verify(req, response.token, response.tokenSecret, verified);
          }
        } else {
          var arity = self._verify.length;
          if (arity == 5) {
            self._verify(response.token, response.tokenSecret, verified);
          } else { // arity == 4
            self._verify(response.token, response.tokenSecret, verified);
          }
        }
      } catch (ex) {
        return self.error(ex);
      }
    });
  } else {
    this._permissions.requestPermissions(options.scope, this._returnURL + '?state=' + options.state, (error, response) => {
      if(error) {
        return this.fail({ message: 'Something went wrong!' });
      }

      self.redirect(this._permissionsURL + '?cmd=_grant-permission&request_token=' + response.token);
    });
  }
};

// Expose constructor.
module.exports = Strategy;
