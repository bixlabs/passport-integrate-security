var passport = require('passport'),
  session = require('express-session'),
  cookieParser = require('cookie-parser'),
  _ = require('lodash');

/**
 *
 * @param connect express app or express.Router
 * @param options JSON object
 * @constructor
 */
function SecurityMiddlware(connect, options) {
  var defaultOptions = {
    "redirect": false,
    "provider": 'local',
    "access_control": [],
    "stateless": false,
    "session": {
      "secret": 'keyboard cat',
      "saveUninitialized": true,
      "resave": true,
      "storage": 'default', // 'default', 'redis',
      // Only used if storage set to 'redis'
      "redis": {
        "host": 'localhost',
        "port": 6379
      }
    },
    "login": {
      "path": '/login',
      "check": '/login_check',
      "callback": function (req, res) {
        res.send(req.user);
      }
    },
    "logout": {
      "path": "/logout",
      "callback": function (req, res) {
        req.logout();
        res.send();
      }
    }
  };

  if (!connect.use || typeof connect.use !== 'function') {
    throw new Error("You must use a compatible connect/express app or router");
  }

  this.connect = connect;
  this.options = _.extend(defaultOptions, options);

  if (options.stateless) {
    this.connect.use(passport.initialize());
  } else {
    this.setupStorage();
  }

  this.setupLogin();
  this.setupLogout();

  this.setupAccessControlList();
}

/**
 * Validate and initialice the session storage
 */
SecurityMiddlware.prototype.setupStorage = function () {

  switch (this.options.session.storage) {
    case 'default':
      break;
    case 'redis':
      try {
        require.resolve("connect-redis");
        var RedisStore = require('connect-redis');
        this.options.session.store = new RedisStore(this.options.session.redis);

        this.connect.use(session(this.options.session));
        this.connect.use(passport.initialize());
        this.connect.use(passport.session());
      } catch (e) {
        console.error("For use 'redis' storage needs install 'npm install --save connect-redis'");
        process.exit(e.code);
      }
      break;
    default:
      throw new Error('Invalid session storage "' + this.options.session.storage + '"');
  }

  this.options.session = _.omit(this.options.session, ['storage', 'redis']);
};


/**
 * Generate a object for check request agaist rules
 * @param req
 * @returns {{anonymous: boolean, roles: Array, request_path: *, method: string}}
 */
SecurityMiddlware.prototype.processRequest = function (req) {
  /**
   * If the user is not defined is anonymous
   * @type {boolean}
   */
  var anom = (!req.user || req.user === null);

  return {
    "anonymous": anom,
    "roles": anom ? [] : (req.user.getRoles ? req.user.getRoles() : []),
    "request_path": req.path,
    "method": req.method
  };
};

/**
 * Setup the method for login users
 */
SecurityMiddlware.prototype.setupLogin = function () {
  if (this.options.login) {
    var provider = passport.authenticate(this.options.provider, this.options.login);
    this.connect.post(this.options.login.check, provider, this.options.login.callback);
  }
};

/**
 * Setup the method for destroy the session
 */
SecurityMiddlware.prototype.setupLogout = function () {
  if (this.options.logout) {
    this.connect.get(this.options.logout.path, this.options.logout.callback);
  }
};

SecurityMiddlware.prototype.setupAccessControlList = function() {
  this.connect.all('*', function (req, res, next) {

    var i, rule,
      allow = false,
      allowRole = false,
      allowMethod = false,
      hasRules = false,
      input = this.processRequest(req),
      regExpPath;

    // TODO: include login.check in the ACL

    for (i = 0; i < this.options.access_control.length; i++) {
      rule = this.options.access_control[i];
      regExpPath = new RegExp(rule.match);

      if (regExpPath.test(input.request_path)) {
        hasRules = true;
        if (rule.anonymous) {
          i = this.options.access_control.length;
          allow = true;
        } else {
          // Testing roles
          rule.roles = typeof rule.roles === 'undefined' ? [] : rule.roles;
          rule.roles = _.isArray(rule.roles) ? rule.roles : [rule.roles];
          // If rule has roles test role count
          allowRole = rule.roles.length > 0 ?
            (_.intersection(rule.roles, input.roles).length > 0) :
            true;

          // Testing methods
          rule.methods = typeof rule.methods === 'undefined' ? [] : rule.methods;
          rule.methods = _.isArray(rule.methods) ? rule.methods : [rule.methods];
          // If rule has methods test method count
          allowMethod = rule.methods.length > 0 ?
            (_.intersection(rule.methods, [input.method]).length > 0) :
            true;

          allow = allowMethod && allowRole;

          // if we find a matching rule, no need for look more
          if (allow) {
            i = this.options.access_control.length;
          }

          // TODO: check ip on rule
        }
      }
    }

    // TODO: look for a way to throw HTTP Exceptions instead set status
    //       Will be more compatible with multiples Content-Type headers
    if ((!hasRules && !input.anonymous) || allow) {
      next();
    } else if (input.anonymous) {
      if (this.options.redirect && this.options.login.path) {
        res.redirect(this.options.login.path);
      } else {
        res.status(403);
        res.send('Access Denied - only users');
      }
    } else {
      res.status(401);
      res.send('Access Denied - You don\'t have permission');
    }
  }.bind(this));
};

module.exports = SecurityMiddlware;