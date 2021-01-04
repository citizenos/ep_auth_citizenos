'use strict';

const PLUGIN_NAME = 'ep_auth_citizenos';

const jwt = require('jsonwebtoken');
const _ = require('lodash');
const request = require('superagent');

const settings = require('ep_etherpad-lite/node/utils/Settings');
const pluginSettings = settings[PLUGIN_NAME];
const db = require('ep_etherpad-lite/node/db/DB').db;
const API = require('ep_etherpad-lite/node/db/API');
const authorManager = require('ep_etherpad-lite/node/db/AuthorManager');
const padMessageHandler = require('ep_etherpad-lite/node/handler/PadMessageHandler');
const logger = require('ep_etherpad-lite/node_modules/log4js').getLogger(PLUGIN_NAME);

// Permission cache
const permissionCache = {};

/**
 * Get Etherpad key for token to author mapping
 *
 * @param {string} token EP token
 *
 * @returns {string} Database key
 *
 * @private
 */
const _getDbKeyForToken = (token) => `token2author:${token}`;


/**
 * Find out Topic ID from the Pad url.
 * If it's a Pad in edit mode, the Pad ID === Topic ID
 * If it's a read-only Pad link, the Topic ID is looked up from read-only ID
 *
 * @param {object} req Express Request object
 *
 * @returns {void}
 *
 * @private
 */
const _handleTopicInfo = async (req) => {
  // Pad name === topicId, lets try to get it from the url
  const matches = req.path.match(/\/p\/([\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})/);
  if (matches && matches.length > 1) {
    req.session.topic = {
      id: matches[1],
    };

    return true;
  }

  // Must be read-only pad, let's find Pad id from read-only ID
  const roMatches = req.path.match(/\/p\/(r\.[\w]*)/);
  if (roMatches && roMatches.length > 1) {
    const roId = roMatches[1];
    try {
      const padIDResult = await API.getPadID(roId);

      req.session.topic = {
        id: padIDResult.padID,
      };

      return true;
    } catch (err) {
      logger.error(err);
    }
  } else {
    logger.warn('Was not able to find Topic id for path', req.path);
    delete req.session.topic;

    return true;
  }
};

/**
 * Handle JWT
 *
 * @param {object} req Request object
 *
 * @returns {void}
 *
 * @private
 */
const _handleJWT = (req) => {
  // JSON Web Token (JWT) passed by CitizenOS
  const token = req.query.jwt;
  let tokenPayload;
  // Initial request, the Pad is first opened with JWT
  if (token) {
    try {
      tokenPayload = jwt.verify(token,
          pluginSettings.jwt.publicKey,
          {algorithms: pluginSettings.jwt.algorithms}
      );
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        // It's ok when for example navigating from timeline view back to Pad.
        // It calls history back, thus
        // FIXME: That just makes token expiry pointless anyway..
        logger.info('JWT verification failed', err, req.path);

        return;
      }
      logger.error('JWT verification failed', err, req.path);

      return;
    }

    const userId = _.get(tokenPayload, 'user.id');

    if (userId) {
      req.session.user = tokenPayload.user;
      logger.debug('JWT payload was fine.', tokenPayload);
    } else {
      logger.error('JWT payload is missing required data.', tokenPayload);
    }
  }

  logger.debug('No JWT provided');
};

/**
 * Get Topic permission level
 *
 * Cache is not used when there is no "userId" as for these cases only authorization really c
 *
 * @param {string} topicId Topic id
 * @param {string|null} userId User id, can be null.
 * @param {boolean} ignoreCache Ignore cache and always call API
 * @param {function} callback Callback function with 1 string argument permission level
 *
 * @return {void}
 *
 * @private
 */
const _getTopicPermissions = async (topicId, userId, ignoreCache) => {
  if (!topicId) {
    logger.debug('_getTopicPermissions', 'No Topic ID provided.');

    return 'none';
  }

  const authorizationUrl = pluginSettings.authorization.url;
  const cacheMaxAge = pluginSettings.authorization.cacheMaxAge;
  const apiKey = pluginSettings.authorization.apiKey;
  const caCert = pluginSettings.authorization.caCert;

  const path = authorizationUrl.replace(':topicId', topicId);

  const query = {};

  if (userId) {
    query.userId = userId;
  }

  let cacheKey;

  // If there is no userId, there is no caching.
  // It is not needed as the handleMessage authorization for messages which have userId
  if (!ignoreCache && topicId && userId) {
    cacheKey = `${topicId}$${userId}`;
  }

  // Check for cache, no cache if there is no userId.
  if (cacheKey) {
    const cacheValue = _.get(permissionCache[cacheKey], 'value');
    const cacheTimestamp = _.get(permissionCache[cacheKey], 'timestamp');

    if (cacheTimestamp && (cacheTimestamp + cacheMaxAge > new Date().getTime())) {
      logger.debug('_getTopicPermissions', 'Cache hit for key', cacheKey);

      return cacheValue;
    } else {
      logger.debug('_getTopicPermissions', 'Cache miss for key', cacheKey);
    }
  }

  const req = request.get(path);
  if (caCert) {
    req.ca(caCert);
  }
  try {
    const res = await req
        .set('X-API-KEY', apiKey)
        .query(query);

    const level = _.get(res, 'body.data.level');
    if (!level) {
      logger.error('Authorization API did not return permission level. Access denied!', res.body);

      return 'none';
    }

    // Add result to cache
    if (cacheKey) {
      logger.debug('Refresh cache!', cacheKey);
      permissionCache[cacheKey] = {
        value: level,
        timestamp: new Date().getTime(),
      };
    }

    return level;
  } catch (err) {
    if (err) {
      logger.error('Authorization API returned an error. Access denied!', err);

      return 'none';
    }
  }
};

/**
 * loadSettings hook
 *
 * Using it to verify plugin configuration, will kill the whole process if the conf is wrong.
 *
 * @returns {void}
 *
 * @see {@link http://etherpad.org/doc/v1.5.7/#index_loadsettings}
 */
exports.loadSettings = (hook, context, cb) => {
  const authorizationUrl = _.get(pluginSettings, 'authorization.url');
  const cacheMaxAge = _.get(pluginSettings, 'authorization.cacheMaxAge');
  const apiKey = _.get(pluginSettings, 'authorization.apiKey');

  if (!authorizationUrl || !cacheMaxAge || !_.isFinite(cacheMaxAge) || !apiKey) {
    const invalidConfErr = `Invalid configuration! Missing authorization.url or
    authorization.cacheMaxAge or
    authorization.apiKey! Please check EP settings.json.`;
    logger.error(invalidConfErr, pluginSettings);
    throw new Error(invalidConfErr);
  }

  const caCert = _.get(pluginSettings, 'authorization.caCert');
  if (caCert) {
    if (caCert.indexOf('-----BEGIN CERTIFICATE-----') !== 0) {
      const invalidCertErr = `Invalid configuration!
      If you provide authorization.caCert, make sure it looks like a cert.`;
      logger.error(invalidCertErr);
      throw new Error(invalidCertErr);
    }
  }

  const jwtPublicKey = _.get(pluginSettings, 'jwt.publicKey');
  if (!jwtPublicKey || jwtPublicKey.indexOf('PUBLIC KEY') < 0) {
    const missingJWTpubKey = `Invalid configuration!.
    Missing JWT public key (ep_auth_citizenos.jwt.publicKey)! Please check your EP settings.json.`;
    logger.error(missingJWTpubKey, pluginSettings);
    throw new Error(missingJWTpubKey);
  }

  const jwtAlgorithms = _.get(pluginSettings, 'jwt.algorithms');
  if (!jwtAlgorithms || !Array.isArray(jwtAlgorithms)) {
    const missingJWTAlgo = `Invalid configuration!
    Missing JWT algorithm (ep_auth_citizenos.jwt.algorithms)! Please check your EP settings.json`;
    logger.error(missingJWTAlgo, pluginSettings);
    throw new Error(missingJWTAlgo);
  }

  return cb();
};
exports.preAuthorize = async (hook, context, cb) => {
  const staticPathsRE = new RegExp(`^/(?:${[
    'api/.*',
    'favicon\\.ico',
    'javascripts/.*',
    'locales\\.json',
    'locales/.*\\.json',
    'pluginfw/.*',
    'static/.*',
  ].join('|')})$`);
  if (context.req.path.match(staticPathsRE)) {
    return cb([true]);
  } else {
    return cb([]);
  }
}

exports.authenticate = async (hook, context, cb) => {
  if (!context.users) {
    context.users = {};
  }
  const req = context.req;
  const res = context.res;

  // Skip authorization for some paths...
  if (req.path.match(/^\/(jserror|favicon|locales|static|javascripts|pluginfw|api)/)) {
    return cb([true]);
  }

  logger.debug('authorize', req.path, req.query);

  // See if handover is done using JWT. We get username from there, if it exists.
  _handleJWT(req);

  if (context.req.session.user) {
    context.users[context.req.session.user.name] = context.req.session.user;
    return cb([true]);
  }
  return cb([false]);
};
/**
 * authorize hook
 *
 * @param {string} hook "authorize"
 * @param {object} context Context
 * @param {function} cb Function cb([thouShallPass])
 * where thouShallPass is true or false depending if authorized or not.
 *
 * @returns {void}
 *
 * @see {@link http://etherpad.org/doc/v1.5.7/#index_authorize}
 */
exports.authorize = async (hook, context, cb) => {
  const req = context.req;
  const res = context.res;


  // Parse Topic info from the request and store it in session.
  await _handleTopicInfo(req);
  // Delete EP long lasting 'token' cookie
  // to force into creating a new one before sending CLIENT_READY.
  // Use short living tokens. Every time User visits, a new one is created.
  // When User leaves, we make best effort to clean up the DB. See "exports.userLeave".
  res.clearCookie('token');
  // Handover has completed and from here on we check for permissions by calling Toru API.
  // This is to ensure that if permissions change in Toru system, we act accordingly in EP
  const topicId = _.get(req.session, 'topic.id');
  const userId = _.get(req.session, 'user.id');
  // userId may be null, it's ok for a public Topic
  if (!topicId) {
    return cb([false]);
  }

  const lvl = await _getTopicPermissions(topicId, userId, true);
  if (['admin', 'edit'].indexOf(lvl) > -1) { // User has edit permissions
    logger.debug('authorize', 'User has edit permissions as the level is', lvl, 'Access granted!');

    return cb([true]);
  } else if (lvl === 'read') { // User has read-only
    logger.debug('authorize', 'User read permissions as the level is', lvl, 'Access granted!');
    // We dont want to redirect to read-only if we are already there
    if (req.path.match(/^\/p\/r\./)) {
      return cb([true]);
    } else {
      // Redirect to read-only version of the pad
      try {
        const readOnlyResult = await API.getReadOnlyID(topicId);
        const roPadID = readOnlyResult.readOnlyID;

        let roPadPath = `/p/${roPadID}`;

        // Pass on all frame parameters to the read-only url
        // so that themes and translations would work
        const parts = req.originalUrl.split('?');
        if (parts && parts.length > 1) {
          roPadPath += `?${parts[1]}`;
        }

        logger.debug('Read only access. Redirecting to', roPadPath);

        return res.redirect(302, roPadPath);
      } catch (err) {
        logger.error('Error while getting read-only Pad ID.  Access denied!', err);

        return cb([false]);
      }
    }
  } else { // User has no permissions
    logger.warn('User has no permissions to access the Pad. Access denied!');

    return cb([false]);
  }
};

/**
 * Auth failure hook
 *
 * Custom failure handler, to avoid sending basic auth response headers
 *
 * @param {string} hook Hook name "authFailure"
 * @param {object} context {req, res, next}
 * @param {function} cb callback
 *
 * @returns {void}
 *
 * @see {@link http://etherpad.org/doc/v1.5.7/#index_authfailure}
 */
exports.authzFailure = (hook, context, cb) => {
  logger.debug('authFailure');
  const res = context.res;
  res.status(403).send('Authentication required');

  return cb([true]);
};

exports.authnFailure = (hook, context, cb) => {
  logger.debug('authFailure');
  const res = context.res;
  res.status(401).send('Authentication required');

  return cb([true]);
};

const _syncAuthorData = async (authorData) => {
  const caCert = pluginSettings.authorization.caCert;
  const authorSyncUrl = pluginSettings.authorSync.url;
  const apiKey = pluginSettings.authorization.apiKey;
  const path = authorSyncUrl.replace(':userId', authorData.userId);
  const req = request.put(path);

  if (caCert) {
    req.ca(caCert);
  }
  try {
    await req
        .set('X-API-KEY', apiKey)
        .send(authorData);
  } catch (err) {
    console.log(err);
  }
};
/**
 * handleMessage hook
 *
 * @param {string} hook "handleMessage"
 * @param {object} context Context
 * @param {function} cb Callback function([message]) where if message is null, then it's dropped
 *
 * @returns {void}
 *
 * @see {@link http://etherpad.org/doc/v1.5.7/#index_handlemessage}
 */
exports.handleMessage = async (hook, context) => {
  // All other messages have to go through authorization
  const client = context.client;
  const message = context.message;
  const session = client.client.request.session;
  const topicId = _.get(session, 'topic.id');
  const userId = _.get(session, 'user.id');
  const token = message.token;

  logger.debug('handleMessage', context.message, session.id);
  // Disable editing user info
  if (message.type === 'COLLABROOM' && message.data.type === 'USERINFO_UPDATE') {
    logger.debug('handleMessage', 'Not allowing USERINFO_UPDATE update, don\'t want users changing their names.');

    return [null];
  }

  if (!topicId) {
    logger.debug('handleMessage', 'Message dropped cause there is no session info');
    client.json.send({accessStatus: 'deny'});

    return [null];
  }
  // Client ready is always allowed
  if (context.message.type === 'CLIENT_READY') {
    const displayName = _.get(session, 'user.name');
    // Pull some magic tricks to reuse same authorID for different tokens.
    if (userId) {
      try {
        logger.debug('handleMessage', 'Creating a new author for User', userId, 'Token is', token);
        const res = await authorManager.createAuthorIfNotExistsFor(userId, displayName);
        const userAuthorId = res.authorID;
        session.authorID = userAuthorId;
        _syncAuthorData({userId, authorID: userAuthorId});
        padMessageHandler.sessioninfos[client.id].author = userAuthorId;
        // Create token in DB with our already existing author.
        // EP would create a new author each time a new token is created.
        db.set(`token2author:${token}`, userAuthorId);
        logger.debug('handleMessage', 'Created new token2authhor mapping', token, userAuthorId);

        return [message];
      } catch (err) {
        logger.error('Failed to update User info', err);

        return [null];
      }
    } else {
      return [message];
    }
  } else {
    const level = await _getTopicPermissions(topicId, userId, false);

    if (['admin', 'edit'].indexOf(level) > -1) {
      return [message];
    } else if (level === 'read' && context.message.type === 'CHANGESET_REQ') {
      // Changeset requests are allowed for read level
      return [message];
    } else {
      logger.debug('handleMessage', 'User is not allowed to post to this pad. The level was', level, 'Access denied!');
      // Send deny message, so that UI would throw "no permissions" error
      client.json.send({accessStatus: 'deny'});

      return [null];
    }
  }
};

/**
 * userLeave hook
 *
 * @param {string} hook "userLeave"
 * @param {object} session Session info
 * @param {function} callback Callback function (err, res)
 *
 * @returns {void}
 *
 * @see {@link http://etherpad.org/doc/v1.5.7/#index_userleave}
 */
exports.userLeave = (hook, session, callback) => {
  logger.debug('userLeave', session, session.id);

  // Delete the token from DB
  const token = _.get(session, 'auth.token');
  if (token) {
    // Cleanup DB from the token,
    // as we generate a new one on each authorization, there would be a lot
    db.remove(_getDbKeyForToken(token));
    callback();
  } else {
    logger.warn('userLeave', 'Wanted to clean up DB but no token was present!', token);
    callback();
  }
};

exports.clientVars = async (hookName, context) => {
  const authorId = context.socket.client.request.session.authorID;

  return {userId: authorId};
};
