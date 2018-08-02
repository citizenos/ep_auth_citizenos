'use strict';

var PLUGIN_NAME = 'ep_auth_citizenos';

var jwt = require('jsonwebtoken');
var _ = require('lodash');
var request = require('superagent');

var settings = require('ep_etherpad-lite/node/utils/Settings');
var pluginSettings = settings[PLUGIN_NAME];
var db = require('ep_etherpad-lite/node/db/DB').db;
var API = require('ep_etherpad-lite/node/db/API');
var authorManager = require('ep_etherpad-lite/node/db/AuthorManager');
var logger = require('ep_etherpad-lite/node_modules/log4js').getLogger(PLUGIN_NAME);

// Permission cache
var permissionCache = {};

/**
 * Get Etherpad key for token to author mapping
 *
 * @param {string} token EP token
 *
 * @returns {string} Database key
 *
 * @private
 */
function _getDbKeyForToken (token) {
    return 'token2author:' + token;
}


/**
 * Find out Topic ID from the Pad url.
 * If it's a Pad in edit mode, the Pad ID === Topic ID
 * If it's a read-only Pad link, the Topic ID is looked up from read-only ID
 *
 * @param {object} req Express Request object
 * @param {function} callback Callback function
 *
 * @returns {void}
 *
 * @private
 */
function _handleTopicInfo (req, callback) {
    // Pad name === topicId, lets try to get it from the url
    var matches = req.path.match(/\/p\/([\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})/);
    if (matches && matches.length > 1) {
        req.session.topic = {
            id: matches[1]
        };

        return callback();
    }

    // Must be read-only pad, let's find Pad id from read-only ID
    var roMatches = req.path.match(/\/p\/(r\.[\w]*)/);
    if (roMatches && roMatches.length > 1) {
        var roId = roMatches[1];
        API.getPadID(roId, function (err, padIDResult) {
            if (err) {
                return callback();
            }

            req.session.topic = {
                id: padIDResult.padID
            };

            return callback();
        });
    } else {
        logger.warn('Was not able to find Topic id for path', req.path);
        delete req.session.topic;

        return callback();
    }
}

/**
 * Handle JWT
 *
 * @param {object} req Request object
 *
 * @returns {void}
 *
 * @private
 */
function _handleJWT (req) {
    // JSON Web Token (JWT) passed by CitizenOS
    var token = req.query.jwt;

    // Initial request, the Pad is first opened with JWT
    if (token) {
        try {
            var tokenPayload = jwt.verify(token, pluginSettings.jwt.publicKey, {algorithms: pluginSettings.jwt.algorithms});
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                // It's ok when for example navigating from timeline view back to Pad. It calls history back, thus
                // FIXME: That just makes token expiry pointless anyway..
                logger.info('JWT verification failed', err, req.path);

                return;
            }
            logger.error('JWT verification failed', err, req.path);

            return;
        }

        var userId = _.get(tokenPayload, 'user.id');

        if (userId) {
            req.session.user = tokenPayload.user;
            logger.debug('JWT payload was fine.', tokenPayload);
        } else {
            logger.error('JWT payload is missing required data.', tokenPayload);
        }
    }

    logger.debug('No JWT provided');
}

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
function _getTopicPermissions (topicId, userId, ignoreCache, callback) {
    if (!topicId) {
        logger.debug('_getTopicPermissions', 'No Topic ID provided.');

        return callback('none');
    }

    var authorizationUrl = pluginSettings.authorization.url;
    var cacheMaxAge = pluginSettings.authorization.cacheMaxAge;
    var apiKey = pluginSettings.authorization.apiKey;
    var caCert = pluginSettings.authorization.caCert;

    var path = authorizationUrl.replace(':topicId', topicId);

    var query = {};

    if (userId) {
        query.userId = userId;
    }

    var cacheKey;

    // If there is no userId, there is no caching. It is not needed as the handleMessage authorization for messages which have userId
    if (!ignoreCache && topicId && userId) {
        cacheKey = topicId + '$' + userId;
    }

    // Check for cache, no cache if there is no userId.
    if (cacheKey) {
        var cacheValue = _.get(permissionCache[cacheKey], 'value');
        var cacheTimestamp = _.get(permissionCache[cacheKey], 'timestamp');

        if (cacheTimestamp && (cacheTimestamp + cacheMaxAge > new Date().getTime())) {
            logger.debug('_getTopicPermissions', 'Cache hit for key', cacheKey);

            return callback(cacheValue);
        } else {
            logger.debug('_getTopicPermissions', 'Cache miss for key', cacheKey);
        }
    }

    var req = request.get(path);
    if (caCert) {
        req.ca(caCert);
    }

    req
        .set('X-API-KEY', apiKey)
        .query(query)
        .end(function (err, res) {
            if (err) {
                logger.error('Authorization API returned an error. Access denied!', err);

                return callback('none');
            }

            var level = _.get(res, 'body.data.level');
            if (!level) {
                logger.error('Authorization API did not return permission level. Access denied!', res.body);

                return callback('none');
            }

            // Add result to cache
            if (cacheKey) {
                logger.debug('Refresh cache!', cacheKey);
                permissionCache[cacheKey] = {
                    value: level,
                    timestamp: new Date().getTime()
                };
            }

            return callback(level);
        });
}

/**
 * loadSettings hook
 *
 * Using it to verify plugin configuration, will kill the whole process if the conf is wrong.
 *
 * @returns {void}
 *
 * @see {@link http://etherpad.org/doc/v1.5.7/#index_loadsettings}
 */
exports.loadSettings = function () {
    var authorizationUrl = _.get(pluginSettings, 'authorization.url');
    var cacheMaxAge = _.get(pluginSettings, 'authorization.cacheMaxAge');
    var apiKey = _.get(pluginSettings, 'authorization.apiKey');

    if (!authorizationUrl || !cacheMaxAge || !_.isFinite(cacheMaxAge) || !apiKey) {
        logger.error('Invalid configuration! Missing authorization.url or authorization.cacheMaxAge or authorization.apiKey! Please check EP settings.json.', pluginSettings);
        process.exit(1);
    }

    var caCert = _.get(pluginSettings, 'authorization.caCert');
    if (caCert) {
        if (caCert.indexOf('-----BEGIN CERTIFICATE-----') !== 0) {
            logger.error('Invalid configuration! If you provide authorization.caCert, make sure it looks like a cert.');
            process.exit(1);
        }
    }

    var jwtPublicKey = _.get(pluginSettings, 'jwt.publicKey');
    if (!jwtPublicKey || jwtPublicKey.indexOf('PUBLIC KEY') < 0) {
        logger.error('Invalid configuration!. Missing JWT public key (ep_auth_citizenos.jwt.publicKey)! Please check your EP settings.json.', pluginSettings);
        process.exit(1);
    }

    var jwtAlgorithms = _.get(pluginSettings, 'jwt.algorithms');
    if (!jwtAlgorithms || !Array.isArray(jwtAlgorithms)) {
        logger.error('Invalid configuration! Missing JWT algorithm (ep_auth_citizenos.jwt.algorithms)! Please check your EP settings.json', pluginSettings);
        process.exit(1);
    }
};

/**
 * authorize hook
 *
 * @param {string} hook "authorize"
 * @param {object} context Context
 * @param {function} cb Function cb([thouShallPass]) where thouShallPass is true or false depending if authorized or not.
 *
 * @returns {void}
 *
 * @see {@link http://etherpad.org/doc/v1.5.7/#index_authorize}
 */
exports.authorize = function (hook, context, cb) {
    var req = context.req;
    var res = context.res;

    // Skip authorization for some paths...
    if (req.path.match(/^\/(jserror|favicon|locales|static|javascripts|pluginfw|api)/)) return cb([true]);

    logger.debug('authorize', req.path, req.query);

    // See if handover is done using JWT. We get username from there, if it exists.
    _handleJWT(req);

    // Parse Topic info from the request and store it in session.
    _handleTopicInfo(req, function () {
        // Delete EP long lasting 'token' cookie to force into creating a new one before sending CLIENT_READY.
        // Use short living tokens. Every time User visits, a new one is created. When User leaves, we make best effort to clean up the DB. See "exports.userLeave".
        res.clearCookie('token');

        // Handover has completed and from here on we check for permissions by calling Toru API.
        // This is to ensure that if permissions change in Toru system, we act accordingly in EP
        var topicId = _.get(req.session, 'topic.id');
        var userId = _.get(req.session, 'user.id');

        if (topicId) { // userId may be null, it's ok for a public Topic
            _getTopicPermissions(topicId, userId, true, function (level) {
                if (['admin', 'edit'].indexOf(level) > -1) { // User has edit permissions
                    logger.debug('authorize', 'User has edit permissions as the level is', level, 'Access granted!');

                    return cb([true]);
                } else if (level === 'read') { // User has read-only
                    logger.debug('authorize', 'User read permissions as the level is', level, 'Access granted!');
                    if (req.path.match(/^\/p\/r\./)) { // We dont want to redirect to read-only if we are already there
                        return cb([true]);
                    } else {
                        // Redirect to read-only version of the pad
                        API.getReadOnlyID(topicId, function (err, readOnlyResult) {
                            var roPadID = readOnlyResult.readOnlyID;
                            if (err || !roPadID) {
                                logger.error('Error while getting read-only Pad ID.  Access denied!');

                                return cb([false]);
                            }

                            var roPadPath = '/p/' + roPadID;

                            // Pass on all frame parameters to the read-only url so that themes and translations would work
                            var parts = req.originalUrl.split('?');
                            if (parts && parts.length > 1) {
                                roPadPath += '?' + parts[1];
                            }

                            logger.debug('Read only access. Redirecting to', roPadPath);

                            return res.redirect(302, roPadPath);
                        });
                    }
                } else { // User has no permissions
                    logger.warn('User has no permissions to access the Pad. Access denied!');

                    return cb([false]);
                }
            });
        } else {
            return cb([false]);
        }
    });
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
exports.authFailure = function (hook, context, cb) {
    logger.debug('authFailure');
    var res = context.res;
    res.status(401).send('Authentication required');

    return cb([true]);
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
exports.handleMessage = function (hook, context, cb) {
    // All other messages have to go through authorization
    var client = context.client;
    var message = context.message;
    var session = client.client.request.session;
    var topicId = _.get(session, 'topic.id');
    var userId = _.get(session, 'user.id');
    var token = message.token;

    logger.debug('handleMessage', context.message, session.id);

    // Disable editing user info
    if (context.message.type === 'COLLABROOM' && context.message.data.type === 'USERINFO_UPDATE') {
        logger.debug('handleMessage', 'Not allowing USERINFO_UPDATE update, don\'t want users changing their names.');

        return cb([null]);
    }

    if (!topicId) {
        logger.debug('handleMessage', 'Message dropped cause there is no session info');
        client.json.send({accessStatus: 'deny'});

        return cb([null]);
    }

    // Client ready is always allowed
    if (context.message.type === 'CLIENT_READY') {
        var displayName = _.get(session, 'user.name');

        // Pull some magic tricks to reuse same authorID for different tokens.
        if (userId) {
            logger.debug('handleMessage', 'Creating a new author for User', userId, 'Token is', token);
            authorManager.createAuthorIfNotExistsFor(userId, displayName, function (err, res) {
                if (err) {
                    logger.error('Failed to update User info', err);

                    return cb([null]);
                }
                var userAuthorId = res.authorID;

                // Create token in DB with our already existing author. EP would create a new author each time a new token is created.
                db.set('token2author:' + token, userAuthorId);
                logger.debug('handleMessage', 'Created new token2authhor mapping', token, userAuthorId);

                return cb([message]);
            });
        } else {
            return cb([message]);
        }
    } else {
        _getTopicPermissions(topicId, userId, false, function (level) {
            if (['admin', 'edit'].indexOf(level) > -1) {
                return cb([message]);
            } else if (level === 'read' && context.message.type === 'CHANGESET_REQ') { // Changeset requests are allowed for read level
                return cb([message]);
            } else {
                logger.debug('handleMessage', 'User is not allowed to post to this pad. The level was', level, 'Access denied!');
                client.json.send({accessStatus: 'deny'}); // Send deny message, so that UI would throw "no permissions" error

                return cb([null]);
            }
        });
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
exports.userLeave = function (hook, session, callback) {
    logger.debug('userLeave', session, session.id);

    // Delete the token from DB
    var token = _.get(session, 'auth.token');
    if (token) {
        // Cleanup DB from the token, as we generate a new one on each authorization, there would be a lot
        db.remove(_getDbKeyForToken(token), callback);
    } else {
        logger.warn('userLeave', 'Wanted to clean up DB but no token was present!', token);

        return callback();
    }
};
