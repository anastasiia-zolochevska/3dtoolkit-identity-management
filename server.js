var express = require('express');
var pg = require('pg');
var crypto = require('crypto');
var Promise = require('promise');
var passport = require("passport");
var BearerStrategy = require('passport-azure-ad').BearerStrategy;
process.env.APPINSIGHTS_INSTRUMENTATIONKEY = process.env.APPINSIGHTS_INSTRUMENTATIONKEY || "NO_APPLICATION_INSIGHTS";
var appInsights = require('applicationinsights');
appInsights.setup().setAutoCollectExceptions(true).start();


var port = process.env.PORT || 3002;

var app = express();

var postgresConfig = {
    user: process.env.PGUSER || "coturn@azturntstpsqlsrv",
    database: process.env.PGDATABASE || "coturndb",
    password: process.env.PGPASSWORD,
    host: process.env.PGHOST || "azturntstpsqlsrv.postgres.database.azure.com",
    port: process.env.PGPORT || 5432,
    max: 10, // max number of clients in the pool 
    idleTimeoutMillis: 30000, // how long a client is allowed to remain idle before being closed 
    ssl: true
};


var b2cStrategy = new BearerStrategy({
    identityMetadata: "https://login.microsoftonline.com/" + (process.env.AAD_TENANT_ID || "3dtoolkit.onmicrosoft.com") + "/v2.0/.well-known/openid-configuration",
    clientID: process.env.AAD_B2C_CLIENT_APPLICATION_ID || "aacf1b7a-104c-4efe-9ca7-9f4916d6b66a",
    policyName: process.env.AAD_B2C_POLICY_NAME || "b2c_1_signup",
    isB2C: true,
    validateIssuer: true,
    loggingLevel: 'info',
    passReqToCallback: false,
},
    function (token, done) {
        return done(null, {}, token);
    }
)
b2cStrategy.name="oauth-bearer-b2c";

passport.use(b2cStrategy);

passport.use(new BearerStrategy({
    identityMetadata: "https://login.microsoftonline.com/" + (process.env.AAD_TENANT_ID || "3dtoolkit.onmicrosoft.com") + "/.well-known/openid-configuration",
    clientID: process.env.AAD_RENDERING_SERVER_APPLICATION_ID || "5b4df04b-e3bb-4710-92ca-e875d38171b3",
    isB2C: false,
    validateIssuer: true,
    loggingLevel: 'info',
    passReqToCallback: false
},
    function (token, done) {
        return done(null, {}, token);
    }
));


app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Authorization, Origin, X-Requested-With, Content-Type, Accept, Peer-Type");
    if ('OPTIONS' == req.method) {
        res.sendStatus(200);
    } else {
        next();
    }

});

app.all('*', function (req, res, next) {
    log(req.url);
    if (req.query.peer_id && peers[req.query.peer_id]) {
        peers[req.query.peer_id].lastSeenActive = (new Date()).getTime();
    }
    if (process.env.AUTH_DISABLED && process.env.AUTH_DISABLED!="False" &&  process.env.AUTH_DISABLED!="false") {
        next();
    }
    else {
        passport.authenticate(['oauth-bearer', 'oauth-bearer-b2c'], function (err, user, info) {
            if (!err && info) {
                next();
            }
            else {
                res.sendStatus(401);
            }
        })(req, res, next);
    }
});


getSecret = function (realm) {
    const client = new pg.Client(postgresConfig);
    return new Promise(function (resolve, reject) {
        client.connect(function (err, client, done) {
            if (err) {
                reject('error fetching client from pool' + err);

            }
            else {
                const query = {
                    // give the query a unique name
                    name: 'fetch-secret',
                    text: 'SELECT * FROM turn_secret WHERE realm = $1',
                    values: [realm]
                }
                client.query(query, function (err, result) {

                    if (err) {
                        reject('error running query' + err);
                    }
                    else if (!result || !result.rows[0]) {
                        reject("no secret set in db for realm " + realm);

                    } else resolve(result.rows[0].value)
                });
            }

        })
    });
}


app.get('/turnCreds',
    function (req, res) {

        var name = req.query.username || "user";
        var realm = req.query.realm || "azturntst.org"
        log(name + ' ' + realm)
        getSecret(realm).then(secret => {
            try {
                var unixTimeStamp = parseInt(Date.now() / 1000) + 24 * 3600,
                    username = [unixTimeStamp, name].join(':'),
                    password,
                    hmac = crypto.createHmac('sha1', secret);
                hmac.setEncoding('base64');
                hmac.write(username);
                hmac.end();
                password = hmac.read();
                res.send({
                    username: username,
                    password: password
                });
            }
            catch (e) {
                log(e);
                throw e;
            }

        }, err => {
            log(err);
            res.sendStatus(500);
        });

    });


function log(message) {
    appInsights.client.trackTrace(message);
    console.log(message);

}

app.listen(port, function () {
    log('Example app listening on port '+port)
})