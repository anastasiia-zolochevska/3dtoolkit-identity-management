var express = require('express');
var pg = require('pg');
var crypto = require('crypto');
var Promise = require('promise');
var passport = require("passport");
var BearerStrategy = require('passport-azure-ad').BearerStrategy;
var appInsights = require('applicationinsights');
appInsights.setup().setAutoCollectExceptions(true).start();


var port = process.env.PORT || 3000;

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

var tenantID = process.env.AAD_TENANT_ID || "3dtoolkit.onmicrosoft.com";
var clientID = process.env.AAD_APPLICATION_ID || "aacf1b7a-104c-4efe-9ca7-9f4916d6b66a";
var policyName = process.env.AAD_B2C_POLICY_NAME || "b2c_1_signup";

var authOptions = {
    identityMetadata: "https://login.microsoftonline.com/" + tenantID + "/v2.0/.well-known/openid-configuration",
    clientID: clientID,
    policyName: policyName,
    isB2C: true,
    validateIssuer: true,
    loggingLevel: 'info',
    passReqToCallback: false
};

var bearerStrategy = new BearerStrategy(authOptions,
    function (token, done) {
        // Send user info using the second argument
        done(null, {}, token);
    }
);

passport.use(bearerStrategy);

app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Authorization, Origin, X-Requested-With, Content-Type, Accept");

    if (req.method == 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});




app.all('*', function (req, res, next) {
    if (process.env.AUTH_DISABLED) {
        log("----------AUTH_DISABLED--------")
        next();
    }
    else {
        passport.authenticate('oauth-bearer', function (err, user, info) {
            if (user) {
                var claims = req.authInfo;
                log('User info: ', req.user);
                log('Validated claims: ', claims);
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
    log('Example app listening on port 3000!')
})