var express = require('express');
var pg = require('pg');
var crypto = require('crypto');
var Promise = require('promise');
var passport = require("passport");
var BearerStrategy = require('passport-azure-ad').BearerStrategy;

var port = process.env.PORT || 3000;

var app = express();

var postgresConfig = {
    user: process.env.PGUSER, 
    database: process.env.PGDATABASE,
    password: process.env.PGUSER, 
    host: process.env.PGHOST, 
    port: process.env.PGPORT, 
    max: 10, // max number of clients in the pool 
    idleTimeoutMillis: 30000, // how long a client is allowed to remain idle before being closed 
    ssl: true
};


var tenantID = process.env.AAD_TENANT_ID
var clientID = process.env.AAD_CLIENT_ID;
var policyName = process.env.AAD_POLICY_NAME;

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
    next();
});


getSecret = function (realm) {
    const client = new pg.Client(postgresConfig);
    return new Promise(function (resolve, reject) {
        client.connect(function (err, client, done) {
            if (err) {
                return console.error('error fetching client from pool', err);

            }
            const query = {
                // give the query a unique name
                name: 'fetch-secret',
                text: 'SELECT * FROM turn_secret WHERE realm = $1',
                values: [realm]
            }
            client.query(query, function (err, result) {

                if (err) {
                    console.error('error running query', err);
                    reject('error running query', err);
                }
                console.log(result.rows[0]);
                resolve(result.rows[0].value)
            });

        })
    });
}


app.get('/turnCreds/:realm',
   passport.authenticate('oauth-bearer', { session: false }),
    function (req, res) {
        var claims = req.authInfo;
        console.log('User info: ', req.user);
        console.log('Validated claims: ', claims);

        var name = req.param("username") || "user";
        var realm = req.params.realm || "azturntst.org"
        getSecret(realm).then(secret => {
            console.log(secret);
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

        });
    });


app.listen(port, function () {
    console.log('Example app listening on port 3000!')
})