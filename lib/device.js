const uuid = require('uuid')
const passport = require('passport')
const moment = require('moment')
const Router = require('express').Router

class DataStore {
    constructor(expiration, interval, verificationUrl) {
        this._expiration = expiration;
        this._interval = interval;
        this._verificationUrl = verificationUrl;

        this._stores = {
            device: {},
            code: {}
        }
    }

    get devices() { 
        return this._stores.device
    }

    get codes() {
        return this._stores.code
    }

    register(deviceId, codeValue) {
        this._stores.device[deviceId] = {
            expires_at: moment().add(this._expiration, 's'),
            expires_in: this._expiration,
            interval: this._interval,
            verification_url: this._verificationUrl,
            access_code: null
        }

        return this._stores.code[codeValue] = {
            device: this._stores.device[deviceId]
        }
    }
}

module.exports = (authStratName, rootUrl) => {
    const router = Router('/device')
    const store = new DataStore(1800, 5, rootUrl)

    router.get('/new', (req, res) => {
        const id = uuid()
        const userCode = uuid().substr(10, 8)

        const result = store.register(id, userCode)

        res.status(200).send({
            device_code: id,
            user_code: userCode,
            expires_in: result.device.expires_in,
            interval: result.device.interval,
            verification_url: result.device.verification_url
        })
    })

    router.get('/device_code', (req, res) => {
        const deviceCode = req.query.device_code

        if (!deviceCode) {
            return res.status(400).send({error: "malformed request"})
        }

        const entry = store.devices[deviceCode]

        if (moment().isAfter(entry.expires_at)) {
            return res.status(400).send({error: "code expired"})
        }

        if (entry.access_code) {
            const auth = entry.access_code
            delete store.devices[deviceCode]
            res.status(200).send({access_code: auth})
        } else {
            res.status(400).send({status: "pending"})
        }
    })

    const loginHandler = passport.authenticate(authStratName)
    const authHandler = (req, res, next) => {
        if (!req.isAuthenticated || !req.isAuthenticated()) {
            loginHandler(req, res, next)
        } else {
            next()
        }
    }

    // callback handler from auth provider
    router.post('/login', authHandler, (req, res) => {
        res.redirect('/device')
    })

    router.get('/login', authHandler, (req, res) => {
        res.redirect('/device')
    })

    router.get('/', authHandler, (req, res) => {
        res.send("<form action='/device/user_code' method='POST'><input type='text' name='user_code' /></form>")
    })

    router.post('/user_code', authHandler, (req, res) => {
        const userCode = req.body.user_code

        if (!userCode) {
            return res.status(400).send({error: "malformed request"})
        }

        const entry = store.codes[userCode]

        if (!entry) {
            return res.status(400).send({error: "invalid code"})
        }

        if (moment().isAfter(entry.device.expires_at)) {
            return res.status(400).send({error: "code expired"})
        }

        store.codes[userCode].device.access_code = req.user.access_token
        delete store.codes[userCode]

        res.status(200).send({status: 'OK'})
    })

    return router
}