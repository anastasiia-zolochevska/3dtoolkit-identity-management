const assert = require('assert')
const supertest = require('supertest')
const express = require('express')
const passport = require('passport')
const bodyParser = require('body-parser')
const uuid = require('uuid/v4')
const app = require('../lib/application')
const device = require('../lib/device')
const MockStrategy = require('./mock-passport-strategy')

describe('3dtoolkit-identity-management', () => {
    describe('Device', () => {
        it('should be able to start oauth2 device flow', (done) => {
            supertest(app)
                .get('/device/new')
                .expect('Content-Type', /json/)
                .expect(200)
                .then((res) => {
                    assert(res.body.device_code !== 'undefined')
                    assert(res.body.user_code !== 'undefined')
                    assert(res.body.expires_in !== 'undefined')
                    assert(res.body.interval !== 'undefined')
                    assert(res.body.verification_url !== 'undefined')
                })
                .then(done, done)
        })

        it('should be able to poll oauth2 device flow', (done) => {
            const tester = supertest(app)
            
            tester
                .get('/device/new')
                .expect('Content-Type', /json/)
                .expect(200)
                .then((res) => {
                    assert(res.body.device_code !== 'undefined')

                    return res.body.device_code
                })
                .then((deviceCode) => {
                    return tester
                        .get(`/device/device_code?device_code=${deviceCode}`)
                        .expect(400, {status: "pending"})
                        .then((res) => {/* mask response object on sucess */})
                })
                .then(done, done)
        })

        const buildDeviceAuthMock = (success) => {            
            const app = require('express')()

            passport.serializeUser((user, done) => {
                return done(null, user)
            })

            passport.deserializeUser((id, done) => {
                return done(null, {})
            })

            passport.use(new MockStrategy((req, self) => {
                if (success) {
                    self.success({access_token: uuid()}, {})
                } else {
                    self.fail({})
                }
            }))
            
            app.use(bodyParser.urlencoded({ extended: true }))
            app.use(passport.initialize())

            app.use('/device', device('mock', 'test'))

            return app
        }

        it('should be prompted to login', (done) => {
            supertest(buildDeviceAuthMock())
                .get('/device')
                .expect(401, done)
        })

        it('should be able to login', (done) => {
            supertest(buildDeviceAuthMock(true))
                .get('/device')
                .expect(200, done)
        })

        it('should be served the code form', (done) => {
            supertest(buildDeviceAuthMock(true))
                .get('/device')
                .expect(200,"<form action='/device/user_code' method='POST'><input type='text' name='user_code' /></form>", done)
        })

        it('should be able to submit a valid code', (done) => {
            const tester = supertest(buildDeviceAuthMock(true))
            
            tester
                .get('/device/new')
                .expect('Content-Type', /json/)
                .expect(200)
                .then((res) => {
                    assert(res.body.user_code !== 'undefined')
                    
                    return res.body.user_code
                })
                .then((userCode) => {
                    return tester
                        .post('/device/user_code')
                        .send(`user_code=${userCode}`)
                        .expect(200)
                        .then((res) => { /* mask response object on sucess */})
                })
                .then(done, done)
        })

        it('should poll a valid code after submission', (done) => {
            const tester = supertest(buildDeviceAuthMock(true))
            
            tester
                .get('/device/new')
                .expect('Content-Type', /json/)
                .expect(200)
                .then((res) => {
                    assert(res.body.user_code !== 'undefined')
                    assert(res.body.device_code !== 'undefined')
                    
                    return [res.body.user_code, res.body.device_code]
                })
                .then((arr) => {
                    const userCode = arr[0]
                    const deviceCode = arr[1]

                    return tester
                        .post('/device/user_code')
                        .send(`user_code=${userCode}`)
                        .expect(200)
                        .then((res) => { return deviceCode })
                })
                .then((deviceCode) => {
                    return tester
                        .get(`/device/device_code?device_code=${deviceCode}`)
                        .expect(200, /access_code/)
                        .then((res) => {/* mask response object on sucess */})
                })
                .then(done, done)
        })

        it('should allow codes only once', (done) => {
            const tester = supertest(buildDeviceAuthMock(true))
            
            tester
                .get('/device/new')
                .expect('Content-Type', /json/)
                .expect(200)
                .then((res) => {
                    assert(res.body.user_code !== 'undefined')
                    
                    return res.body.user_code
                })
                .then((userCode) => {
                    return tester
                        .post('/device/user_code')
                        .send(`user_code=${userCode}`)
                        .expect(200)
                        .then((res) => { return userCode })
                })
                .then((userCode) => {
                    return tester
                        .post('/device/user_code')
                        .send(`user_code=${userCode}`)
                        .expect(400, /invalid code/)
                        .then((res) => { /* mask response object on sucess */})
                })
                .then(done, done)
        })
    })
})