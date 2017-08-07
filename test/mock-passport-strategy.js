const passport = require('passport')
const util = require('util')

function MockStrategy(verify) {
    this._verify = verify
    passport.Strategy.call(this)

    this.name = 'mock'
}

util.inherits(MockStrategy, passport.Strategy)

MockStrategy.prototype.authenticate = function (req, opts) {
    this._verify(req, this)
}

module.exports = MockStrategy