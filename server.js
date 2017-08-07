const app = require('./lib/application')
const log = require('./lib/logger')
const port = process.env.PORT || 3000

app.listen(port, function () {
    log(`Example app listening on port ${port}`)
})