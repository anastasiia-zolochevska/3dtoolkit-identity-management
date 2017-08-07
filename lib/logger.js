var appInsights = require('applicationinsights');

process.env.APPINSIGHTS_INSTRUMENTATIONKEY = process.env.APPINSIGHTS_INSTRUMENTATIONKEY || "NO_APPLICATION_INSIGHTS";
appInsights.setup().setAutoCollectExceptions(true).start();

module.exports = (message) => {
    appInsights.client.trackTrace(message);
    console.log(message);
}