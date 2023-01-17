const apicache = require('apicache');

const hashes = require('./hashes/hashes');

const cache = apicache.middleware;

module.exports = (app) => {
  app.get('*', cache('5 minutes'), (req, res) => {
    res.json(hashes.getHashes());
  });
};
