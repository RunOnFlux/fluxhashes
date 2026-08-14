const apicache = require('apicache');
const fs = require('fs');
const path = require('path');

const hashes = require('./hashes/hashes');

const cache = apicache.middleware;

// Only successful responses are cached. By default apicache stores whatever the handler returned,
// including the 404 below -- so a request arriving before the first document was published would
// pin that 404 for the full cache window, well after the document existed.
const cacheSuccess = apicache.newInstance({ statusCodes: { include: [200] } }).middleware;

const HASHLIST = path.join(__dirname, 'hashes', 'hashlist-signed.json');

module.exports = (app) => {
  // The same hash list, signed, so a consumer can verify it came from us rather than trusting this
  // server or whatever relayed the response. Served alongside the unsigned array, not instead of it.
  //
  // Must come before the catch-all below, which would otherwise answer this path with the array.
  app.get('/hashlist', cacheSuccess('5 minutes'), (req, res) => {
    fs.readFile(HASHLIST, 'utf8', (error, document) => {
      if (error) {
        // Nothing signed has been published yet. 404 rather than an empty or partial document,
        // which a caller could mistake for a valid list that simply excludes their entry.
        res.status(404).json({ error: 'no signed hash list published' });
        return;
      }
      res.type('application/json').send(document);
    });
  });

  app.get('*', cache('5 minutes'), (req, res) => {
    res.json(hashes.getHashes());
  });
};
