import https from 'https';
import fs from 'fs';

const token = process.env.PAT;
const repo = process.env.REPO || 'Sami9889/whyismycomputeronfuckingfire';
const owner = repo.split('/')[0];

function gh(path) {
  return new Promise(function (resolve, reject) {
    const req = https.request({
      hostname: 'api.github.com',
      path: '/repos/' + repo + path,
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'cache-script',
        'X-GitHub-Api-Version': '2022-11-28'
      }
    }, function (res) {
      let data = '';
      res.on('data', function (c) { data += c; });
      res.on('end', function () {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error('status ' + res.statusCode + ': ' + data.slice(0, 300)));
        }
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(20000, function () { req.destroy(new Error('timeout')); });
    req.end();
  });
}

function graphql(query, variables) {
  return new Promise(function (resolve, reject) {
    const req = https.request({
      hostname: 'api.github.com',
      path: '/graphql',
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json',
        'User-Agent': 'cache-script'
      }
    }, function (res) {
      let data = '';
      res.on('data', function (c) { data += c; });
      res.on('end', function () {
        try {
          const json = JSON.parse(data);
          if (json.errors && json.errors.length) reject(new Error(json.errors[0].message));
          else resolve(json.data || json);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(20000, function () { req.destroy(new Error('timeout')); });
    req.write(JSON.stringify({ query: query, variables: variables }));
    req.end();
  });
}

const cache = { updated_at: new Date().toISOString(), incidents: [], sponsors: [], raised_usd: 0 };

try {
  const issues = await gh('/issues?labels=thermal-incident&state=open&per_page=30');
  cache.incidents = issues
    .filter(function (i) { return !i.pull_request; })
    .map(function (i) {
      return { title: i.title, created_at: i.created_at, body: i.body || '', number: i.number };
    });
} catch (e) {
  console.log('incidents fetch failed:', e.message);
}

try {
  const data = await graphql(
    'query($login:String!){ user(login:$login){ sponsorshipsAsSponsor(first:100){ totalCount nodes{ tier{ monthly_price_in_dollars name } createdAt } } } }',
    { login: owner }
  );
  const u = data.user;
  cache.sponsor_count = u.sponsorshipsAsSponsor.totalCount || 0;
  cache.sponsors = u.sponsorshipsAsSponsor.nodes.map(function (n) {
    return { tier: n.tier ? n.tier.name || '' : '', monthly_usd: n.tier ? n.tier.monthly_price_in_dollars || 0 : 0, created_at: n.createdAt };
  });
  cache.sponsors.forEach(function (s) { cache.raised_usd += s.monthly_usd; });
} catch (e) {
  console.log('sponsors fetch failed:', e.message);
}

fs.writeFileSync('cache.json', JSON.stringify(cache, null, 2));
