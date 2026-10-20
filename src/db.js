// Data layer: a small JSON-file store (no native dependencies, deploys anywhere).
// Only bcrypt password hashes are stored, never plain-text passwords.
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const config = require('./config');

const FILE = path.join(__dirname, '..', 'data', 'db.json');
let db;

function save() {
  fs.writeFileSync(FILE + '.tmp', JSON.stringify(db, null, 2));
  fs.renameSync(FILE + '.tmp', FILE); // atomic write
}


function seed() {
  const h = (p) => bcrypt.hashSync(p, config.bcryptRounds);
  db = {
    users: [
      { id: 1, username: 'asha', name: 'Asha Verma', role: 'customer', password: h('Asha@2026'),
        account: '501234567890', balance: 84250.75, failed: 0, lockedUntil: 0 },
      { id: 2, username: 'rohan', name: 'Rohan Iyer', role: 'customer', password: h('Rohan@2026'),
        account: '509876543210', balance: 23100.0, failed: 0, lockedUntil: 0 },
      { id: 3, username: 'admin', name: 'Bank Administrator', role: 'admin', password: h('Admin#2026'),
        account: null, balance: 0, failed: 0, lockedUntil: 0 },
    ],
    transactions: [],
  };
  db.transactions.push(
    { id: crypto.randomUUID(), userId: 1, date: new Date().toISOString(), desc: 'Salary credit', amount: 52000 },
    { id: crypto.randomUUID(), userId: 1, date: new Date().toISOString(), desc: 'Electricity bill', amount: -1840.5 },
    { id: crypto.randomUUID(), userId: 2, date: new Date().toISOString(), desc: 'Opening deposit', amount: 23100 },
  );
  save();
}

function load() {
  if (fs.existsSync(FILE)) db = JSON.parse(fs.readFileSync(FILE, 'utf8'));
  else seed();
}
load();

module.exports = {
  findUserByName: (u) => db.users.find((x) => x.username === u),
  findUserById: (id) => db.users.find((x) => x.id === id),
  findUserByAccount: (a) => db.users.find((x) => x.account === a),
  listUsers: () => db.users,
  txFor: (userId) => db.transactions.filter((t) => t.userId === userId).slice(-20).reverse(),
  addTx: (t) => db.transactions.push({ id: crypto.randomUUID(), date: new Date().toISOString(), ...t }),
  save,
};
