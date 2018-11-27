const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs')
const session = require('express-session')
const KnexSessionStore = require('connect-session-knex')(session)

const db = require('./database/dbConfig.js');

const server = express();

const sessionConfig = {
  secret: 'asudn287348dfnanddsfj894u43',
  cookie: {
    maxAge: 1000 * 60 * 4800,
    secure: false // only send it over https if true; if production you want this to be true
  },
  httpOnly: true, //no js can touch this cookie
  resave: false,
  saveUninitialized: false,
  store: new KnexSessionStore({
      tablename: 'sessions',
      sidfieldname: 'sid',
      knex: db,
      createtable: true,
      clearInterval: 1000 * 60 * 60
  })
}

server.use(session(sessionConfig)); //wires up session management
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send('Its Alive!');
});

const protected = function(req, res, next) {
  if(req.session && req.session.username) {
    next();
  } else {
    res.status(401).json({ message: 'Please log in' })
  }
}

server.post('/register', (req, res) => {
  const credentials = req.body;

  //hash the password
  const hash = bcrypt.hashSync(credentials.password, 14);
  credentials.password = hash;
  //save the user
  db('users')
  .insert(credentials)
  .then(ids => {
    const id = ids[0]
    res.status(201).json({ newUserId: id })
  })
  .catch(err => {
    res.status(500).json(err)
  })
})

server.post('/login', (req, res) => {
  const creds = req.body

  db('users')
    .where({ username: creds.username })
    .first()
    .then(user => {
      if(user && bcrypt.compareSync(creds.password, user.password)) {
        req.session.username = user.username;
        res.status(200).json({ welcome: user.username })
      } else {
        res.status(401).json({ message: 'Error logging in' })
      }
    })
    .catch(err => {
      res.status(500).json({ err })
    })
})

server.get('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if(err) {
        res.status(404).status({ err })
      } else {
        res.status(200).json({ message: 'You are now logged out' })
      }
    })
  }
})

// protect this route, only authenticated users should see it
server.get('/users', protected, (req, res) => {
    db('users')
    .select('id', 'username', 'password')
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.listen(3300, () => console.log('\nrunning on port 3300\n'));
