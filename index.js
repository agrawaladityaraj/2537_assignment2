require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = require("./db.js");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/public"));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
  ttl: expireTime / 1000,
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: expireTime },
  })
);

app.get("/", (req, res) => {
  let html;
  if (req.session.authenticated) {
    html = `<h1>Hello, ${req.session.name}</h1>
    <br />
    <a href="/members"><button>Members area</button></a>
    <a href="/logout"><button>Logout</button></a>`;
  } else {
    html = `<a href="/login"><button>Log In</button></a>
    <a href="/signup"><button>Sign Up</button></a>`;
  }
  res.send(html);
});

app.get("/signup", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/");
    return;
  }

  const { msg } = req.query;

  var html = `<div>Sign Up:</div>
  <br />
  <form action='/signup' method='post'>
  <input name='name' type='text' placeholder='name'>
  <input name='email' type='email' placeholder='email'>
  <input name='password' type='password' placeholder='password'>
  <button>Submit</button>
  </form>
  ${
    msg
      ? `
    <br />
    <div style="color:red;">${msg}</div>`
      : ""
  }`;
  res.send(html);
});

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().required().email(),
    password: Joi.string().required(),
  });

  const validation = schema.validate({ name, email, password });

  if (validation.error != null) {
    res.redirect(`/signup?msg=${validation.error.details[0].message}`);
    return;
  }

  const hash = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hash });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;
  req.session.save();
  res.redirect("/members");
});

app.get("/login", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/");
    return;
  }

  const { msg } = req.query;

  var html = `<div>Log In:</div>
  <br />
  <form action='/login' method='post'>
  <input name='email' type='email' placeholder='email'>
  <input name='password' type='password' placeholder='password'>
  <button>Submit</button>
  </form>
  ${
    msg
      ? `
    <br />
    <div style="color:red;">${msg}</div>`
      : ""
  }`;
  res.send(html);
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().required().email(),
    password: Joi.string().required(),
  });

  const validation = schema.validate({ email, password });

  if (validation.error != null) {
    res.redirect(`/login?msg=${validation.error.details[0].message}`);
    return;
  }

  const user = await userCollection.findOne({ email });

  if (!user) {
    res.redirect(`login?msg="User not found"`);
    return;
  }

  if (await bcrypt.compare(password, user.password)) {
    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = email;
    req.session.save();
    res.redirect("/members");
  } else {
    res.redirect(`login?msg="Email or password incorrect"`);
  }
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }
  const random = getRandomInt(3);
  const html = `<h1>Hello, ${req.session.name}</h1>
  <br />
  <image style="width:500px" src="/cat${random}.jpg" alt="cat${random}" />
  <br />
  <a href="/logout"><button>Logout</button></a>`;
  res.send(html);
});

app.get("/logout", (req, res) => {
  mongoStore.destroy(req.session.id, () => {
    req.session.destroy();
    res.redirect("/");
  });
});

app.get("*", (_, res) => {
  res.status(404);
  res.send("<h1>Page not found - 404</h1>");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});

function getRandomInt(max) {
  return Math.floor(Math.random() * max) + 1;
}

module.exports = app;
