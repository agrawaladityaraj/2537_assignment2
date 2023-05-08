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

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/public"));
app.use("/js", express.static("./js"));

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
  if (req.session.authenticated) {
    res.render("authenticatedHome", { name: req.session.name });
  } else {
    res.render("unauthenticatedHome");
  }
});

app.get("/signup", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/");
    return;
  }

  res.render("genericAuthentication", {
    errorMessage: req.query.msg,
    title: "Sign Up",
    formAction: "/signup",
    inputs: [
      {
        id: "name",
        name: "name",
        type: "text",
        placeholder: "Name",
        label: "Name",
      },
      {
        id: "email",
        name: "email",
        type: "email",
        placeholder: "Email",
        label: "Email",
      },
      {
        id: "password",
        name: "password",
        type: "password",
        placeholder: "Password",
        label: "Password",
      },
    ],
  });
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
  await userCollection.insertOne({ name, email, password: hash, type: "user" });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.email = email;
  req.session.type = "user";
  req.session.save();
  res.redirect("/members");
});

app.get("/login", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/");
    return;
  }

  res.render("genericAuthentication", {
    errorMessage: req.query.msg,
    title: "Sign In",
    formAction: "/login",
    inputs: [
      {
        id: "email",
        name: "email",
        type: "email",
        placeholder: "Email",
        label: "Email",
      },
      {
        id: "password",
        name: "password",
        type: "password",
        placeholder: "Password",
        label: "Password",
      },
    ],
  });
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
    req.session.type = user.type;
    req.session.save();
    res.redirect("/members");
  } else {
    res.redirect(`login?msg="Email or password incorrect"`);
  }
});

app.get("/admin", async (req, res) => {
  if (!req.session.authenticated || req.session.type !== "admin") {
    res.redirect("/");
    return;
  }

  const result = userCollection
    .find({ email: { $ne: req.session.email } })
    .project({ name: 1, _id: 1, type: 1 });
  const users = await result.toArray();
  res.render("admin", { users: users });
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }

  res.render("members");
});

app.get("/logout", (req, res) => {
  mongoStore.destroy(req.session.id, () => {
    req.session.destroy();
    res.redirect("/");
  });
});

app.get("*", (_, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});

module.exports = app;
