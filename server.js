require("dotenv").config();
const express = require("express");
const { JsonDB } = require("node-json-db");
const { Config } = require("node-json-db/dist/lib/JsonDBConfig");
const uuid = require("uuid");
const speakeasy = require("speakeasy");

const app = express();

// The second argument is used to tell the DB to save after each push
// If you put false, you'll have to call the save() method.
// The third argument is to ask JsonDB to save the database in an human readable format. (default false)
// The last argument is the separator. By default it's slash (/)
var db = new JsonDB(new Config("myDataBase", true, false, "/"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/api", (req, res) => {
  res.status(200).json({ message: "Welcome To The 2FA Exmaple!!" });
});

app.post("/api/register", (req, res) => {
  try {
    const id = uuid.v4();
    const path = `/user/${id}`;

    // Create temporary secret until it it verified
    const temp_secret = speakeasy.generateSecret();

    // Create user in the database
    db.push(path, { id, temp_secret });

    // Send user id and base32 key to user
    res.status(200).json({ id, secret: temp_secret.base32 });
  } catch (e) {
    res.status(500).json({ message: "Error generating secret key" });
    console.log(e);
  }
});

app.post("/api/verify", (req, res) => {
  const { userId, token } = req.body;
  try {
    // Retrieve user from database
    const path = `/user/${userId}`;
    const user = db.getData(path);
    console.log({ user });
    const { base32: secret } = user.temp_secret;
    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
    });

    if (verified) {
      // Update user data
      db.push(path, { id: userId, secret: user.temp_secret });
      res.status(200).json({ verified: true });
    } else {
      res.status(400).json({ verified: false });
    }
  } catch (err) {
    res.status(500).json({ message: "Error retrieving user." });
    console.log(err.message);
  }
});

app.post("/api/validate", (req, res) => {
  const { userId, token } = req.body;
  try {
    // Retrieve user from database
    const path = `/user/${userId}`;
    const user = db.getData(path);
    console.log({ user });
    const { base32: secret } = user.secret;

    // Returns true if the token matches
    const tokenValidates = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (tokenValidates) {
      res.status(200).json({ validated: true });
    } else {
      res.status(400).json({ validated: false });
    }
  } catch (err) {
    res.status(500).json({ message: "Error retrieving user." });
    console.log(err.message);
  }
});

const port = 3000;

app.listen(port, () => {
  console.log(`App is running on PORT: ${port}.`);
});
