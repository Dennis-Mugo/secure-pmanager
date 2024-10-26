const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const fs = require("fs");
const { v4 } = require("uuid");
const {
  getJsonFile,
  writeToJsonFile,
  simpleEncrypt,
  simpleDecrypt,
  verifyPassword,
} = require("./lib");
const { Keychain } = require("./password-manager");

const app = express();
const PORT = 3000;

// Middleware to parse URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware to parse JSON data
app.use(bodyParser.json());

app.use(express.static(path.join(__dirname, "public")));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "public"));

//Defineing routes
app.get("/", (req, res) => {
  return res.redirect("/signin/0");
});

app.get("/signin/:error", (req, res) => {
  const { error } = req.params;
  let data = { error: error != 0 ? error : "" };
  res.render("signin", data);
});

app.get("/signup/:error", (req, res) => {
  const data = {
    error: req.params?.error != 0 ? req.params.error : "",
  };

  res.render("signup", data);
});

app.post("/signup_submit", async (req, res) => {
  let body = req.body;
  let userId = v4();

  if (!body.password) {
    return res.redirect(
      `/signup/${encodeURIComponent("Password is required!")}`
    );
  }
  let users = getJsonFile("users.json");
  if (users[body.username]) {
    return res.redirect(
      `/signup/${encodeURIComponent("Username already exists.")}`
    );
  }

  //Add user to users.json
  users[body.username] = userId;
  writeToJsonFile("users.json", users);

  //Add a keylist.json
  writeToJsonFile(`${userId}_keys.json`, { keys: [v4()] });

  let keychain = await Keychain.init(body.password);
  //Adding a test password to help in verification during signin
  await keychain.set(v4(), v4());

  let [jsonDump, keychainHash] = await keychain.dump();
  writeToJsonFile(`${userId}.json`, JSON.parse(jsonDump));

  res.redirect(`/signin/0`);
});

app.post("/signin_submit", async (req, res) => {
  const { username, password } = req.body;
  let users = getJsonFile("users.json");
  if (!users[username]) {
    return res.redirect(
      `/signin/${encodeURIComponent("Username does not exist!")}`
    );
  }
  let userId = users[username];
  let keychainJson = JSON.stringify(getJsonFile(`${userId}.json`));
  try {
    let now = Date.now().toString();
    let encrypted = simpleEncrypt(password, now);
    writeToJsonFile("session.json", {
      pass: encrypted,
      key: now,
      userId,
      userName: username,
    });
    return res.redirect(`dashboard/${userId}/0/0`);
  } catch (e) {
    console.log(e);
    return res.redirect(`/signin/${encodeURIComponent(e)}`);
  }
});

app.post("/signout", async (req, res) => {
  writeToJsonFile("session.json", { pass: "", key: "" });
  return res.redirect("/signin/0");
});

app.get("/dashboard/:userId/:error/:success", async (req, res) => {
  let { userId, error, success } = req.params;
  let [unmaskedDomain, unmaskedValue] = ["", ""];
  const users = getJsonFile("users.json");

  let session = getJsonFile("session.json");
  if (
    !Object.values(users).includes(userId) ||
    !session?.pass ||
    !session?.key
  ) {
    return res.redirect("/signin/0");
  }
  let pass = simpleDecrypt(session.pass, session.key);

  let allKeys = getJsonFile(`${userId}_keys.json`);
  const { keys } = allKeys;

  if (error === "viewing") {
    unmaskedDomain = success;
    error = 0;
    success = 0;
    const kvs = getJsonFile(`${userId}.json`);
    try {
      let manager = await Keychain.load(pass, JSON.stringify(kvs));
      unmaskedValue = await manager.get(unmaskedDomain);
    } catch (e) {
      console.log(e);
      return res.render("dashboard", {
        session,
        error: e,
        success: "",
        keys: keys.slice(1),
        unmaskedDomain,
        unmaskedValue,
      });
    }
  }

  const data = {
    session,
    error: error != 0 ? error : "",
    success: success != 0 ? success : "",
    keys: keys.slice(1),
    unmaskedDomain,
    unmaskedValue,
  };
  res.render("dashboard", data);
});

app.post("/add_record", async (req, res) => {
  let { domain, password } = req.body;
  let { userId, pass, key } = getJsonFile("session.json");
  let keyObj = getJsonFile(`${userId}_keys.json`);
  if (keyObj.keys.includes(domain)) {
    return res.redirect(
      `/dashboard/${userId}/${encodeURIComponent(
        "The domain already exists!"
      )}/0`
    );
  }

  pass = simpleDecrypt(pass, key);

  let kvs = JSON.stringify(getJsonFile(`${userId}.json`));
  let passswordManager = await Keychain.load(pass, kvs);
  await passswordManager.set(domain, password);
  let [jsonDump, keychainHash] = await passswordManager.dump();
  writeToJsonFile(`${userId}.json`, JSON.parse(jsonDump));
  keyObj.keys.push(domain);
  writeToJsonFile(`${userId}_keys.json`, keyObj);

  return res.redirect(
    `/dashboard/${userId}/0/${encodeURIComponent(
      "Password added successfully."
    )}`
  );
});

app.get("/view_record/:domain/:pass", async (req, res) => {
  const { domain, pass } = req.params;
  const { userId } = getJsonFile("session.json");
  if (!verifyPassword(pass)) {
    return res.redirect(
      `/dashboard/${userId}/${encodeURIComponent("Incorrect password")}/0`
    );
  }
  return res.redirect(`/dashboard/${userId}/viewing/${domain}`);
});

app.get("/edit_record/:domain/:pass/:newPassword", async (req, res) => {
  const { domain, pass, newPassword } = req.params;
  const { userId } = getJsonFile("session.json");
  if (!verifyPassword(pass)) {
    return res.redirect(
      `/dashboard/${userId}/${encodeURIComponent("Incorrect password")}/0`
    );
  }

  try {
    let kvs = getJsonFile(`${userId}.json`);
    let manager = await Keychain.load(pass, JSON.stringify(kvs));
    await manager.set(domain, newPassword);
    const [jsonDump, kvHash] = await manager.dump();
    writeToJsonFile(`${userId}.json`, JSON.parse(jsonDump));
    return res.redirect(
      `/dashboard/${userId}/0/${encodeURIComponent(
        "Record updated successfully"
      )}`
    );
  } catch (e) {
    console.log(e);
    return res.redirect(`/dashboard/${userId}/${encodeURIComponent(e)}/0`);
  }
});

app.get("/remove_record/:domain/:pass", async (req, res) => {
  const { domain, pass } = req.params;
  const { userId } = getJsonFile("session.json");
  if (!verifyPassword(pass)) {
    return res.redirect(
      `/dashboard/${userId}/${encodeURIComponent("Incorrect password")}/0`
    );
  }

  try {
    //Remove from kvs
    let kvs = getJsonFile(`${userId}.json`);
    let manager = await Keychain.load(pass, JSON.stringify(kvs));
    let result = await manager.remove(domain);
    const [jsonDump, kvHash] = await manager.dump();
    writeToJsonFile(`${userId}.json`, JSON.parse(jsonDump));

    //remove from kvs keys
    let jsonKeys = getJsonFile(`${userId}_keys.json`);
    jsonKeys = jsonKeys.keys.filter((key) => key !== domain);
    writeToJsonFile(`${userId}_keys.json`, {
      keys: jsonKeys,
    });

    return res.redirect(
      `/dashboard/${userId}/0/${encodeURIComponent(
        "Record deleted successfully"
      )}`
    );
  } catch (e) {
    console.log(e);
    return res.redirect(`/dashboard/${userId}/${encodeURIComponent(e)}/0`);
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
