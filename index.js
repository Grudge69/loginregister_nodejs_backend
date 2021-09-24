const express = require("express");
const mysql = require("mysql");
const cors = require("cors");

const app = express();

const ports = process.env.PORT || 3000;

const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "loginsystem",
  password: "Admin0502@",
});

app.post("/signup", async (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  if (password.length < 7) res.send({ message: "Password too short" });
  else {
    const hashedPassword = await bcrypt.hash(password, 12);
    console.log("Encrypted Password : " + hashedPassword);

    // check unique email address
    var sql = "SELECT * FROM users WHERE username =?";
    db.query(sql, [username], (err, data, fields) => {
      try {
        if (err) throw err;
        if (data.length > 0) {
          console.log("User exists");
          res.send({ message: "User exists" });
        } else {
          // save users data into database
          var sql =
            "INSERT INTO users (username, password, creation_date_time) VALUES (?,?,CURRENT_TIMESTAMP);";
          db.query(sql, [username, hashedPassword], (err, result) => {
            if (err) {
              res.send({ err: err });
            } else {
              res.send({ message: "Successfully Registered" });
            }
          });
        }
      } catch (err) {
        res.send({ message: err.message });
      }
    });
  }
});

app.post("/login", async (req, res) => {
  const username = req.body.username;

  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, result) => {
      try {
        if (result.length > 0) {
          const storedUser = result[0];
          console.log(storedUser);

          const password = req.body.password;

          const isEqual = await bcrypt.compare(password, storedUser.password);

          if (!isEqual) {
            const error = new Error("Wrong password!");
            error.statusCode = 401;
            throw error;
          }

          const token = jwt.sign(
            {
              username: storedUser.username,
              id: storedUser.id,
            },
            "secretortoken",
            { expiresIn: "1h" }
          );

          res.status(200).json({
            token: token,
            id: storedUser.id,
            username: storedUser.username,
          });
        } else {
          res.send({
            message: "Wrong username / password combination",
          });
        }
      } catch (err) {
        res.send({ message: err.message });
      }
    }
  );
});

app.listen(ports, () => {
  console.log(`Listening on port ${ports}`);
});
