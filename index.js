const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const expressValidator = require('express-validator');
const crypto = require('crypto');

const app = express();

const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'Assignment'
});

class User {
    constructor(email, fname, lname, password) {
        this.email = email;
        this.fname = fname;
        this.lname = lname;
        this.password = password;
    }
    async save() {
        const hashedPassword = await bcrypt.hash(this.password, 10);
        const [rows] = await db.execute('INSERT INTO users (email,fname,lname,password) VALUES (?,?,?,?)', [this.email, this.fname, this.lname, hashedPassword]);
        this.id = rows.insertId;
    }

    static async findByEmail(email) {
        const [rows] = await db.execute('INSERT INTO users where email = ?', [email]);
        if (rows.length === 0) {
            return null;
        }
        return new User(rows[0].email, rows[0].fname, rows[0].lname, rows[0].password);
    }

    async passwordComparison(password) {
        return await bcrypt.compare(password, this.password);
    }

    resetPasswordLink() {
        const resetToken = crypto.randomBytes(20).toString('hex');
        const tokenExpiration = Date.now() + 300000;

        return { resetToken, tokenExpiration };
    }

    async updatePassword(newPassword) {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.execute('UPDATE users SET password = ? where id = ?', [hashedPassword, this.id]);

    }

}

app.use(bodyParser.json());

app.post('/signup', async (req, res) => {
    const { fname, lname, email, password } = req.body;

    try {
        const oldUser = await User.findByEmail(email);
        if (oldUser) {
            return res.status(400).json({ message: 'Email already Exists' });
        }

        const newUser = new User(email, fname, lname, password);
        await newUser.save();

        res.status(200).json({ message: 'Sign Up Successfull' });
    }
    catch (err) {
        console.error(err);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.post('/Login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findByEmail(email);
        if (!user) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }

        const correct = await user.passwordComparison(password);
        if (!correct) {
            return res.status(400).json({ message: "Invalid Credentials" });
        }

        const payload = { userId: user.id };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token });
    }
    catch (err) {
        console.error;
    }
})

app.listen(3000);