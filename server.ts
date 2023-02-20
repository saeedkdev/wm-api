require('dotenv').config();
import express from 'express';
// const mongoose = require('mongoose');
import mongoose, {ConnectOptions} from 'mongoose';
// const jwt = require('jsonwebtoken');
import jwt from 'jsonwebtoken';
// const bcrypt = require('bcryptjs');
import bcrypt from 'bcryptjs';

const app : express.Application = express();
// const bodyParser = require('body-parser');
import bodyParser from 'body-parser';
// const upload = multer(); // for parsing multipart/form-data

app.use(bodyParser.json());

const port : number = 3000;
const hostname = process.env.HOSTNAME || 'localhost';
const token_secret : string = process.env.TOKEN_SECRET || '';

app.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
});

const mongoUrl : string = process.env.MONGO_URL || '';

mongoose.connect(
    mongoUrl, {},
    () => {
        console.log('Connected to DB');
    });

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    email: { type: String, required: true },
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

const noteSchema = new mongoose.Schema({
    created_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

const Note = mongoose.model('Note', noteSchema);

const blockSchema = new mongoose.Schema({
    note: { type: mongoose.Schema.Types.ObjectId, ref: 'Note' },
    type: { type: String, required: true },
    properties: { type: Object, required: true },
}, { timestamps: true });

const Block = mongoose.model('Block', blockSchema);

app.get('/', (_req, _res) => {
    _res.send('Hello World');
});

app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
        username,
        password: hashedPassword,
        email,
    });

    try {
        await user.save();
        res.send('User created');
    } catch (err) {
        res.send(err);
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log(email);
    const user = await User.findOne({ email });
    console.log(user);

    if (!user) return res.send('User not found');

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.send('Invalid Login Information');

    const token = jwt.sign({ _id: user._id }, token_secret);
    if (!token) return res.send('Token not valid');

    res.header('auth-token', token).send(token);
});

function validateToken(req:any, res:any, next:any) {
    const authToken = req.header('auth-token');
    const token = authToken && authToken.split(' ')[1];
    if (!token) return res.status(401).send('Access Denied');

    jwt.verify(token, token_secret, (err:any, user:any) => {
        if (err) return res.status(403).send('Invalid Token');
        req.user = user;
        next();
    });
}

app.get('/notes', validateToken, async (req, res) => {
    // const notes = await Note.find({ user: req.user._id });
    // res.send(notes);
});