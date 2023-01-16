require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const bodyParser = require('body-parser');
// const upload = multer(); // for parsing multipart/form-data

app.use(bodyParser.json());

const port = process.env.PORT || 3000;
const hostname = process.env.HOSTNAME || 'localhost';

app.listen(port, hostname, () => {
    console.log(`Server running at http://${hostname}:${port}/`);
});

mongoose.connect(
    process.env.MONGO_URL,
    { useNewUrlParser: true },
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

app.get('/', (req, res) => {
    res.send('Hello World');
});

