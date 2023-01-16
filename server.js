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

app.get('/', (req, res) => {
    res.send('Hello World');
});

