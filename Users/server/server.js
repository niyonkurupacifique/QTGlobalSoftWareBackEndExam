
var app = express();
// var sql = require("mssql");
import router from './routerr.js';
import express from 'express';
import cors from 'cors';
import * as dotenv from 'dotenv'
dotenv.config()
app.use(cors()); // Enable CORS for all routes
app.use(express.json()); // Add this line before your route handlers


app.use(router)

var server = app.listen(5000, function () {
    console.log('Server is running on http://localhost:5000');
});
