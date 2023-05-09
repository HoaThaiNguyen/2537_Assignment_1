require("./utils.js");
require('dotenv').config();

const express = require('express');
const app = express();

const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require("joi");
const saltRounds = 10;

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)
const port = process.env.PORT || 1520;

/* secret stuff */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* end of secret stuff */

var {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

console.log(`mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`);

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
    if (!req.session.authenticated) {
        var html = `
        <button href="/signup"> Sign up </button> <br>
        <button href="/login"> Log in </button>
        `;
        res.send(html);
    } else {
        var html = `
        Hello Name! <br>
        <button href="/members"> Go to Members Area </button> <br>
        <button href="/logout"> Logout </button>
        `;
        res.send(html);
    }
});

app.get('/signup', (req,res) => {
    var html = `
    create user!
    <form action='/signUpUser' method='post'>
        <input name='username' type='text' placeholder='username'> <br>
        <input name='email' type='email' placeholder='email'> <br>
        <input name='password' type='password' placeholder='password'> <br>
    <button> Submit </button>
    </form>
    `;
    res.send(html);
});

app.post('/signUpUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().alphanum().required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   //res.send(html);
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, password: hashedPassword});
	console.log("Inserted user");

    res.redirect('/members');
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 