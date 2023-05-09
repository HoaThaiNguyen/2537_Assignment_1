require("./utils.js");
require('dotenv').config(); //needed for secret encryption

const express = require('express');
const app = express();

const session = require('express-session'); //session
const MongoStore = require('connect-mongo'); //database

const bcrypt = require('bcrypt'); //encrypting password
const Joi = require("joi"); //checking matching password
const saltRounds = 10;

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour (hours * minutes * seconds * millis)
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

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));

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
        res.render("index");
    } else {
        res.render("logInUserIsIn", {username: req.session.username});
    }
});

app.get('/signup', (req,res) => {
    res.render("signUp");
});

app.post('/signUpUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object({
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().required(),
			password: Joi.string().max(20).required()
	    }
    );

	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
        res.render("signUpError", {error: validationResult.error.message});
    } else {
        var hashedPassword = await bcrypt.hash(password, saltRounds);
        await userCollection.insertOne({username: username, password: hashedPassword, user_type: "user"});
        console.log("Inserted user");
        req.session.authenticated = true;
        req.session.username = username;
        res.redirect("/");
    }
});

app.get('/login', (req,res) => {
    res.render("logIn");
});

app.post('/logInUser', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        res.render("logInError");
        return;
    }

    const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();
	if (result.length != 1) {
        res.render("userNotFound");
        return;
	}
	else if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = username;
		req.session.cookie.maxAge = expireTime;
        await userCollection.updateOne({username: 'Hoa'}, {$set: {user_type: 'admin'}});
		res.redirect('/');
		return;
	} else {
        res.render("logInIncorrectPassword");
	}
});

app.get('/members', (req,res) => {
    if (req.session.authenticated) {
        const images = [
            "Jacq.jpg",
            "Miriam.jpg",
            "Nemona.jpg"
        ]
        res.render("members", {username: req.session.username, imageList: images});
    } else {
        res.redirect("/");
    }
});

app.get('/about', (req,res) => {
    var color = req.query.color;
    res.render("about", {color: color});
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1, _id: 1}).toArray();
 
    res.render("admin", {users: result});
});

function sessionValidation(req,res,next) {
    if (req.session.authenticated) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("adminUnauthorize");
        return;
    }
    else {
        next();
    }
}

function isAdmin(req) {
    console.log(req.session.user_type);
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.render('logOut');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 