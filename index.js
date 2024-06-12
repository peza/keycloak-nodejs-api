import express from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import Keycloak from "keycloak-connect";
import axios from 'axios';
import jwt from 'jsonwebtoken';

const app = express();
app.use(bodyParser.urlencoded({extended: true})); // Configure for form-encoded data


const memoryStore = new session.MemoryStore();

const getConfig = {
    "realm": "MyRealm",
    "serverUrl": 'https://192.168.0.19:8443',
    "ssl-required": "external",
    "clientId": `my-client`,
    "credentials": {
        "secret": "S0m3G3n3rat3dS3cr3t"
    }
}
// avoid redirections to keycloak login window
Keycloak.prototype.redirectToLogin = function(req) {
    return false;
};

const keycloak = new Keycloak({store: memoryStore}, getConfig);


// Session Configuration
app.use(session({
    secret: 'some secret',
    resave: false,
    saveUninitialized: true,
    store: memoryStore
}));
app.use(keycloak.middleware());

// Endpoint to log in and get a token
app.post('/login', async (req, res) => {
    const {username, password} = req.body;
    if (!username || !password) {
        return res.status(400).send('username, and password must be provided');
    }

    try {
        const tokenResponse = await login(username, password);
        res.json(tokenResponse);
    } catch (error) {
        console.log(error)
        res.status(500).send('Login failed');
    }
});

function getTokenOutFromRawHeaders(req) {
    const headers = {};
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
        headers[req.rawHeaders[i].toLowerCase()] = req.rawHeaders[i + 1];
    }
    let token;
    // Check if the "Authorization" header exists
    const authorizationHeader = headers['authorization'];
    if (!authorizationHeader) {
        return null;
    } else {
        const tokenParts = authorizationHeader.split(' ');
        if (tokenParts.length !== 2 || tokenParts[0].toLowerCase() !== 'bearer') {
            return null; // Invalid authorization header format
        } else {
            return tokenParts[1];
        }
    }
}

function protector() {
    return (req, res, next) => {
        let token = getTokenOutFromRawHeaders(req);
        let decoded = jwt.decode(token, {complete: true});
        if (!decoded.payload.LinesList.includes('Lipoti')) {
            return res.status(403).send('Access denied');
        } else {
            keycloak.protect()(req, res, next);
        }
    };
}



// Endpoint to log in and get a token
app.post('/refresh', async (req, res) => {
    const {refresh_token} = req.body;
    if (!refresh_token) {
        return res.status(400).send('refresh_token must be provided');
    }

    try {
        const tokenResponse = await refresh(refresh_token);
        res.json(tokenResponse);
    } catch (error) {
        console.log(error)
        res.status(500).send('refresh token failed');
    }
});

// Protect a route
app.get('/protected', protector(), (req, res) => {
    res.send('This is a protected resource');
});

app.get('/protected1', keycloak.protect(), (req, res) => {
    res.send('This is a protected resource also');
});

// Public route
app.get('/public', (req, res) => {
    res.send('This is a public resource');
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});

const login = async (username, password) => {
    const tokenUrl = `${getConfig.serverUrl}/realms/${getConfig.realm}/protocol/openid-connect/token`;

    try {

        const response = await axios.post(tokenUrl, new URLSearchParams({
            client_id: getConfig.clientId,
            client_secret: getConfig.credentials.secret,
            username: username,
            password: password,
            grant_type: 'password'
        }))

        return response.data;
    } catch (error) {
        console.error('Error logging in:', error.response ? error.response.data : error.message);
        throw error;
    }
};
const refresh = async (refreshToken) => {
    const tokenUrl = `${getConfig.serverUrl}/realms/${getConfig.realm}/protocol/openid-connect/token`;

    try {

        const response = await axios.post(tokenUrl, new URLSearchParams({
            client_id: getConfig.clientId,
            client_secret: getConfig.credentials.secret,
            refresh_token: refreshToken,
            grant_type: 'refresh_token'
        }))

        return response.data;
    } catch (error) {
        console.error('Error refreshing token:', error.response ? error.response.data : error.message);
        throw error;
    }
};