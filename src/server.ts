import http from 'http';
import fs from 'fs';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import config from './config/config';
import './config/passport';

const router = express();

/** Server Handling */
const httpServer = http.createServer(router);

/** Log the request */
router.use((req, res, next) => {
    console.info(`METHOD: [${req.method}] - URL: [${req.url}] - IP: [${req.socket.remoteAddress}]`);

    res.on('finish', () => {
        console.info(`METHOD: [${req.method}] - URL: [${req.url}] - STATUS: [${res.statusCode}] - IP: [${req.socket.remoteAddress}]`);
    });

    next();
});

/** Parse the body of the request / Passport */
router.use(session(config.session));
router.use(passport.initialize());
router.use(passport.session());
router.use(express.urlencoded({ extended: false }));
router.use(express.json()); 

/** Rules of our API */
router.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.header('origin'));
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');

    if (req.method == 'OPTIONS') {
        res.header('Access-Control-Allow-Methods', 'PUT, POST, PATCH, DELETE, GET');
        return res.status(200).json({});
    }

    next();
});

/** GET route stars authentication session with SAML Identity Provider */
router.get('/login', passport.authenticate('saml', config.saml.options), (req, res, next) => {
    return res.redirect(`${config.frontend.baseURL}/${config.frontend.loginRoute}`);
});


/** POST route handles response from SAML Identity Provider */
router.post('/login', passport.authenticate('saml', config.saml.options), (req, res, next) => {
    const redirectionURL = 'complete';
    const userObject:any = req.user;
    // Creating demo bearer token
    const payloadObject = { custom: { email: userObject.nameID } };
    const jwtObject = {
        alg: 'eyJhbGciOiJIUzI1NiJ9',
        payload: Buffer.from(JSON.stringify(payloadObject)).toString('base64'),
        signature: '3Yr6cayJai6LPPYe85i_WWx3cU'
    }
    const access_token=`${jwtObject.alg}.${jwtObject.payload}.${jwtObject.signature}`;
    res.status(302).redirect(`${redirectionURL}?frontend=${config.frontend.baseURL}&saml=${config.frontend.samlRoute}&access_token=${access_token}`);
});

/** GET route - presents an html page which sends authentication data back to Frontend */
router.get('/complete', (req, res, next) => {
    const body = fs.readFileSync('./src/html/complete.html', 'utf-8');
    return res.status(200).send(body).end();
});

httpServer.listen(config.server.port, () => console.info(`Server is running on port ${config.server.port}`));
