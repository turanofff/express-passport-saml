import http from 'http';
import fs from 'fs';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import crypto from 'crypto';
import { generateBearerToken, parseState, urlDecodeBase64 } from './utils';
import config from './config/config';
import './config/passport';

const router = express();

/** Stores auth_code as a key; a challenge_code and an access_token a.k.a. bearer token */
const authStorage = new Map<string, { challenge_code: string, access_token?: string, expires: number}>();

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

/** GET route just loads welcome message */
router.get('/', (req, res, next) => {
    const body = fs.readFileSync('./src/html/welcome.html', 'utf-8');
    return res.status(200).send(body).end();
});

  
/** GET route stars authentication session with SAML Identity Provider */
router.get('/login', (req:any, res:any, next:any) => {
    const state = req?.query?.state;
    const challenge_code = req?.query?.challenge_code;

    if (state && challenge_code) {
        const samlOptions = {...config.saml.options, additionalParams: { RelayState: `${state}.${challenge_code}`} }
        passport.authenticate('saml', samlOptions)(req, res, next);
    } else {
        const body = fs.readFileSync('./src/html/no-state-error.html', 'utf-8');
        return res.status(403).send(body).end();
    }
});


/** POST route handles response from SAML Identity Provider */
router.post('/login', passport.authenticate('saml', config.saml.options), (req, res, next) => {
    const relayState = parseState(req?.body?.RelayState); // this is how we get state parameter from SAML Response
    
    const state = relayState?.state;
    const challenge_code = urlDecodeBase64(relayState?.challenge_code);

    const redirectionURL = 'complete';
    const userObject:any = req.user;

    const payloadObject = { custom: { email: userObject.nameID } }; // This is payload from SAML Request
    const access_token = generateBearerToken(payloadObject);
    const auth_code = crypto.randomBytes(12).toString('hex');

    if (challenge_code) {
        authStorage.set(auth_code, { challenge_code, access_token, expires: new Date().getTime()+5*60*1000});
        res.status(302).redirect(`${redirectionURL}?frontend=${config.frontend.baseURL}&saml=${config.frontend.samlRoute}&auth_code=${auth_code}&state=${state}`);
    } else {
        const body = fs.readFileSync('./src/html/generic-error.html', 'utf-8');
        return res.status(403).send(body).end();
    }
});

/** POST route handles exchange of auth_code and code_verifier for access token */
router.post('/token', (req, res) => {
    const auth_code = req?.body?.auth_code;
    const code_verifier = req?.body?.code_verifier;

    if (auth_code && code_verifier && authStorage.has(auth_code)) {

        const incoming_code_verifier = crypto.createHash('sha256')
            .update(code_verifier)
            .digest('base64')
            .replace(/=/g,''); // Removing padding symbols "=" 
        const stored_code_verifier = authStorage.get(auth_code)?.challenge_code;

        if (incoming_code_verifier === stored_code_verifier) {
            const access_token = authStorage.get(auth_code)?.access_token;
            authStorage.delete(auth_code);
            return res.status(200).send({
                access_token
            }).end();
        } else {
            authStorage.delete(auth_code);
            return res.status(403).send({
                error: 'Invalid verification code code'
            }).end();
        }
    } else {
        return res.status(403).send({
            error: 'Invalid or missing input params'
        }).end();
    }

});

/** GET route - presents an html page which sends authentication data back to Frontend */
router.get('/complete', (req, res) => {
    const body = fs.readFileSync('./src/html/complete.html', 'utf-8');
    return res.status(200).send(body).end();
});

/** Cleaning up expired states and auth_code */ 
setInterval(() => {
    const currentDate = new Date().getTime();
    for (const [key, value] of authStorage.entries()) {
        if (currentDate > value.expires) {
            authStorage.delete(key);
        }
      }
}, 60*1000);

httpServer.listen(config.server.port, () => console.info(`Server is running on port ${config.server.port}`));
