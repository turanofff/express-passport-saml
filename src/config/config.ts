import * as dotenv from 'dotenv'
dotenv.config()

const config = {
    saml: {
        cert: './src/config/saml.pem',
        entryPoint: process.env.SAML_ACS,
        issuer: process.env.SAML_ISSUER,
        options: {
            failureRedirect: '/',
            failureFlash: false,
        },
    },
    server: {
        port: 3000
    },
    session: {
        resave: false,
        secret: process.env.SESSION_SECRET!,
        saveUninitialized: true
    },
    frontend: {
        baseURL: process.env.FRONTEND_ENDPOINT,
        loginRoute: 'login',
        samlRoute: 'login'
    },
    jwtSecret: process.env.TOKEN_SECRET ?? ''
};

export default config;
