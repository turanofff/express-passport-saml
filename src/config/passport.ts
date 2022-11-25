import fs from 'fs';
import passport from 'passport';
import { Strategy } from 'passport-saml';
import config from './config';

const savedUsers: Express.User[] = [];

passport.serializeUser<Express.User>((expressUser, done) => {
    console.info(expressUser, 'Serialize User');
    done(null, expressUser);
});

passport.deserializeUser<Express.User>((expressUser, done) => {
    console.info(expressUser, 'Deserialize User');

    done(null, expressUser);
});

passport.use(
    new Strategy(
        {
            issuer: config.saml.issuer,
            protocol: 'http://',
            path: '/login',
            entryPoint: config.saml.entryPoint,
            cert: fs.readFileSync(config.saml.cert, 'utf-8'),
            identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:email',
            disableRequestAcsUrl: true,
        },
        (expressUser: any, done: any) => {
            if (!savedUsers.includes(expressUser)) {
                savedUsers.push(expressUser);
            }

            return done(null, expressUser);
        }
    )
);
