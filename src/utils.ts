import jwt from 'jsonwebtoken';
import config from './config/config';

/** Decodes URL safe chars into Base64 allowed chars */
export const urlDecodeBase64 = (input: string) => {
    const b64Chars: { [index: string]: string } = { '-': '+', '_': '/' };
    try {
      return decodeURIComponent(
        Buffer.from(input).toString()
          .split('')
          .map(c => {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
          })
          .join('')
      ).replace(/[-_.]/g, (m: string) => b64Chars[m]);
    }
    catch(err) {
      // Do nothing cuz we couldn't parse url component
    }
  }

/** Creates a bearer token */
export const generateBearerToken = (payload: any) => {
  return jwt.sign(payload, config.jwtSecret, { expiresIn: '1800s' });
}

export const parseState = (payload: any) => {
  try {
    return JSON.parse(decodeURIComponent(payload));
  } catch (err) {
    // Do nothing cuz we couldn't parse url component
  }
}