import express from 'express';
import { voluntaryAuthenticateToken } from '../middlewares/authToken.js';
import webAuthService from '../services/WebAuthService.js';

const router = express.Router();
router.post('/generate-registration-options', voluntaryAuthenticateToken, async (req, res, next) => {
    const webAuthInstance = new webAuthService();
    const authUserName = req.user?.username;
    const { username: reqUsername } = req.body;
    try {
        const options = await webAuthInstance.generateRegistrationOptions(authUserName, reqUsername, res);
        res.json(options);
    } catch (e) {
        next(e);
    }
});

router.post('/verify-registration', voluntaryAuthenticateToken, async (req, res, next) => {
    //const {body} = req;
    const id = req.user?.id;
    const webAuthInstance = new webAuthService();
    try {
        const result = await webAuthInstance.verifyRegistration(id, req, res);
        res.send(result);
    } catch (e) {
        next(e);
    }
});

router.get('/generate-authentication-options', (req, res, next) => {
    //const {id} = req.user;
    const webAuthInstance = new webAuthService();
    try {
        const options = webAuthInstance.generateAuthenticationOptions(res);
        res.send(options);
    } catch (e) {
        next(e);
    }
});

router.post('/verify-authentication', async (req, res, next) => {
    const webAuthInstance = new webAuthService();
    try {
        const userRecord = await webAuthInstance.verifyAuthentication(req, res);
        res.json(userRecord);
    } catch (e) {
        next(e);
    }

});

export { router };
