import express from "express";
import {UserService} from "../services/UserService.js";
import jwt from "jsonwebtoken";
import {authenticateToken} from "../middlewares/authToken.js";
import webAuthService from "../services/WebAuthService.js";

const router = express.Router();
router.get('/generate-registration-options', authenticateToken, async (req, res, next) => {
    const webAuthInstance = new webAuthService();
    const {id} = req.user;
    try {
        const options = await webAuthInstance.generateRegistrationOptions(id);
        res.json(options);
    } catch (e) {
        next(e)
    }
});

router.post('/verify-registration',  authenticateToken, async (req, res, next) => {
    const { body } = req;
    const {id} = req.user;
    const webAuthInstance = new webAuthService();
    try {
        const result = await webAuthInstance.verifyRegistration(body, id);
        const verifiedRes = webAuthInstance.resultVerifyHandler(result)
        res.send(verifiedRes)
    } catch (e) {
        next(e)
    }

});

router.get('/generate-authentication-options', (req, res) => {
    const webAuthInstance = new webAuthService();
    const options = webAuthInstance.generateAuthenticationOptions();
    res.send(options);
});

router.post('/verify-authentication', async (req, res) => {
    const webAuthInstance = new webAuthService();
    const body = req.body;
    const result = await webAuthInstance.verifyAuthentication(body);

    const verifiedRes = webAuthInstance.resultVerifyHandler(result)
    res.send(verifiedRes)
});

export {router}
