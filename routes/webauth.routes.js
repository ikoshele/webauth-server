import express from "express";
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

router.get('/generate-authentication-options', (req, res, next) => {
    //const {id} = req.user;
    const webAuthInstance = new webAuthService(res);
    try {
        const options = webAuthInstance.generateAuthenticationOptions();
        res.send(options);
    } catch (e) {
        next(e)
    }
});

router.post('/verify-authentication', async (req, res,next) => {
    const webAuthInstance = new webAuthService(res, req);
    try {
        const userRecord = await webAuthInstance.verifyAuthentication();
        res.json(userRecord)
    } catch (e) {
        next(e)
    }

});

export {router}
