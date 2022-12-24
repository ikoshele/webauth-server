import express from "express";
import {UserService} from "../services/UserService.js";
import jwt from "jsonwebtoken";

const router = express.Router();

/* GET home page. */
router.get('/login', function (req, res, next) {
    res.send('Login page');
});

router.post('/login', async (req, res, next) => {
    try {
        const {username, password} = req.body
        const userInstance = new UserService();
        const {refreshToken, ...user} = await userInstance.signIn({username, password});
        userInstance.setRefreshTokenCookie(res, refreshToken);
        res.status(200).json(user)
    } catch (e) {
        next(e)
    }
});

router.get('/signup', function(req, res, next) {
    res.send('Register page');
});

router.post('/signup', async (req, res, next) => {
    try {
        const {username, password, name} = req.body
        const userInstance = new UserService();
        const {refreshToken, ...user} = await userInstance.register({username, password, name});
        userInstance.setRefreshTokenCookie(res, refreshToken);
        res.status(201).json(user)
    } catch (e) {
        next(e)
    }
});

router.post('/token-refresh', async (req, res, next) => {
    try {
        const refreshToken = req.signedCookies.jwt;
        console.log(refreshToken)
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403)
            }
            const {generateToken} = new UserService();
            const {accessToken} = generateToken();
            res.status(200).json(accessToken)
        });
        next();
    } catch (e) {
        next(e)
    }
});

export {router}
