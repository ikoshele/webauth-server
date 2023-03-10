import express from 'express';
import { UserService } from '../services/UserService.js';
import jwt from 'jsonwebtoken';
import { generateToken } from '../services/TokenService.js';

const router = express.Router();

/* GET home page. */
router.get('/login', function (req, res) {
    res.send('Login page');
});

router.post('/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;
        const userInstance = new UserService();
        const user = await userInstance.signIn({
            username,
            password
        }, res);
        return res.status(200).json(user);
    } catch (e) {
        return next(e);
    }
});

router.get('/signup', function (req, res) {
    res.send('Register page');
});

router.post('/signup', async (req, res, next) => {
    try {
        const { username, password, name } = req.body;
        const userInstance = new UserService();
        const user = await userInstance.register({
            username,
            password,
            name
        }, res);
        return res.status(201).json(user);
    } catch (e) {
        return next(e);
    }
});

router.post('/token-refresh', async (req, res, next) => {
    try {
        const refreshToken = req.signedCookies.jwt;
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            const { accessToken } = generateToken(user.id, user.username);
            return res.status(200).json(accessToken);
        });
    } catch (e) {
        next(e);
    }
});

export { router };
