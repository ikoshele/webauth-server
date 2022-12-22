import express from "express";
const router = express.Router();
import {UserService} from "../services/UserService.js";

router.get('/signup', function(req, res, next) {
    res.send('Register page');
});

router.post('/signup', async (req, res, next) => {
    try {
        const {username, password} = req.body
        const userInstance = new UserService();
        const user = await userInstance.register({username, password});
        res.status(201).json(user)
    } catch (e) {
        next(e)
    }

});

export {router}
