import express from "express";
import {UserService} from "../services/UserService.js";
const router = express.Router();

/* GET home page. */
router.get('/login', function(req, res, next) {
    res.send('Login page');
});

router.post('/login', async (req, res, next) => {
    try {
        const {username, password} = req.body
        const userInstance = new UserService();
        const user = await userInstance.signIn({username, password});
        res.status(200).json(user)
    } catch (e) {
        next(e)
    }
})

export {router}
