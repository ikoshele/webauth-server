import express from 'express';

const router = express.Router();
import { authenticateToken } from '../middlewares/authToken.js';
import { UserService } from '../services/UserService.js';

/* GET home page. */
router.get('/profile', authenticateToken, async (req, res, next) => {
    const { id } = req.user;
    if (!id) res.sendStatus(401);
    const { getUserData } = new UserService();
    try {
        const userRecord = await getUserData(id);
        res.json({ userRecord });
    } catch (e) {
        next(e);
    }
});

export { router };
