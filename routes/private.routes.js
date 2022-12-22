import express from "express";
const router = express.Router();
import {authenticateToken} from "../middlewares/authToken.js";

/* GET home page. */
router.get('/private', authenticateToken, (req, res, next) => {
  res.send('hello private');
});

export {router}
