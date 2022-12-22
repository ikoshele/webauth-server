import {UserModel} from "../models/user.model.js";
import bcrypt from 'bcrypt'
import jwt from "jsonwebtoken";

export class UserService {
    async register(userData) {
        try {
            const hashedPassword = userData.password ? await bcrypt.hash(userData.password,10) : null;
            const userRecord = await UserModel.create({ username: userData.username, hashedPassword: hashedPassword });
            if (userRecord) {
                const  {id, username} = userRecord.dataValues
                const token = this.generateToken(username)
                return {id, username, token}
            }
        } catch (e) {
            throw e
        }
    }
    async signIn(userData) {
        const {username, password} = userData
        const userRecord = await UserModel.findOne({where: { username }});
        if (!userRecord) {
            throw new Error('User not registered');
        }
        const isValidPassword = await bcrypt.compare(password, userRecord.hashedPassword);
        if (isValidPassword) {
            const token = this.generateToken(username)
            return {id: userRecord.id, username: userRecord.username, token}
        } else {
            throw new Error('Incorrect password');
        }
    }
    generateToken(username) {
        const today = new Date();
        const exp = new Date(today);
        exp.setDate(today.getDate() + 60);
        return jwt.sign({username}, process.env.TOKEN_SECRET, { expiresIn: '1800s' });
    }
}