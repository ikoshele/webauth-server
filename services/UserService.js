import {UserModel} from "../models/user.model.js";
import bcrypt from 'bcrypt'
import jwt from "jsonwebtoken";

export class UserService {
    async register(userData) {
        try {
            const hashedPassword = userData.password ? await bcrypt.hash(userData.password,10) : null;
            const userRecord = await UserModel.create({ username: userData.username, hashedPassword: hashedPassword, name: userData.name });
            if (userRecord) {
                const  {id, username} = userRecord.dataValues
                const {accessToken, refreshToken} = this.generateToken(id, username);
                return {id, username, accessToken, refreshToken}
            }
        } catch (e) {
            throw e
        }
    }
    async signIn(userData) {
        const {username, password} = userData
        const userRecord = await UserModel.findOne({where: { username }});
        if (!userRecord) {
            throw new Error('User not found');
        }
        const isValidPassword = await bcrypt.compare(password, userRecord.hashedPassword);
        if (isValidPassword) {
            const {accessToken, refreshToken} = this.generateToken(userRecord.id, username);
            return {id: userRecord.id, username: userRecord.username, accessToken, refreshToken}
        } else {
            throw new Error('Incorrect password');
        }
    }
    generateToken(id, username) {
        const accessToken = jwt.sign({id, username}, process.env.TOKEN_SECRET, { expiresIn: '1800s' });
        const refreshToken = jwt.sign({id, username}, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '1d' });
        return {
            accessToken,
            refreshToken
        };
    }

    setRefreshTokenCookie(res, refreshToken) {
        res.cookie('jwt', refreshToken, {
            httpOnly: true,
            sameSite: 'None', secure: true,
            maxAge: 24 * 60 * 60 * 1000,
            signed: true
        });
    }

    async getUserData(userId) {
        const userRecord = await UserModel.findOne({where: { id: userId }});
        if (!userRecord) {
            throw new Error('No user found');
        }
        const {id, username, name} = userRecord
        return {id, username, name};
    }
}