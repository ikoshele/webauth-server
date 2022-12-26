import { UserModel } from '../models/user.model.js';
import bcrypt from 'bcrypt';
import { generateToken, setRefreshTokenCookie } from './TokenService.js';

export class UserService {
    async register(userData, res) {
        const hashedPassword = userData.password ? await bcrypt.hash(userData.password, 10) : null;
        console.log(hashedPassword);
        const userRecord = await UserModel.create({
            username: userData.username,
            hashedPassword: hashedPassword,
            name: userData.name
        });
        if (userRecord) {
            const { id, username } = userRecord.dataValues;
            const { accessToken, refreshToken } = generateToken(id, username);
            setRefreshTokenCookie(res, refreshToken);
            return { id,
                username,
                accessToken };
        }
    }

    async signIn(userData, res) {
        const { username, password } = userData;
        const userRecord = await UserModel.findOne({ where: { username } });
        if (!userRecord) {
            throw new Error('User not found');
        }
        const isValidPassword = await bcrypt.compare(password, userRecord.hashedPassword);
        if (isValidPassword) {
            const { accessToken, refreshToken } = generateToken(userRecord.id, username);
            setRefreshTokenCookie(res, refreshToken);
            return { id: userRecord.id,
                username: userRecord.username,
                accessToken };
        } else {
            throw new Error('Incorrect password');
        }
    }

    async getUserData(userId) {
        const userRecord = await UserModel.findOne({ where: { id: userId } });
        if (!userRecord) {
            throw new Error('No user found');
        }
        const { id, username, name } = userRecord;
        return { id,
            username,
            name };
    }
}