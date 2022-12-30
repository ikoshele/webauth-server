import { UserModel } from '../models/user.model.js';
import bcrypt from 'bcrypt';
import { setupTokens } from './TokenService.js';

export class UserService {
    async register(userData, res) {
        const hashedPassword = userData.password ? await bcrypt.hash(userData.password, 10) : null;
        const userRecord = await UserModel.create({
            username: userData.username,
            hashedPassword: hashedPassword,
            name: userData.name
        });
        if (userRecord) {
            const { id, username } = userRecord.dataValues;
            const accessToken = await setupTokens(id, username, res);
            return {
                id,
                username,
                accessToken
            };
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
            const accessToken = await setupTokens(userRecord.id, username, res);
            return {
                id: userRecord.id,
                username: userRecord.username,
                accessToken
            };
        } else {
            throw new Error('Incorrect password');
        }
    }

    async getUserData(userId) {
        const userRecord = await UserModel.findOne({ where: { id: userId } });
        if (!userRecord) {
            throw new Error('No user found');
        }
        const { id, username, name, devices } = userRecord;
        const decodedDevices = devices.map((device) => device.credentialID = device.credentialID.toString('base64url'));
        return {
            id,
            username,
            name,
            decodedDevices
        };
    }
}