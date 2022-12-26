import {
    generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse
} from '@simplewebauthn/server';
import base64url from 'base64url';
import { UserModel } from '../models/user.model.js';
import { v4 as uuidv4 } from 'uuid';
import cache from '../loaders/cache.js';
import { generateToken, setRefreshTokenCookie, setupTokens } from './TokenService.js';

export default class webAuthService {
    constructor() {
        this.rpName = 'SimpleWebAuthn Example';
        this.rpID = 'localhost';
        this.origin = 'http://localhost:5173';
    }

    async getUserFromDb(username) {
        const userRecord = await UserModel.findOne({ where: { username: username } });
        if (!userRecord) {
            throw new Error('User not found');
        }
        return userRecord;
    }

    async generateRegistrationOptions(authUserName, reqUsername, res) {
        if (!authUserName && !reqUsername) throw new Error('Please specify username');
        if (!authUserName && reqUsername) {
            const userRecord = await UserModel.findOne({ where: { username: reqUsername } });
            if (userRecord) {
                throw new Error('Select another username');
            }
        }
        const generatedUser = {
            username: reqUsername,
            devices: []
        };
        const user = authUserName ? await this.getUserFromDb(authUserName) : generatedUser;

        const {
            /**
             * The username can be a human-readable name, email, etc... as it is intended only for display.
             */
            username, devices,
        } = user;
        const options = generateRegistrationOptions({
            rpName: this.rpName,
            rpID: this.rpID,
            userID: username,
            userName: username, // Don't prompt users for additional information about the authenticator
            // (Recommended for smoother UX)
            attestationType: 'none', // Prevent users from re-registering existing authenticators
            excludeCredentials: devices.map(dev => ({
                id: dev.credentialID,
                type: 'public-key',
                transports: dev.transports,
            })),
            authenticatorSelection: {
                // "Discoverable credentials" used to be called "resident keys". The
                // old name persists in the options passed to `navigator.credentials.create()`.
                residentKey: 'required',
                userVerification: 'preferred',
            },
        });

        /**
         * The server needs to temporarily remember this value for verification, so don't lose it until
         * after you verify an authenticator response.
         */
        const sessionId = this.setSessionId(res);
        cache.set(sessionId, {
            username,
            devices,
            challenge: options.challenge
        }, 1800);
        return options;
    }

    async verifyRegistration(userId, req, res) {
        let user = this.getCacheOnce(req.signedCookies.sessionId);
        let createdUser;
        const userRequest = req.body;
        const expectedChallenge = user.challenge;

        const { verified, registrationInfo } = await verifyRegistrationResponse({
            credential: userRequest,
            expectedChallenge,
            expectedOrigin: this.origin,
            expectedRPID: this.rpID,
            requireUserVerification: true
        });

        if (verified && registrationInfo) {
            const { credentialPublicKey, credentialID, counter } = registrationInfo;

            const existingDevice = user.devices.find(device => device.credentialID.equals(credentialID));

            if (!existingDevice) {
                /**
                 * Add the returned device to the user's list of devices
                 */
                const newDevice = {
                    credentialPublicKey,
                    credentialID,
                    counter,
                    transports: userRequest.transports,
                };
                if (userId) {
                    await UserModel.update({ devices: [newDevice, ...user.devices] }, { where: { id: userId } });
                } else {
                    createdUser = await UserModel.create({
                        username: user.username,
                        devices: [newDevice]
                    });
                }
            }
        }
        this.resultVerifyHandler(verified);
        if (createdUser) {
            const { id, username } = createdUser;
            const accessToken = await setupTokens(id, username, res);
            return {
                id,
                username,
                accessToken,
                verified
            };
        }
        return {
            verified
        };
    }

    generateAuthenticationOptions(res) {
        const opts = {
            timeout: 60000,
            allowCredentials: undefined,
            userVerification: 'required',
            rpID: this.rpID,
        };

        const options = generateAuthenticationOptions(opts);

        /**
         * The server needs to temporarily remember this value for verification, so don't lose it until
         * after you verify an authenticator response.
         */
        const sessionId = this.setSessionId(res);
        cache.set(sessionId, options.challenge, 1800); // Cache the challenge for 30 mins
        return options;
    }

    async verifyAuthentication(req, res) {
        const requestBody = req.body;
        const userRecord = await this.getUserFromDb(requestBody.response.userHandle);
        const { id, username, devices } = userRecord;
        const expectedChallenge = this.getCacheOnce(req.signedCookies.sessionId);

        let dbAuthenticator;
        const bodyCredIDBuffer = base64url.toBuffer(requestBody.rawId);
        // "Query the DB" here for an authenticator matching `credentialID`
        for (const dev of devices) {
            if (dev.credentialID.equals(bodyCredIDBuffer)) {
                dbAuthenticator = dev;
                break;
            }
        }

        if (!dbAuthenticator) {
            throw new Error('Authenticator is not registered with this site');
        }

        const opts = {
            credential: requestBody,
            expectedChallenge: `${expectedChallenge}`,
            expectedOrigin: 'http://localhost:5173',
            expectedRPID: this.rpID,
            authenticator: dbAuthenticator,
            requireUserVerification: true,
        };
        const { verified, authenticationInfo } = await verifyAuthenticationResponse(opts);

        if (verified) {
            // Update the authenticator's counter in the DB to the newest count in the authentication
            dbAuthenticator.counter = authenticationInfo.newCounter;
            await userRecord.update({ devices: devices });
        }
        this.resultVerifyHandler(verified);
        const accessToken = await setupTokens(id, username, res);
        return {
            id,
            username,
            accessToken
        };
    }

    resultVerifyHandler(result) {
        if (result && !result.error) {
            return result;
        }
        if (result.error) {
            throw new Error(result.error);
        }
    }

    setSessionId(res) {
        const sessionId = uuidv4();
        res.cookie('sessionId', sessionId, {
            httpOnly: true,
            sameSite: 'Lax',
            secure: false,
            maxAge: 60 * 60 * 1000, //1 hour
            signed: true
        });
        return sessionId;
    }

    getCacheOnce(key) {
        const val = cache.get(key);
        cache.del(key);
        return val;
    }
}