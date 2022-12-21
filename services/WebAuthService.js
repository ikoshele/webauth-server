import {
    generateAuthenticationOptions,
    generateRegistrationOptions, verifyAuthenticationResponse,
    verifyRegistrationResponse
} from "@simplewebauthn/server";
import base64url from "base64url";

export default class webAuthService {
    constructor() {
        this.loggedInUserId = 'internalUserId';
        this.rpName = 'SimpleWebAuthn Example';
        this.rpID = 'localhost';
        this.origin = 'http://localhost:5173';
        this.inMemoryUserDeviceDB = {
            [this.loggedInUserId]: {
                id: this.loggedInUserId,
                username: `user@${this.rpID}`,
                devices: [],
                /**
                 * A simple way of storing a user's current challenge being signed by registration or authentication.
                 * It should be expired after `timeout` milliseconds (optional argument for `generate` methods,
                 * defaults to 60000ms)
                 */
                currentChallenge: undefined,
            },
        };
    }

    getUserFromDb() {
        return this.inMemoryUserDeviceDB[this.loggedInUserId]
    }

    generateRegistrationOptions() {
        const user = this.getUserFromDb();

        const {
            /**
             * The username can be a human-readable name, email, etc... as it is intended only for display.
             */
            username,
            devices,
        } = user;
        const options = generateRegistrationOptions({
            rpName: this.rpName,
            rpID: this.rpID,
            userID: this.loggedInUserId,
            userName: username,
            // Don't prompt users for additional information about the authenticator
            // (Recommended for smoother UX)
            attestationType: 'none',
            // Prevent users from re-registering existing authenticators
            excludeCredentials: devices.map(dev => ({
                id: dev.credentialID,
                type: 'public-key',
                transports: dev.transports,
            })),
        });

        /**
         * The server needs to temporarily remember this value for verification, so don't lose it until
         * after you verify an authenticator response.
         */
        user.currentChallenge = options.challenge;
        return options;
    }

    async verifyRegistration(payload) {
        const user = this.getUserFromDb();
        const expectedChallenge = user.currentChallenge;
        let verification;
        try {
            verification = await verifyRegistrationResponse({
                credential: payload,
                expectedChallenge,
                expectedOrigin: this.origin,
                expectedRPID: this.rpID,
            });
        } catch (error) {
            console.error(error);
            return {
                error: error.message
            };
        }

        const {verified, registrationInfo} = verification;

        if (verified && registrationInfo) {
            const {credentialPublicKey, credentialID, counter} = registrationInfo;

            const existingDevice = user.devices.find(device => device.credentialID.equals(credentialID));

            if (!existingDevice) {
                /**
                 * Add the returned device to the user's list of devices
                 */
                const newDevice = {
                    credentialPublicKey,
                    credentialID,
                    counter,
                    transports: payload.transports,
                };
                user.devices.push(newDevice);
            }
        }
        return {
            verified
        };
    }

    generateAuthenticationOptions() {
        // (Pseudocode) Retrieve the logged-in user
        const user = this.getUserFromDb();
// (Pseudocode) Retrieve any of the user's previously-
// registered authenticators
        const opts = {
            timeout: 60000,
            allowCredentials: user.devices.map(dev => ({
                id: dev.credentialID,
                type: 'public-key',
                transports: dev.transports,
            })),
            userVerification: 'required',
            rpID: this.rpID,
        };

        const options = generateAuthenticationOptions(opts);

        /**
         * The server needs to temporarily remember this value for verification, so don't lose it until
         * after you verify an authenticator response.
         */
        user.currentChallenge = options.challenge;
        return options;
    }

    async verifyAuthentication(payload) {
        const user = this.getUserFromDb();

        const expectedChallenge = user.currentChallenge;

        let dbAuthenticator;
        const bodyCredIDBuffer = base64url.toBuffer(payload.rawId);
        // "Query the DB" here for an authenticator matching `credentialID`
        for (const dev of user.devices) {
            if (dev.credentialID.equals(bodyCredIDBuffer)) {
                dbAuthenticator = dev;
                break;
            }
        }

        if (!dbAuthenticator) {
            return {
                error: 'Authenticator is not registered with this site'
            };
        }

        let verification;
        try {
            const opts = {
                credential: payload,
                expectedChallenge: `${expectedChallenge}`,
                expectedOrigin: 'http://localhost:5173',
                expectedRPID: this.rpID,
                authenticator: dbAuthenticator,
                requireUserVerification: true,
            };
            verification = await verifyAuthenticationResponse(opts);
        } catch (error) {
            console.error(error);
            return {
                error: error.message
            };
        }

        const {verified, authenticationInfo} = verification;

        if (verified) {
            // Update the authenticator's counter in the DB to the newest count in the authentication
            dbAuthenticator.counter = authenticationInfo.newCounter;
        }
        return {
            verified
        }
    }
    resultVerifyHandler(result, res) {
        if (result && !result.error) {
            res.send(result)
        }
        if (result.error) {
            res.status(400).send({ error: result.error })
        }
    }
}