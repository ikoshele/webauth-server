import { DataTypes } from 'sequelize';
import { sequelize } from '../loaders/database.js';

export const UserModel = sequelize.define('user', {
    // The following specification of the 'id' attribute could be omitted
    // since it is the default.
    id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: DataTypes.INTEGER
    },
    username: {
        allowNull: false,
        type: DataTypes.STRING,
        unique: true,
        validate: {
            // We require usernames to have length of at least 3, and
            // only use letters, numbers and underscores.
            is: /^\w{3,}$/,
        }
    },
    name: {
        type: DataTypes.STRING,
    },
    hashedPassword: {
        type: DataTypes.STRING,
        allowNull: true,
        validate: {
            allowNull(value) {
                if (!value && (!this.devices || !this.devices.length)) {
                    throw new Error('Password may be empty only if you use WebAuth');
                }
            }
        }
    },
    devices: {
        type: DataTypes.JSON,
        get() {
            const rawValue = this.getDataValue('devices');
            const parsed = JSON.parse(rawValue);
            parsed.forEach((device) => {
                device.credentialPublicKey = Buffer.from(device.credentialPublicKey.data);
                device.credentialID = Buffer.from(device.credentialID.data);
            });
            return  parsed;
        },
        set(value) {
            this.setDataValue('devices', JSON.stringify(value));
        },
        defaultValue: JSON.stringify([])
    },
    challenge: {
        type: DataTypes.STRING(43),
    }
});
