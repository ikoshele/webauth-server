import {DataTypes} from "sequelize";
import {sequelize} from "../loaders/database.js";

export const User = sequelize.define('user', {
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
            is: /^\w{3,}$/
        }
    },
    hash_password: {
        type: DataTypes.STRING(64),
        validate: {
            is: /^[0-9a-f]{64}$/i
        },
        allowNull: false,
    },
});
