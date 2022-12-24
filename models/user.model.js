import {DataTypes} from "sequelize";
import {sequelize} from "../loaders/database.js";

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
            is: /^\w{3,}$/
        }
    },
    name: {
        type: DataTypes.STRING,
    },
    hashedPassword: {
        type: DataTypes.STRING,
        allowNull: false,
    },
});
