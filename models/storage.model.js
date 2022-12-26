import {DataTypes} from 'sequelize';
import {sequelize} from '../loaders/database.js';

export const StorageModel = sequelize.define('storage', {
    // The following specification of the 'id' attribute could be omitted
    // since it is the default.
    id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: DataTypes.INTEGER
    },
    sessionId: {
        allowNull: false,
        type: DataTypes.UUID,
        unique: true,
    },
    data: {
        type: DataTypes.STRING(43)
    }
});
