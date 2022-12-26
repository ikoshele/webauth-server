import * as dotenv from 'dotenv';
dotenv.config();
import { Sequelize } from 'sequelize';

export const sequelize = new Sequelize(process.env.MYSQL_DB_NAME, process.env.MYSQL_LOGIN, process.env.MYSQL_PWD, {
    host: process.env.MYSQL_HOST,
    dialect: 'mysql'
});


