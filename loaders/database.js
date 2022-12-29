import * as dotenv from 'dotenv';

dotenv.config();
import { Sequelize, ValidationError } from 'sequelize';

const sequelize = new Sequelize(process.env.MYSQL_DB_NAME, process.env.MYSQL_LOGIN, process.env.MYSQL_PWD, {
    host: process.env.MYSQL_HOST,
    dialect: 'mysql'
});
export { sequelize, ValidationError };
//export const sequelize = new Sequelize(process.env.REMOTE_DATABASE_URL);


