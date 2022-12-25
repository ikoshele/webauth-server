import express from 'express'
import * as dotenv from 'dotenv'
dotenv.config()
import cors from 'cors'
import cookieParser from 'cookie-parser'
const app = express();
const port = 3000;

import {sequelize} from "./loaders/database.js";
import './models/index.js'
import {UserService} from "./services/UserService.js";
import {router as indexRoutes} from './routes/index.routes.js'
import {router as authRoutes} from './routes/auth.routes.js'
import {router as privateRoutes} from './routes/profile.routes.js'
import {router as webAuthRoutes} from './routes/webauth.routes.js'
import {errorHandler} from "./middlewares/errorHandler.js";

app.use(express.json());
app.use(cors({credentials: true, origin: true}));
app.use(cookieParser(process.env.COOKIES_SECRET))


app.use('/', indexRoutes);
app.use('/', authRoutes);
app.use('/', webAuthRoutes);
app.use('/', privateRoutes);


app.get('/', (req, res) => {
    res.send('hello world')
})




app.use(errorHandler)


const startApp = async () => {
    try {
        await sequelize.authenticate()
        console.log('Connection has been established successfully.');
        await sequelize.sync({force: true});
        const userInstance = new UserService();
        //await userInstance.register('name')
        app.listen(port, () => {
            console.log(`Example app listening on port ${port}`)
        })
    } catch (error) {
        console.log("error =>", error);
    }
};
await startApp();