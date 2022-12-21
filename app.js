import express from 'express'
import * as dotenv from 'dotenv'
dotenv.config()
import cors from 'cors'
const app = express();
const port = 3000;

import {sequelize} from "./loaders/database.js";
import './models/index.js'
import {UserService} from "./services/UserService.js";
import webAuthService from "./services/WebAuthService.js";

app.use(express.json());
app.use(cors());

const webAuthInstance = new webAuthService();

app.get('/', (req, res) => {
    res.send('hello world')
})

app.get('/generate-registration-options', (req, res) => {
    const options = webAuthInstance.generateRegistrationOptions();
    res.json(options);
});

app.post('/verify-registration',  async (req, res) => {
    const { body } = req;
    const result = await webAuthInstance.verifyRegistration(body);

    webAuthInstance.resultVerifyHandler(result, res)
});

app.get('/generate-authentication-options', (req, res) => {
    const options = webAuthInstance.generateAuthenticationOptions();
    res.send(options);
});

app.post('/verify-authentication', async (req, res) => {
    const body = req.body;
    const result = await webAuthInstance.verifyAuthentication(body);

    webAuthInstance.resultVerifyHandler(result, res)
});


const startApp = async () => {
    try {
        await sequelize.authenticate()
        console.log('Connection has been established successfully.');
        await sequelize.sync();
        const userInstance = new UserService();
        await userInstance.register('name')
        app.listen(port, () => {
            console.log(`Example app listening on port ${port}`)
        })
    } catch (error) {
        console.log("error =>", error);
    }
};
await startApp();