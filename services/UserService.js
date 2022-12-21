import {User} from "../models/user.model.js";

export class UserService {
    async register(user) {
        let userRecord;
        try {
            userRecord = await User.create({ username: "Jane", hash_password: "123" })
        } catch (e) {
            console.log(e)
        }
        return userRecord
    }
}