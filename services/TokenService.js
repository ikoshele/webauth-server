import jwt from "jsonwebtoken";

export function generateToken(id, username) {
    const accessToken = jwt.sign({id, username}, process.env.TOKEN_SECRET, { expiresIn: '10s' });
    //const accessToken = jwt.sign({id, username}, process.env.TOKEN_SECRET, { expiresIn: '1800s' });
    const refreshToken = jwt.sign({id, username}, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '20s' });
    //const refreshToken = jwt.sign({id, username}, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '1d' });
    return {
        accessToken,
        refreshToken
    };
}

export function setRefreshTokenCookie(res, refreshToken) {
    res.cookie('jwt', refreshToken, {
        httpOnly: true,
        sameSite: 'Lax',
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
        signed: true
    });
}