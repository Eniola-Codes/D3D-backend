"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const mongoose_1 = __importDefault(require("mongoose"));
const dotenv_1 = __importDefault(require("dotenv"));
const auth_1 = __importDefault(require("./routes/auth"));
const user_1 = __importDefault(require("./routes/user"));
const passport_1 = __importDefault(require("passport"));
const auth_2 = require("./lib/utils/auth");
require('./services/auth/google');
dotenv_1.default.config();
const FRONTEND_URL = process.env.FRONTEND_APPLICATION_URL;
const app = (0, express_1.default)();
app.use(body_parser_1.default.json());
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET, POST, PUT, PATCH, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});
app.use('/api/auth', auth_1.default);
app.use('/api/user', user_1.default);
app.get('/auth/google', passport_1.default.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', (req, res, next) => {
    passport_1.default.authenticate('google', { session: false }, async (err, user) => {
        if (err || !user) {
            return res.redirect(`${FRONTEND_URL}/account?auth=login&error=true`);
        }
        const token = (0, auth_2.generateJwt)(user);
        return res.redirect(`${FRONTEND_URL}/account?auth=login&token=${token}`);
    })(req, res, next);
});
app.use((error, req, res) => {
    const status = error.statusCode || 500;
    const message = error.message;
    const data = error.data;
    res.status(status).json({ message, data });
});
mongoose_1.default
    .connect(process.env.MONGODB_CONNECTION)
    .then(() => {
    app.listen(8080, () => { });
})
    .catch(() => { });
