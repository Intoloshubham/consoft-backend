import dotenv from 'dotenv';
dotenv.config();

export const {
    PORT ,
    DATABASE_URL,
    DEBUG_MODE,
    JWT_SECRET,
    REFRESH_SECRET,
    APP_URL,
    EMAIL_HOST,
    EMAIL_PORT,
    EMAIL_USER,
    EMAIL_PASSWORD,
    EMAIL_FROM
} = process.env