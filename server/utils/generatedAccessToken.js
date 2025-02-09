import jwt from 'jsonwebtoken';

const generatedAccessToken = async (userId) => {
    const token = await jwt.sign(
        { id: userId },
        process.env.SECRET_KEY_ACCESS_TOKEN, // Ensure this is defined in `.env`
        { expiresIn: '5h' }
    );
    return token;
};

export default generatedAccessToken;
